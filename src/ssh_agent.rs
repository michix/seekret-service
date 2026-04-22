/// SSH Agent implementation for seekret-service (Linux/macOS only).
///
/// Exposes SSH public keys from a KeePass database via the SSH agent protocol
/// on a Unix domain socket. Only public keys are held in memory for identity
/// listing. Private keys are fetched on demand from the HTTP API for each
/// signing request and securely zeroized immediately after use. Authorization
/// is fully delegated to the HTTP service — the agent does not perform its own
/// authorization checks.
use log::{debug, info, warn};
use signature::Signer;
use ssh_encoding::Encode;
use ssh_key::private::PrivateKey;
use ssh_key::public::PublicKey;
use zeroize::Zeroize;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Mutex;

use crate::RESETCACHE;

// SSH agent protocol message types (IETF draft-miller-ssh-agent)
pub(crate) const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub(crate) const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
pub(crate) const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub(crate) const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
pub(crate) const SSH_AGENT_FAILURE: u8 = 5;
pub(crate) const SSH_AGENTC_EXTENSION: u8 = 27;

/// A public key record with its KeePass entry path used as comment.
///
/// Only the public key is retained in memory. The corresponding private key
/// is fetched on demand from the HTTP API for signing operations and dropped
/// (with automatic zeroization) immediately afterward.
pub(crate) struct SshPublicKeyRecord {
    pub(crate) public_key: PublicKey,
    pub(crate) comment: String,
}

/// Type alias for a function that fetches a private key for signing on demand.
///
/// The function receives the KeePass entry path (comment) and returns
/// `Some(PrivateKey)` on success or `None` if the key could not be fetched
/// (e.g. HTTP error, authorization denied, parse failure).
pub(crate) type KeyFetcher = dyn Fn(&str) -> Option<PrivateKey> + Send;

/// Shared agent state protected by a Mutex.
///
/// Only public keys are stored here. Private keys are never held persistently.
pub(crate) struct SshAgentState {
    pub(crate) keys: Vec<SshPublicKeyRecord>,
}

/// Reads one SSH agent protocol message from the stream.
///
/// # Returns
///
/// `Some(data)` on success, `None` on EOF or protocol error.
pub(crate) fn read_agent_msg(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).is_err() {
        return None;
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 256 * 1024 {
        warn!("SSH agent: rejecting oversized message ({len} bytes)");
        return None;
    }
    let mut data = vec![0u8; len];
    if stream.read_exact(&mut data).is_err() {
        return None;
    }
    Some(data)
}

/// Writes one SSH agent protocol message to the stream.
pub(crate) fn write_agent_msg(stream: &mut UnixStream, msg: &[u8]) -> std::io::Result<()> {
    let len = msg.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(msg)?;
    stream.flush()
}

/// Builds an SSH_AGENT_FAILURE response.
pub(crate) fn failure_msg() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

/// Dispatches an incoming SSH agent request.
///
/// # Arguments
///
/// * `data` - The raw message bytes.
/// * `state` - The shared agent state (public keys only).
/// * `key_fetcher` - Function to fetch a private key on demand for signing.
pub(crate) fn handle_request(
    data: &[u8],
    state: &Mutex<SshAgentState>,
    key_fetcher: &KeyFetcher,
) -> Vec<u8> {
    if data.is_empty() {
        return failure_msg();
    }
    match data[0] {
        SSH2_AGENTC_REQUEST_IDENTITIES => handle_identities(state),
        SSH2_AGENTC_SIGN_REQUEST => handle_sign(&data[1..], state, key_fetcher),
        SSH_AGENTC_EXTENSION => {
            debug!("SSH agent: extension request (not supported)");
            failure_msg()
        }
        other => {
            debug!("SSH agent: unsupported message type {other}");
            failure_msg()
        }
    }
}

/// Responds with the list of identities (public keys) the agent holds.
pub(crate) fn handle_identities(state: &Mutex<SshAgentState>) -> Vec<u8> {
    let state = state.lock().unwrap();
    let mut buf = Vec::new();
    buf.push(SSH2_AGENT_IDENTITIES_ANSWER);
    buf.extend((state.keys.len() as u32).to_be_bytes());
    for k in &state.keys {
        let pubkey_blob = k.public_key.to_bytes().unwrap_or_default();
        buf.extend((pubkey_blob.len() as u32).to_be_bytes());
        buf.extend(&pubkey_blob);
        let comment = k.comment.as_bytes();
        buf.extend((comment.len() as u32).to_be_bytes());
        buf.extend(comment);
    }
    buf
}

/// Handles an SSH2_AGENTC_SIGN_REQUEST.
///
/// The request format is: string key_blob, string data, uint32 flags.
/// The private key is fetched on demand via `key_fetcher` and dropped
/// (with automatic zeroization) immediately after signing. Authorization
/// is delegated to the HTTP service — if the user has not authorized,
/// the HTTP request will fail and signing is denied.
///
/// # Arguments
///
/// * `data` - The sign request payload (after the message type byte).
/// * `state` - The shared agent state (public keys only).
/// * `key_fetcher` - Function to fetch a private key on demand for signing.
pub(crate) fn handle_sign(
    data: &[u8],
    state: &Mutex<SshAgentState>,
    key_fetcher: &KeyFetcher,
) -> Vec<u8> {
    let mut d = data;
    let key_blob = match parse_ssh_string(&mut d) {
        Some(x) => x,
        None => return failure_msg(),
    };
    let to_sign = match parse_ssh_string(&mut d) {
        Some(x) => x,
        None => return failure_msg(),
    };
    // flags (unused for now)
    let _flags: u32 = if d.len() >= 4 {
        u32::from_be_bytes([d[0], d[1], d[2], d[3]])
    } else {
        0
    };

    // Find the public key record matching the requested key blob
    let entry_path = {
        let st = state.lock().unwrap();
        let matching = st
            .keys
            .iter()
            .find(|k| k.public_key.to_bytes().unwrap_or_default() == key_blob);

        match matching {
            Some(k) => k.comment.clone(),
            None => {
                debug!("SSH agent: no matching key found");
                return failure_msg();
            }
        }
    };

    // Fetch the private key on demand from the HTTP API.
    // Authorization is handled by the HTTP service — if access is denied,
    // the fetch returns None and we return failure.
    let private_key = match key_fetcher(&entry_path) {
        Some(k) => k,
        None => {
            info!(
                "SSH agent: failed to fetch private key for '{entry_path}' — access may have been denied"
            );
            return failure_msg();
        }
    };

    // Perform signing — the private key is dropped (zeroized) at end of scope
    let result = match private_key.try_sign(&to_sign) {
        Ok(signature) => {
            let mut sig_blob = Vec::new();
            if signature.encode(&mut sig_blob).is_err() {
                warn!("SSH agent: failed to encode signature");
                return failure_msg();
            }
            let mut out = Vec::new();
            out.push(SSH2_AGENT_SIGN_RESPONSE);
            out.extend((sig_blob.len() as u32).to_be_bytes());
            out.extend(&sig_blob);
            debug!("SSH agent: signed request for '{entry_path}'");
            out
        }
        Err(e) => {
            warn!("SSH agent: signing failed: {e}");
            failure_msg()
        }
    };

    // private_key is dropped here — ssh-key's Drop impl zeroizes key material
    result
}

/// Parses an SSH wire-format string (uint32 length + bytes).
pub(crate) fn parse_ssh_string(d: &mut &[u8]) -> Option<Vec<u8>> {
    if d.len() < 4 {
        return None;
    }
    let (len_bytes, rest) = d.split_at(4);
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    if rest.len() < len {
        return None;
    }
    let (data, remainder) = rest.split_at(len);
    *d = remainder;
    Some(data.to_vec())
}

/// Performs a minimal HTTP GET request to localhost and returns the response body.
///
/// # Arguments
///
/// * `port` - The HTTP server port.
/// * `path` - The URL path to request (e.g. "/my-entry/ssh-key").
///
/// # Returns
///
/// `Ok(body)` on HTTP 200, `Err(message)` on any error or non-200 status.
fn http_get_localhost(port: u16, path: &str) -> Result<String, String> {
    let addr = format!("127.0.0.1:{port}");
    let key_id = path
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .iter()
        .rev()
        .nth(1)
        .copied()
        .unwrap_or("<none>");
    let mut stream =
        TcpStream::connect(&addr).map_err(|e| format!("failed to connect to {addr}: {e}"))?;
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Seekret-Source: ssh-agent ({key_id})\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("failed to send request: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush: {e}"))?;

    let mut reader = BufReader::new(stream);

    // Parse status line
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| format!("failed to read status line: {e}"))?;
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("invalid status line: {status_line}"))?;

    // Skip headers
    loop {
        let mut header = String::new();
        reader
            .read_line(&mut header)
            .map_err(|e| format!("failed to read header: {e}"))?;
        if header.trim().is_empty() {
            break;
        }
    }

    // Read body
    let mut body = String::new();
    reader
        .read_to_string(&mut body)
        .map_err(|e| format!("failed to read body: {e}"))?;

    if status_code == 200 {
        Ok(body)
    } else {
        Err(format!("HTTP {status_code}: {body}"))
    }
}

/// Fetches SSH public keys from the HTTP API.
///
/// For each entry path, fetches the `ssh-key` (PEM) from the local HTTP
/// service, parses the private key to extract its public key, then
/// immediately drops the private key (which triggers secure zeroization
/// via `ssh-key`'s `Drop` implementation). If the key is encrypted, the
/// passphrase is fetched from the `secret` endpoint and also zeroized
/// after use.
///
/// # Arguments
///
/// * `port` - The HTTP server port.
/// * `entry_paths` - KeePass entry paths to load SSH public keys from.
///
/// # Returns
///
/// A vector of successfully loaded public key records.
pub(crate) fn fetch_ssh_public_keys(port: u16, entry_paths: &[String]) -> Vec<SshPublicKeyRecord> {
    let mut keys = Vec::new();
    for path in entry_paths {
        let mut pem = match http_get_localhost(port, &format!("/{path}/ssh-key")) {
            Ok(p) => p,
            Err(e) => {
                warn!("SSH agent: failed to fetch ssh-key for '{path}': {e}");
                continue;
            }
        };

        if pem.is_empty() {
            warn!("SSH agent: entry '{path}' returned empty ssh-key");
            continue;
        }

        let public_key = match PrivateKey::from_openssh(&pem) {
            Ok(key) => {
                let private_key = if key.is_encrypted() {
                    // Fetch the passphrase from the secret endpoint
                    let mut passphrase = match http_get_localhost(port, &format!("/{path}/secret"))
                    {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("SSH agent: failed to fetch passphrase for '{path}': {e}");
                            continue;
                        }
                    };
                    if passphrase.is_empty() {
                        warn!("SSH agent: key in '{path}' is encrypted but secret is empty");
                        continue;
                    }
                    let decrypted = match key.decrypt(&passphrase) {
                        Ok(d) => d,
                        Err(e) => {
                            warn!("SSH agent: failed to decrypt key from '{path}': {e}");
                            passphrase.zeroize();
                            continue;
                        }
                    };
                    // Securely zeroize the passphrase
                    passphrase.zeroize();
                    decrypted
                } else {
                    key
                };
                // Extract the public key before dropping the private key
                let pubkey = private_key.public_key().clone();
                // private_key is dropped here — ssh-key's Drop impl zeroizes key material
                drop(private_key);
                pubkey
            }
            Err(e) => {
                warn!("SSH agent: failed to parse SSH key from '{path}': {e}");
                continue;
            }
        };

        // Securely zeroize the PEM data
        pem.zeroize();

        info!("SSH agent: loaded public key from '{path}'");
        keys.push(SshPublicKeyRecord {
            public_key,
            comment: path.clone(),
        });
    }
    keys
}

/// Fetches a single private key on demand from the HTTP API for signing.
///
/// The private key is fetched, parsed, and (if encrypted) decrypted. All
/// intermediate secrets (PEM, passphrase) are zeroized. The caller is
/// responsible for dropping the returned `PrivateKey` after use, which
/// triggers automatic zeroization of key material.
///
/// # Arguments
///
/// * `port` - The HTTP server port.
/// * `entry_path` - The KeePass entry path to fetch the SSH key from.
///
/// # Returns
///
/// `Some(PrivateKey)` on success, `None` on any error (including HTTP 401
/// when the user has not authorized access).
pub(crate) fn fetch_private_key_for_signing(port: u16, entry_path: &str) -> Option<PrivateKey> {
    let mut pem = match http_get_localhost(port, &format!("/{entry_path}/ssh-key")) {
        Ok(p) => p,
        Err(e) => {
            warn!("SSH agent: failed to fetch ssh-key for '{entry_path}': {e}");
            return None;
        }
    };

    if pem.is_empty() {
        warn!("SSH agent: entry '{entry_path}' returned empty ssh-key");
        return None;
    }

    let private_key = match PrivateKey::from_openssh(&pem) {
        Ok(key) => {
            if key.is_encrypted() {
                let mut passphrase =
                    match http_get_localhost(port, &format!("/{entry_path}/secret")) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("SSH agent: failed to fetch passphrase for '{entry_path}': {e}");
                            pem.zeroize();
                            return None;
                        }
                    };
                if passphrase.is_empty() {
                    warn!("SSH agent: key in '{entry_path}' is encrypted but secret is empty");
                    pem.zeroize();
                    return None;
                }
                let result = key.decrypt(&passphrase);
                passphrase.zeroize();
                match result {
                    Ok(decrypted) => decrypted,
                    Err(e) => {
                        warn!("SSH agent: failed to decrypt key from '{entry_path}': {e}");
                        pem.zeroize();
                        return None;
                    }
                }
            } else {
                key
            }
        }
        Err(e) => {
            warn!("SSH agent: failed to parse SSH key from '{entry_path}': {e}");
            pem.zeroize();
            return None;
        }
    };

    // Securely zeroize the PEM data
    pem.zeroize();

    debug!(
        "SSH agent: fetched private key for '{entry_path}' (len {})",
        private_key
            .public_key()
            .to_bytes()
            .map(|b| b.len())
            .unwrap_or(0)
    );
    Some(private_key)
}

/// Starts the SSH agent, binding to a Unix socket and serving requests.
///
/// This function blocks indefinitely (designed to run in a dedicated thread).
/// Only public keys are fetched from the local HTTP API on startup and
/// refreshed whenever the KeePass file-change flag (`RESETCACHE`) is set.
/// Private keys are fetched on demand for each signing request and securely
/// zeroized immediately after use. Authorization is fully delegated to the
/// HTTP service.
///
/// # Arguments
///
/// * `port` - The HTTP server port to fetch SSH keys from.
/// * `entry_paths` - KeePass entry paths containing SSH private keys.
/// * `socket_path` - Path for the Unix domain socket.
pub fn run_agent(port: u16, entry_paths: Vec<String>, socket_path: PathBuf) {
    // Fetch initial public keys from the HTTP API
    let keys = fetch_ssh_public_keys(port, &entry_paths);

    if keys.is_empty() {
        warn!("SSH agent: no SSH keys loaded — agent will start but have no identities");
    }

    // Clean up any stale socket
    let _ = fs::remove_file(&socket_path);

    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            log::error!(
                "SSH agent: failed to bind socket at {}: {e}",
                socket_path.display()
            );
            return;
        }
    };

    // Set socket permissions to 0600 (owner-only)
    if let Err(e) = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)) {
        warn!("SSH agent: failed to set socket permissions: {e} — continuing anyway");
    }

    info!("SSH agent: listening on {}", socket_path.display());

    let state = Mutex::new(SshAgentState { keys });

    // Create the key fetcher closure that fetches private keys on demand
    let key_fetcher = move |entry_path: &str| -> Option<PrivateKey> {
        fetch_private_key_for_signing(port, entry_path)
    };

    for stream in listener.incoming() {
        match stream {
            Ok(mut sock) => {
                debug!("SSH agent: new client connection");
                while let Some(req) = read_agent_msg(&mut sock) {
                    // Check if cache reset was flagged — reload public keys from HTTP
                    let reset = *RESETCACHE.lock().unwrap();
                    if reset {
                        info!(
                            "SSH agent: KeePass file changed — reloading public keys from HTTP API"
                        );
                        let new_keys = fetch_ssh_public_keys(port, &entry_paths);
                        let mut st = state.lock().unwrap();
                        st.keys = new_keys;
                    }
                    let reply = handle_request(&req, &state, &key_fetcher);
                    if write_agent_msg(&mut sock, &reply).is_err() {
                        break;
                    }
                }
            }
            Err(e) => {
                log::error!("SSH agent: accept error: {e}");
                break;
            }
        }
    }

    // Cleanup socket on exit
    let _ = fs::remove_file(&socket_path);
    info!("SSH agent: stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{rand_core::OsRng, Algorithm, PrivateKey};
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;

    /// Helper: encode a byte slice as an SSH wire-format string (u32 len + data).
    fn ssh_string(data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend((data.len() as u32).to_be_bytes());
        buf.extend(data);
        buf
    }

    /// Helper: generate a fresh Ed25519 private key for testing.
    fn test_key() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("Failed to generate test key")
    }

    /// Helper: build an SshAgentState with the given public key records.
    fn make_state(keys: Vec<SshPublicKeyRecord>) -> Mutex<SshAgentState> {
        Mutex::new(SshAgentState { keys })
    }

    /// Helper: create a KeyFetcher that always returns the given private key.
    fn mock_fetcher(key: PrivateKey) -> Box<KeyFetcher> {
        // We need to allow the key to be returned multiple times in tests,
        // so we clone the key material each time. In production this would
        // be an HTTP fetch.
        let key_pem = key
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("Failed to serialize test key");
        Box::new(move |_entry_path: &str| -> Option<PrivateKey> {
            Some(PrivateKey::from_openssh(&*key_pem).expect("Failed to parse test key"))
        })
    }

    /// Helper: create a KeyFetcher that always returns None (simulates
    /// HTTP error or authorization denial).
    fn mock_fetcher_denied() -> Box<KeyFetcher> {
        Box::new(|_entry_path: &str| -> Option<PrivateKey> { None })
    }

    // ── parse_ssh_string tests ───────────────────────────────────────

    #[test_log::test]
    fn test_parse_ssh_string_valid() {
        let payload = b"hello";
        let wire = ssh_string(payload);
        let mut d: &[u8] = &wire;
        let result = parse_ssh_string(&mut d).expect("Should parse successfully");
        assert_eq!(result, payload);
        assert!(d.is_empty(), "All bytes should be consumed");
    }

    #[test_log::test]
    fn test_parse_ssh_string_empty_string() {
        let wire = ssh_string(b"");
        let mut d: &[u8] = &wire;
        let result = parse_ssh_string(&mut d).expect("Should parse empty string");
        assert!(result.is_empty());
    }

    #[test_log::test]
    fn test_parse_ssh_string_truncated_length() {
        let d_short: &[u8] = &[0, 0]; // only 2 bytes, need 4
        let mut d = d_short;
        assert!(parse_ssh_string(&mut d).is_none());
    }

    #[test_log::test]
    fn test_parse_ssh_string_truncated_data() {
        // Claim 10 bytes but only provide 3
        let mut wire = (10u32).to_be_bytes().to_vec();
        wire.extend(b"abc");
        let mut d: &[u8] = &wire;
        assert!(parse_ssh_string(&mut d).is_none());
    }

    #[test_log::test]
    fn test_parse_ssh_string_multiple_strings() {
        let mut wire = ssh_string(b"first");
        wire.extend(ssh_string(b"second"));
        let mut d: &[u8] = &wire;
        let first = parse_ssh_string(&mut d).unwrap();
        let second = parse_ssh_string(&mut d).unwrap();
        assert_eq!(first, b"first");
        assert_eq!(second, b"second");
        assert!(d.is_empty());
    }

    // ── handle_request dispatch tests ────────────────────────────────

    #[test_log::test]
    fn test_handle_request_empty_returns_failure() {
        let state = make_state(vec![]);
        let fetcher = mock_fetcher_denied();
        let result = handle_request(&[], &state, &*fetcher);
        assert_eq!(result, vec![SSH_AGENT_FAILURE]);
    }

    #[test_log::test]
    fn test_handle_request_unknown_type_returns_failure() {
        let state = make_state(vec![]);
        let fetcher = mock_fetcher_denied();
        let result = handle_request(&[99], &state, &*fetcher);
        assert_eq!(result, vec![SSH_AGENT_FAILURE]);
    }

    #[test_log::test]
    fn test_handle_request_identities_type() {
        let state = make_state(vec![]);
        let fetcher = mock_fetcher_denied();
        let result = handle_request(&[SSH2_AGENTC_REQUEST_IDENTITIES], &state, &*fetcher);
        assert_eq!(result[0], SSH2_AGENT_IDENTITIES_ANSWER);
    }

    // ── handle_identities tests ──────────────────────────────────────

    #[test_log::test]
    fn test_identities_no_keys() {
        let state = make_state(vec![]);
        let result = handle_identities(&state);
        assert_eq!(result[0], SSH2_AGENT_IDENTITIES_ANSWER);
        // nkeys = 0
        let nkeys = u32::from_be_bytes([result[1], result[2], result[3], result[4]]);
        assert_eq!(nkeys, 0);
        assert_eq!(result.len(), 5);
    }

    #[test_log::test]
    fn test_identities_one_key() {
        let key = test_key();
        let pubkey_blob = key.public_key().to_bytes().unwrap();
        let comment = "test-key";
        let state = make_state(vec![SshPublicKeyRecord {
            public_key: key.public_key().clone(),
            comment: comment.to_string(),
        }]);

        let result = handle_identities(&state);
        assert_eq!(result[0], SSH2_AGENT_IDENTITIES_ANSWER);

        // nkeys = 1
        let nkeys = u32::from_be_bytes([result[1], result[2], result[3], result[4]]);
        assert_eq!(nkeys, 1);

        // Parse key blob from response
        let mut d: &[u8] = &result[5..];
        let resp_pubkey = parse_ssh_string(&mut d).expect("Should contain pubkey blob");
        assert_eq!(resp_pubkey, pubkey_blob);

        // Parse comment from response
        let resp_comment = parse_ssh_string(&mut d).expect("Should contain comment");
        assert_eq!(resp_comment, comment.as_bytes());
    }

    #[test_log::test]
    fn test_identities_multiple_keys() {
        let keys: Vec<SshPublicKeyRecord> = (0..3)
            .map(|i| {
                let key = test_key();
                SshPublicKeyRecord {
                    public_key: key.public_key().clone(),
                    comment: format!("key-{i}"),
                }
            })
            .collect();
        let state = make_state(keys);
        let result = handle_identities(&state);
        let nkeys = u32::from_be_bytes([result[1], result[2], result[3], result[4]]);
        assert_eq!(nkeys, 3);
    }

    // ── handle_sign tests ────────────────────────────────────────────

    /// Build an SSH2_AGENTC_SIGN_REQUEST payload (without the message type byte).
    fn build_sign_request(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        let mut buf = ssh_string(key_blob);
        buf.extend(ssh_string(data));
        buf.extend(flags.to_be_bytes());
        buf
    }

    #[test_log::test]
    fn test_sign_denied_when_fetcher_returns_none() {
        let key = test_key();
        let pubkey_blob = key.public_key().to_bytes().unwrap();
        let state = make_state(vec![SshPublicKeyRecord {
            public_key: key.public_key().clone(),
            comment: "test".to_string(),
        }]);

        let fetcher = mock_fetcher_denied();
        let req = build_sign_request(&pubkey_blob, b"data to sign", 0);
        let result = handle_sign(&req, &state, &*fetcher);
        assert_eq!(
            result,
            vec![SSH_AGENT_FAILURE],
            "Should deny when key fetcher returns None"
        );
    }

    #[test_log::test]
    fn test_sign_succeeds_when_fetcher_returns_key() {
        let key = test_key();
        let pubkey_blob = key.public_key().to_bytes().unwrap();
        let state = make_state(vec![SshPublicKeyRecord {
            public_key: key.public_key().clone(),
            comment: "test".to_string(),
        }]);

        let fetcher = mock_fetcher(key);
        let req = build_sign_request(&pubkey_blob, b"data to sign", 0);
        let result = handle_sign(&req, &state, &*fetcher);
        assert_eq!(
            result[0], SSH2_AGENT_SIGN_RESPONSE,
            "Should return sign response"
        );
        assert!(result.len() > 5, "Response should contain a signature blob");
    }

    #[test_log::test]
    fn test_sign_wrong_key_returns_failure() {
        let key = test_key();
        let wrong_key = test_key();
        let wrong_blob = wrong_key.public_key().to_bytes().unwrap();
        let state = make_state(vec![SshPublicKeyRecord {
            public_key: key.public_key().clone(),
            comment: "test".to_string(),
        }]);

        let fetcher = mock_fetcher(key);
        let req = build_sign_request(&wrong_blob, b"data to sign", 0);
        let result = handle_sign(&req, &state, &*fetcher);
        assert_eq!(
            result,
            vec![SSH_AGENT_FAILURE],
            "Should fail for unknown key"
        );
    }

    #[test_log::test]
    fn test_sign_malformed_request_returns_failure() {
        let state = make_state(vec![]);
        let fetcher = mock_fetcher_denied();
        // Truncated: only 2 bytes, not enough for an SSH string
        let result = handle_sign(&[0, 0], &state, &*fetcher);
        assert_eq!(result, vec![SSH_AGENT_FAILURE]);
    }

    // ── Full round-trip over Unix socket ─────────────────────────────

    #[test_log::test]
    fn test_agent_socket_round_trip() {
        use std::os::unix::net::UnixListener;
        use std::thread;

        let socket_path =
            std::env::temp_dir().join(format!("seekret-test-agent-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket_path);

        let key = test_key();
        let pubkey_blob = key.public_key().to_bytes().unwrap();

        // Set up agent state with public keys only
        let state = make_state(vec![SshPublicKeyRecord {
            public_key: key.public_key().clone(),
            comment: "socket-test".to_string(),
        }]);

        let listener = UnixListener::bind(&socket_path).expect("Failed to bind test socket");

        // Create a key fetcher that returns the test key
        let fetcher = mock_fetcher(key);

        let sock_path_clone = socket_path.clone();
        let agent_thread = thread::spawn(move || {
            // Accept one connection, handle messages, then exit
            let (mut sock, _) = listener.accept().expect("Accept failed");
            while let Some(req) = read_agent_msg(&mut sock) {
                let reply = handle_request(&req, &state, &*fetcher);
                if write_agent_msg(&mut sock, &reply).is_err() {
                    break;
                }
            }
            let _ = std::fs::remove_file(&sock_path_clone);
        });

        // Connect as client
        let mut client =
            UnixStream::connect(&socket_path).expect("Failed to connect to test socket");

        // 1. Request identities
        let identities_req = vec![SSH2_AGENTC_REQUEST_IDENTITIES];
        write_agent_msg(&mut client, &identities_req).expect("Failed to send identities request");
        let identities_resp =
            read_agent_msg(&mut client).expect("Failed to read identities response");
        assert_eq!(identities_resp[0], SSH2_AGENT_IDENTITIES_ANSWER);
        let nkeys = u32::from_be_bytes([
            identities_resp[1],
            identities_resp[2],
            identities_resp[3],
            identities_resp[4],
        ]);
        assert_eq!(nkeys, 1);

        // 2. Sign request — should succeed (mock fetcher always provides the key)
        let mut sign_req = vec![SSH2_AGENTC_SIGN_REQUEST];
        sign_req.extend(build_sign_request(&pubkey_blob, b"please sign this", 0));
        write_agent_msg(&mut client, &sign_req).expect("Failed to send sign request");
        let sign_resp = read_agent_msg(&mut client).expect("Failed to read sign response");
        assert_eq!(
            sign_resp[0], SSH2_AGENT_SIGN_RESPONSE,
            "Sign should succeed when fetcher provides key"
        );

        // Close client, agent thread will exit
        drop(client);
        agent_thread.join().expect("Agent thread panicked");
    }

    #[test_log::test]
    fn test_agent_socket_round_trip_denied() {
        use std::os::unix::net::UnixListener;
        use std::thread;

        let socket_path = std::env::temp_dir().join(format!(
            "seekret-test-agent-denied-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket_path);

        let key = test_key();
        let pubkey_blob = key.public_key().to_bytes().unwrap();

        // Set up agent state with public keys only
        let state = make_state(vec![SshPublicKeyRecord {
            public_key: key.public_key().clone(),
            comment: "socket-test".to_string(),
        }]);

        let listener = UnixListener::bind(&socket_path).expect("Failed to bind test socket");

        // Create a key fetcher that always denies (simulates HTTP 401)
        let fetcher = mock_fetcher_denied();

        let sock_path_clone = socket_path.clone();
        let agent_thread = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("Accept failed");
            while let Some(req) = read_agent_msg(&mut sock) {
                let reply = handle_request(&req, &state, &*fetcher);
                if write_agent_msg(&mut sock, &reply).is_err() {
                    break;
                }
            }
            let _ = std::fs::remove_file(&sock_path_clone);
        });

        let mut client =
            UnixStream::connect(&socket_path).expect("Failed to connect to test socket");

        // Sign request — should fail (fetcher denies)
        let mut sign_req = vec![SSH2_AGENTC_SIGN_REQUEST];
        sign_req.extend(build_sign_request(&pubkey_blob, b"please sign this", 0));
        write_agent_msg(&mut client, &sign_req).expect("Failed to send sign request");
        let sign_resp = read_agent_msg(&mut client).expect("Failed to read sign response");
        assert_eq!(
            sign_resp,
            vec![SSH_AGENT_FAILURE],
            "Sign should fail when fetcher denies"
        );

        drop(client);
        agent_thread.join().expect("Agent thread panicked");
    }
}
