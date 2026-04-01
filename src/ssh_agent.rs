/// SSH Agent implementation for seekret-service.
///
/// Exposes SSH private keys from a KeePass database via the SSH agent protocol.
/// On Linux/macOS a Unix domain socket is used; on Windows a named pipe at
/// `\\.\pipe\openssh-ssh-agent` provides the same functionality. SSH keys are
/// fetched from the HTTP API instead of opening the KeePass database directly.
/// Signing requests are only served when the user has recently authorized
/// access through the main HTTP authorization flow.
use chrono::{Duration, Utc};
use log::{debug, info, warn};
use signature::Signer;
use ssh_encoding::Encode;
use ssh_key::PrivateKey;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
#[cfg(not(target_os = "windows"))]
use std::os::unix::fs::PermissionsExt;
#[cfg(not(target_os = "windows"))]
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Mutex;

#[cfg(target_os = "windows")]
use std::io::{Error as IoError, ErrorKind};

use crate::LAST_USER_ACCESS;
use crate::RESETCACHE;

// SSH agent protocol message types (IETF draft-miller-ssh-agent)
pub(crate) const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub(crate) const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
pub(crate) const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub(crate) const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
pub(crate) const SSH_AGENT_FAILURE: u8 = 5;
pub(crate) const SSH_AGENTC_EXTENSION: u8 = 27;

/// A loaded SSH key with its KeePass entry path used as comment.
pub(crate) struct SshKeyRecord {
    pub(crate) private_key: PrivateKey,
    pub(crate) comment: String,
}

/// Shared agent state protected by a Mutex.
pub(crate) struct SshAgentState {
    pub(crate) keys: Vec<SshKeyRecord>,
    pub(crate) timeout_secs: i64,
    pub(crate) use_touch_id: bool,
    /// When true, the agent prompts the user for authorization on sign requests
    /// if the current authorization has expired. Set to false in tests.
    pub(crate) prompt_on_deny: bool,
}

/// Reads one SSH agent protocol message from the stream.
///
/// # Arguments
///
/// * `stream` - Any readable stream implementing `Read`.
///
/// # Returns
///
/// `Some(data)` on success, `None` on EOF or protocol error.
pub(crate) fn read_agent_msg(stream: &mut impl Read) -> Option<Vec<u8>> {
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
///
/// # Arguments
///
/// * `stream` - Any writable stream implementing `Write`.
/// * `msg` - The message payload to send.
///
/// # Returns
///
/// An `io::Result<()>` indicating success or failure.
pub(crate) fn write_agent_msg(stream: &mut impl Write, msg: &[u8]) -> std::io::Result<()> {
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
pub(crate) fn handle_request(data: &[u8], state: &Mutex<SshAgentState>) -> Vec<u8> {
    if data.is_empty() {
        return failure_msg();
    }
    match data[0] {
        SSH2_AGENTC_REQUEST_IDENTITIES => handle_identities(state),
        SSH2_AGENTC_SIGN_REQUEST => handle_sign(&data[1..], state),
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
        let pubkey_blob = k.private_key.public_key().to_bytes().unwrap_or_default();
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
/// Signing is only performed when the shared `LAST_USER_ACCESS` indicates
/// recent authorization.
pub(crate) fn handle_sign(data: &[u8], state: &Mutex<SshAgentState>) -> Vec<u8> {
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

    let state = state.lock().unwrap();

    // Find key matching the requested public key blob
    let matching_key = state
        .keys
        .iter()
        .find(|k| k.private_key.public_key().to_bytes().unwrap_or_default() == key_blob);

    let key_record = match matching_key {
        Some(k) => k,
        None => {
            debug!("SSH agent: no matching key found");
            return failure_msg();
        }
    };

    // Check authorization: prompt the user if not recently authorized
    let authorized = {
        let last_access = LAST_USER_ACCESS.lock().unwrap();
        match *last_access {
            None => false,
            Some(ts) => {
                let timeout = Duration::seconds(state.timeout_secs);
                ts + timeout >= Utc::now()
            }
        }
    };

    if !authorized {
        if !state.prompt_on_deny {
            info!(
                "SSH agent: signing denied for '{}' — authorization expired",
                key_record.comment
            );
            return failure_msg();
        }
        info!(
            "SSH agent: authorization required for '{}' — prompting user",
            key_record.comment
        );
        let granted = if state.use_touch_id {
            crate::user_authorization_dialog_touchid()
        } else {
            crate::user_authorization_dialog_basic()
        };
        if granted {
            let mut last_access = LAST_USER_ACCESS.lock().unwrap();
            *last_access = Some(Utc::now());
        } else {
            info!(
                "SSH agent: signing denied for '{}' — user rejected authorization",
                key_record.comment
            );
            return failure_msg();
        }
    }

    // Perform signing
    match key_record.private_key.try_sign(&to_sign) {
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
            debug!("SSH agent: signed request for '{}'", key_record.comment);
            out
        }
        Err(e) => {
            warn!("SSH agent: signing failed: {e}");
            failure_msg()
        }
    }
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
    let mut stream =
        TcpStream::connect(&addr).map_err(|e| format!("failed to connect to {addr}: {e}"))?;
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
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

/// Fetches SSH private keys from the HTTP API.
///
/// For each entry path, fetches the `ssh-key` (PEM) and `secret` (passphrase)
/// from the local HTTP service. If the key is encrypted, the passphrase from
/// the `secret` endpoint is used to decrypt it.
///
/// # Arguments
///
/// * `port` - The HTTP server port.
/// * `entry_paths` - KeePass entry paths to load SSH keys from.
///
/// # Returns
///
/// A vector of successfully loaded key records.
pub(crate) fn fetch_ssh_keys(port: u16, entry_paths: &[String]) -> Vec<SshKeyRecord> {
    let mut keys = Vec::new();
    for path in entry_paths {
        let pem = match http_get_localhost(port, &format!("/{path}/ssh-key")) {
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

        let private_key = match PrivateKey::from_openssh(&pem) {
            Ok(key) => {
                if key.is_encrypted() {
                    // Fetch the passphrase from the secret endpoint
                    let passphrase = match http_get_localhost(port, &format!("/{path}/secret")) {
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
                    match key.decrypt(&passphrase) {
                        Ok(decrypted) => decrypted,
                        Err(e) => {
                            warn!("SSH agent: failed to decrypt key from '{path}': {e}");
                            continue;
                        }
                    }
                } else {
                    key
                }
            }
            Err(e) => {
                warn!("SSH agent: failed to parse SSH key from '{path}': {e}");
                continue;
            }
        };

        info!("SSH agent: loaded key from '{path}'");
        keys.push(SshKeyRecord {
            private_key,
            comment: path.clone(),
        });
    }
    keys
}

/// Starts the SSH agent on Linux/macOS, binding to a Unix socket and serving
/// requests.
///
/// This function blocks indefinitely (designed to run in a dedicated thread).
/// SSH keys are fetched from the local HTTP API on startup and refreshed
/// whenever the KeePass file-change flag (`RESETCACHE`) is set. Signing is
/// gated on recent user authorization through the main HTTP service.
///
/// # Arguments
///
/// * `port` - The HTTP server port to fetch SSH keys from.
/// * `entry_paths` - KeePass entry paths containing SSH private keys.
/// * `socket_path` - Path for the Unix domain socket.
/// * `timeout_secs` - Authorization timeout in seconds (shared with HTTP service).
/// * `use_touch_id` - Whether to use Touch ID for authorization prompts.
#[cfg(not(target_os = "windows"))]
pub fn run_agent(
    port: u16,
    entry_paths: Vec<String>,
    socket_path: PathBuf,
    timeout_secs: i64,
    use_touch_id: bool,
) {
    // Fetch initial keys from the HTTP API
    let keys = fetch_ssh_keys(port, &entry_paths);

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

    let state = Mutex::new(SshAgentState {
        keys,
        timeout_secs,
        use_touch_id,
        prompt_on_deny: true,
    });

    for stream in listener.incoming() {
        match stream {
            Ok(mut sock) => {
                debug!("SSH agent: new client connection");
                while let Some(req) = read_agent_msg(&mut sock) {
                    // Check if cache reset was flagged — reload keys from HTTP
                    let reset = *RESETCACHE.lock().unwrap();
                    if reset {
                        info!("SSH agent: KeePass file changed — reloading keys from HTTP API");
                        let new_keys = fetch_ssh_keys(port, &entry_paths);
                        let mut st = state.lock().unwrap();
                        st.keys = new_keys;
                    }
                    let reply = handle_request(&req, &state);
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

/// Starts the SSH agent on Windows, binding to the OpenSSH named pipe and
/// serving requests.
///
/// The pipe is created at `\\.\pipe\openssh-ssh-agent` which is the standard
/// path that Windows OpenSSH clients (`ssh.exe`, Git for Windows, etc.)
/// connect to. Each client connection is handled sequentially on the agent
/// thread. The pipe is configured with a security descriptor that restricts
/// access to the current user.
///
/// This function blocks indefinitely (designed to run in a dedicated thread).
/// SSH keys are fetched from the local HTTP API on startup and refreshed
/// whenever the KeePass file-change flag (`RESETCACHE`) is set. Signing is
/// gated on recent user authorization through the main HTTP service.
///
/// # Arguments
///
/// * `port` - The HTTP server port to fetch SSH keys from.
/// * `entry_paths` - KeePass entry paths containing SSH private keys.
/// * `pipe_name` - The named pipe path (e.g. `\\.\pipe\openssh-ssh-agent`).
/// * `timeout_secs` - Authorization timeout in seconds (shared with HTTP service).
/// * `use_touch_id` - Whether to use Touch ID/Windows Hello for authorization prompts.
#[cfg(target_os = "windows")]
pub fn run_agent(
    port: u16,
    entry_paths: Vec<String>,
    pipe_name: String,
    timeout_secs: i64,
    use_touch_id: bool,
) {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows::Win32::Storage::FileSystem::FlushFileBuffers;
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_ACCESS_DUPLEX,
        PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    // Fetch initial keys from the HTTP API
    let keys = fetch_ssh_keys(port, &entry_paths);

    if keys.is_empty() {
        warn!("SSH agent: no SSH keys loaded — agent will start but have no identities");
    }

    info!("SSH agent: creating named pipe at {pipe_name}");

    let state = Mutex::new(SshAgentState {
        keys,
        timeout_secs,
        use_touch_id,
        prompt_on_deny: true,
    });

    let pipe_name_h = HSTRING::from(&pipe_name);

    loop {
        // Create a new instance of the named pipe for each client
        let pipe_handle = unsafe {
            CreateNamedPipeW(
                &pipe_name_h,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                255,  // max instances
                4096, // out buffer size
                4096, // in buffer size
                0,    // default timeout
                None, // default security (current user)
            )
        };

        let pipe_handle = match pipe_handle {
            Ok(h) => h,
            Err(e) => {
                log::error!("SSH agent: failed to create named pipe: {e}");
                return;
            }
        };

        if pipe_handle == INVALID_HANDLE_VALUE {
            log::error!("SSH agent: CreateNamedPipeW returned INVALID_HANDLE_VALUE");
            return;
        }

        info!("SSH agent: waiting for client connection on {pipe_name}");

        // Wait for a client to connect
        let connect_result = unsafe { ConnectNamedPipe(pipe_handle, None) };
        match connect_result {
            Ok(()) => {}
            Err(e) => {
                if e.code() == ERROR_PIPE_CONNECTED.to_hresult() {
                    // Client connected between CreateNamedPipe and ConnectNamedPipe
                    debug!("SSH agent: client already connected");
                } else {
                    log::error!("SSH agent: ConnectNamedPipe failed: {e}");
                    let _ = unsafe { CloseHandle(pipe_handle) };
                    continue;
                }
            }
        }

        debug!("SSH agent: new client connection");

        // Wrap the pipe handle in a struct implementing Read + Write
        let mut pipe_stream = NamedPipeStream {
            handle: pipe_handle,
        };

        while let Some(req) = read_agent_msg(&mut pipe_stream) {
            // Check if cache reset was flagged — reload keys from HTTP
            let reset = *RESETCACHE.lock().unwrap();
            if reset {
                info!("SSH agent: KeePass file changed — reloading keys from HTTP API");
                let new_keys = fetch_ssh_keys(port, &entry_paths);
                let mut st = state.lock().unwrap();
                st.keys = new_keys;
            }
            let reply = handle_request(&req, &state);
            if write_agent_msg(&mut pipe_stream, &reply).is_err() {
                break;
            }
        }

        // Disconnect and close the pipe instance
        let _ = unsafe { FlushFileBuffers(pipe_handle) };
        let _ = unsafe { DisconnectNamedPipe(pipe_handle) };
        let _ = unsafe { CloseHandle(pipe_handle) };
    }
}

/// Wrapper around a Windows named pipe `HANDLE` that implements `Read` and
/// `Write` so the generic `read_agent_msg` / `write_agent_msg` functions can
/// operate on it.
#[cfg(target_os = "windows")]
struct NamedPipeStream {
    handle: windows::Win32::Foundation::HANDLE,
}

#[cfg(target_os = "windows")]
impl Read for NamedPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use windows::Win32::Storage::FileSystem::ReadFile;

        let mut bytes_read = 0u32;
        unsafe {
            ReadFile(self.handle, Some(buf), Some(&mut bytes_read), None)
                .map_err(|e| IoError::new(ErrorKind::Other, format!("ReadFile failed: {e}")))?;
        }
        Ok(bytes_read as usize)
    }
}

#[cfg(target_os = "windows")]
impl Write for NamedPipeStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use windows::Win32::Storage::FileSystem::WriteFile;

        let mut bytes_written = 0u32;
        unsafe {
            WriteFile(self.handle, Some(buf), Some(&mut bytes_written), None)
                .map_err(|e| IoError::new(ErrorKind::Other, format!("WriteFile failed: {e}")))?;
        }
        Ok(bytes_written as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        use windows::Win32::Storage::FileSystem::FlushFileBuffers;

        unsafe {
            FlushFileBuffers(self.handle).map_err(|e| {
                IoError::new(ErrorKind::Other, format!("FlushFileBuffers failed: {e}"))
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ssh_key::{rand_core::OsRng, Algorithm, PrivateKey};
    use std::sync::Mutex;

    /// Serializes tests that read/write the global LAST_USER_ACCESS static.
    /// Tests must hold this lock while they depend on a specific authorization state.
    static AUTH_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    /// Helper: build an SshAgentState with the given keys and timeout.
    /// Prompting is disabled so tests never open GUI dialogs.
    fn make_state(keys: Vec<SshKeyRecord>, timeout_secs: i64) -> Mutex<SshAgentState> {
        Mutex::new(SshAgentState {
            keys,
            timeout_secs,
            use_touch_id: false,
            prompt_on_deny: false,
        })
    }

    /// Helper: set LAST_USER_ACCESS to a specific value.
    fn set_last_user_access(value: Option<chrono::DateTime<Utc>>) {
        let mut guard = LAST_USER_ACCESS.lock().unwrap();
        *guard = value;
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
        let state = make_state(vec![], 10);
        let result = handle_request(&[], &state);
        assert_eq!(result, vec![SSH_AGENT_FAILURE]);
    }

    #[test_log::test]
    fn test_handle_request_unknown_type_returns_failure() {
        let state = make_state(vec![], 10);
        let result = handle_request(&[99], &state);
        assert_eq!(result, vec![SSH_AGENT_FAILURE]);
    }

    #[test_log::test]
    fn test_handle_request_identities_type() {
        let state = make_state(vec![], 10);
        let result = handle_request(&[SSH2_AGENTC_REQUEST_IDENTITIES], &state);
        assert_eq!(result[0], SSH2_AGENT_IDENTITIES_ANSWER);
    }

    // ── handle_identities tests ──────────────────────────────────────

    #[test_log::test]
    fn test_identities_no_keys() {
        let state = make_state(vec![], 10);
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
        let state = make_state(
            vec![SshKeyRecord {
                private_key: key,
                comment: comment.to_string(),
            }],
            10,
        );

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
        let keys: Vec<SshKeyRecord> = (0..3)
            .map(|i| SshKeyRecord {
                private_key: test_key(),
                comment: format!("key-{i}"),
            })
            .collect();
        let state = make_state(keys, 10);
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
    fn test_sign_denied_when_not_authorized() {
        let _lock = AUTH_TEST_LOCK.lock().unwrap();
        set_last_user_access(None);

        let key = test_key();
        let pubkey_blob = key.public_key().to_bytes().unwrap();
        let state = make_state(
            vec![SshKeyRecord {
                private_key: key,
                comment: "test".to_string(),
            }],
            10,
        );

        let req = build_sign_request(&pubkey_blob, b"data to sign", 0);
        let result = handle_sign(&req, &state);
        assert_eq!(
            result,
            vec![SSH_AGENT_FAILURE],
            "Should deny when unauthorized"
        );
    }

    #[test_log::test]
    fn test_sign_denied_when_authorization_expired() {
        let _lock = AUTH_TEST_LOCK.lock().unwrap();
        // Set authorization to 20 seconds ago, timeout is 10 seconds
        set_last_user_access(Some(Utc::now() - chrono::Duration::seconds(20)));

        let key = test_key();
        let pubkey_blob = key.public_key().to_bytes().unwrap();
        let state = make_state(
            vec![SshKeyRecord {
                private_key: key,
                comment: "test".to_string(),
            }],
            10,
        );

        let req = build_sign_request(&pubkey_blob, b"data to sign", 0);
        let result = handle_sign(&req, &state);
        assert_eq!(
            result,
            vec![SSH_AGENT_FAILURE],
            "Should deny when authorization expired"
        );
    }

    #[test_log::test]
    fn test_sign_succeeds_when_authorized() {
        let _lock = AUTH_TEST_LOCK.lock().unwrap();
        // Set authorization to now
        set_last_user_access(Some(Utc::now()));

        let key = test_key();
        let pubkey_blob = key.public_key().to_bytes().unwrap();
        let state = make_state(
            vec![SshKeyRecord {
                private_key: key,
                comment: "test".to_string(),
            }],
            10,
        );

        let req = build_sign_request(&pubkey_blob, b"data to sign", 0);
        let result = handle_sign(&req, &state);
        assert_eq!(
            result[0], SSH2_AGENT_SIGN_RESPONSE,
            "Should return sign response"
        );
        assert!(result.len() > 5, "Response should contain a signature blob");
    }

    #[test_log::test]
    fn test_sign_wrong_key_returns_failure() {
        let _lock = AUTH_TEST_LOCK.lock().unwrap();
        set_last_user_access(Some(Utc::now()));

        let key = test_key();
        let wrong_key = test_key();
        let wrong_blob = wrong_key.public_key().to_bytes().unwrap();
        let state = make_state(
            vec![SshKeyRecord {
                private_key: key,
                comment: "test".to_string(),
            }],
            10,
        );

        let req = build_sign_request(&wrong_blob, b"data to sign", 0);
        let result = handle_sign(&req, &state);
        assert_eq!(
            result,
            vec![SSH_AGENT_FAILURE],
            "Should fail for unknown key"
        );
    }

    #[test_log::test]
    fn test_sign_malformed_request_returns_failure() {
        let state = make_state(vec![], 10);
        // Truncated: only 2 bytes, not enough for an SSH string
        let result = handle_sign(&[0, 0], &state);
        assert_eq!(result, vec![SSH_AGENT_FAILURE]);
    }

    // ── Full round-trip over Unix socket ─────────────────────────────

    #[cfg(not(target_os = "windows"))]
    #[test_log::test]
    fn test_agent_socket_round_trip() {
        let _lock = AUTH_TEST_LOCK.lock().unwrap();
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::thread;

        let socket_path =
            std::env::temp_dir().join(format!("seekret-test-agent-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket_path);

        let key = test_key();
        let pubkey_blob = key.public_key().to_bytes().unwrap();

        // Set up agent state and listener
        let state = make_state(
            vec![SshKeyRecord {
                private_key: key,
                comment: "socket-test".to_string(),
            }],
            60,
        );

        let listener = UnixListener::bind(&socket_path).expect("Failed to bind test socket");

        let sock_path_clone = socket_path.clone();
        let agent_thread = thread::spawn(move || {
            // Accept one connection, handle messages, then exit
            let (mut sock, _) = listener.accept().expect("Accept failed");
            while let Some(req) = read_agent_msg(&mut sock) {
                let reply = handle_request(&req, &state);
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

        // 2. Sign request — should fail (no authorization)
        set_last_user_access(None);
        let mut sign_req = vec![SSH2_AGENTC_SIGN_REQUEST];
        sign_req.extend(build_sign_request(&pubkey_blob, b"please sign this", 0));
        write_agent_msg(&mut client, &sign_req).expect("Failed to send sign request");
        let sign_resp = read_agent_msg(&mut client).expect("Failed to read sign response");
        assert_eq!(
            sign_resp,
            vec![SSH_AGENT_FAILURE],
            "Sign should fail without authorization"
        );

        // 3. Authorize and sign again — should succeed
        set_last_user_access(Some(Utc::now()));
        write_agent_msg(&mut client, &sign_req).expect("Failed to send second sign request");
        let sign_resp2 = read_agent_msg(&mut client).expect("Failed to read second sign response");
        assert_eq!(
            sign_resp2[0], SSH2_AGENT_SIGN_RESPONSE,
            "Sign should succeed when authorized"
        );

        // Close client, agent thread will exit
        drop(client);
        agent_thread.join().expect("Agent thread panicked");
    }
}
