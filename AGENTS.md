# AGENTS.md - Developer Guide for Seekret Service

Seekret Service is a Rust daemon that exposes KeePass secrets via an HTTP API and optionally an SSH agent. Secrets are encrypted in memory with ChaCha20Poly1305. Platforms: Linux, macOS (Touch ID), Windows (native GUI). The SSH agent works on all three platforms (Unix socket on Linux/macOS, named pipe on Windows).

## Build / Test / Lint

```bash
cargo build                          # dev build
cargo build --release                # release (LTO, stripped, codegen-units=1)
cargo check                          # type-check only

RUST_LOG=debug cargo test -- --nocapture                          # all tests
cargo test test_open_keepass_database -- --nocapture               # single test
RUST_LOG=debug cargo test test_open_keepass_database -- --nocapture # single test + logs

cargo fmt                            # format code
cargo fmt --check                    # check only
cargo clippy -- -W clippy::all       # lint

./update-dependencies.sh             # update deps + build + test + clippy + fmt check
```

**Test database:** `test.kdbx` (password `test`, keyfile `test.key`). Entries: `root_entry1` (user `root-username`, pass `root-password`), `my-ssh-key` (has `ssh-key` custom field), plus entries under `folder1/`, `folder1/folder1.1/`, `folder2/`.

**Manual integration test:**
```bash
RUST_LOG=debug cargo run -- --keepass-path test.kdbx --keepass-keyfile test.key --port 8124 --enable-ssh-agent --ssh-key "my-ssh-key"
curl http://127.0.0.1:8124/root_entry1/secret
curl http://127.0.0.1:8124/root_entry1/username
```

## Project Structure

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI config, HTTP server, KeePass cache, file watcher, auth dialogs, tests |
| `src/ssh_agent.rs` | SSH agent protocol (Unix socket on Linux/macOS, named pipe on Windows) |
| `src/password_window.rs` | Windows-only password input dialog (`winsafe` GUI) |
| `src/ok_abort_window.rs` | Windows-only OK/Abort confirmation dialog (`winsafe` GUI) |
| `build.rs` | Links Windows resource file |
| `update-dependencies.sh` | Automated dependency update pipeline |

## Code Style

### Formatting
- 4-space indentation, UTF-8, LF line endings, trim trailing whitespace (`.editorconfig`)
- JSON/YAML/shell: 2-space indentation
- Always run `cargo fmt` — no custom `rustfmt.toml` exists

### Import Order
Group imports in this order, separated by blank lines:
1. External crates (`actix_web`, `clap`, `keepass`, etc.)
2. Standard library (`std::*`)
3. Platform-conditional imports (`#[cfg(…)] use …`)
4. Local imports (`crate::*`, module declarations)

### Naming
| Kind | Convention | Examples |
|------|-----------|----------|
| Functions | `snake_case` | `get_entry_from_keepass_cache`, `run_agent` |
| Types/Structs | `PascalCase` | `Config`, `SshKeyRecord` |
| Constants | `SCREAMING_SNAKE_CASE` | `KEY_USERNAME`, `SSH_AGENT_FAILURE` |
| Statics/thread-locals | `SCREAMING_SNAKE_CASE` | `RESETCACHE`, `LAST_USER_ACCESS`, `SECRETS_MAP` |
| Local variables | `snake_case` | `entry_path`, `key_blob` |

### Documentation Comments
Use `///` with structured sections on all non-trivial functions:
```rust
/// Brief description.
///
/// # Arguments
///
/// * `param` - Description.
///
/// # Returns
///
/// Description of return value.
```

### Error Handling
- `panic!()` — unrecoverable startup errors (missing files)
- `expect("descriptive message")` — operations that should never fail
- `log::error!()` — runtime errors the program can survive
- `warn!()` — non-fatal issues (SSH agent key parse failures, auth denials)
- `?` operator — error propagation in functions returning `Result`
- `Result<T, E>` / `Option<T>` — fallible and optional operations

### Logging
Use the `log` crate. Enable with `RUST_LOG=debug`.
- `debug!()` — diagnostics (cache ops, protocol details)
- `info!()` — lifecycle events (start/stop, requests, key loading)
- `warn!()` — recoverable problems
- `log::error!()` — actual errors

**Security:** never log passwords or secrets; log lengths only.

### Platform-Specific Code
```rust
#[cfg(target_os = "windows")] mod password_window;
#[cfg(target_os = "linux")]   use std::process::Command;
```
The `ssh_agent` module is compiled unconditionally on all platforms; platform differences are handled with `#[cfg]` gates inside the module (Unix socket vs named pipe). Functions with per-platform implementations (e.g., `get_password_from_user`, `user_authorization_dialog_basic`) each have three `#[cfg]` variants (linux, macos, windows). Use `pub(crate)` when cross-module access is needed.

### Thread Safety
- `static Mutex<T>` — shared state across threads (`RESETCACHE`, `LAST_USER_ACCESS`)
- `thread_local!` with `Cell`/`RefCell` — per-thread state (`SECRETS_MAP`, `CIPHER`, `LAST_KEEPASS_ACCESS`)
- `OnceLock` — one-time initialized statics (macOS main-thread channel)
- Actix server runs with `workers(1)` to keep thread-local state consistent
- Background threads: file watcher, SSH agent (both via `std::thread::spawn`)

### Security Practices
- In-memory encryption of all cached secrets (ChaCha20Poly1305 with random nonces)
- Time-based authorization gating on both HTTP and SSH agent requests
- Unix: SSH agent socket permissions set to `0600`; stale sockets cleaned up on start/exit
- Windows: named pipe uses default security (current user)
- Cache cleared on file change or timeout

### Testing
- Tests use the `#[test_log::test]` attribute (from `test-log` dev dependency)
- SSH agent tests set `prompt_on_deny: false` in `SshAgentState` to avoid GUI dialogs
- Tests that modify global `LAST_USER_ACCESS` hold `AUTH_TEST_LOCK` for serialization
- The Unix socket round-trip test is gated with `#[cfg(not(target_os = "windows"))]`

## Architecture

- **HTTP API:** `/{path}/secret`, `/{path}/username`, and `/{path}/ssh-key` — Actix-web, single worker
- **KeePass cache:** thread-local `SECRETS_MAP` with encrypted values, timeout-based expiry, file-change reset
- **Authorization:** `LAST_USER_ACCESS` static Mutex shared between HTTP handlers and SSH agent; platform-specific dialog prompts the user
- **File watcher:** background thread sets `RESETCACHE` flag on KeePass file changes
- **SSH agent:** optional (`--enable-ssh-agent`); on Linux/macOS listens on a Unix socket, on Windows listens on a named pipe (`\\.\pipe\openssh-ssh-agent`); serves SSH keys from KeePass entries; denies signing when authorization has expired
- **macOS main-thread:** AppKit dialogs must run on the main thread; actix runs on a background thread, closures are dispatched via `MAIN_THREAD_TX`/`MAIN_THREAD_RX` channels

## Commit Messages
Use conventional commits, lowercase after prefix:
- `feat:` new features
- `fix:` bug fixes
- `chore:` maintenance, dependency updates
- `chore(deps):` dependency bumps
- `docs:` documentation changes

## Common Tasks

**Add an HTTP endpoint:** create a `#[get("/path")]` handler returning `impl Responder`, register with `.service()` in `run_webservice`.

**Add a platform-specific feature:** add deps under `[target.'cfg(…)'.dependencies]` in `Cargo.toml`, create `#[cfg]`-gated module/functions for each platform.

**Modify cache behavior:** see `get_entry_from_keepass_cache`, `empty_keepass_cache`, `fill_keepass_cache` in `main.rs`.

**SSH agent keys:** stored as OpenSSH PEM in a custom field named `ssh-key`. If encrypted, the passphrase comes from the Password field of the same entry.
