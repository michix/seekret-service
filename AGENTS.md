# AGENTS.md - Developer Guide for Seekret Service

This guide provides coding agents with essential information for working on the Seekret Service codebase.

## Project Overview

Seekret Service is a daemon for accessing KeePass secrets via an HTTP API, written in Rust. It's a security-focused application that exposes secrets through a local webservice while keeping data encrypted in memory using ChaCha20Poly1305.

**Technology Stack:**
- **Language:** Rust (Edition 2021)
- **Web Framework:** Actix-web 4 with Actix-rt 2
- **Security:** ChaCha20Poly1305 encryption, KeePass library 0.8.3
- **File Monitoring:** notify 8.0.0
- **CLI:** clap 4.5.40 with derive features
- **Logging:** env_logger 0.11 with log 0.4
- **Platform Support:** Linux, macOS (with Touch ID), and Windows (with native GUI)

## Build/Test/Lint Commands

### Building
```bash
# Development build
cargo build

# Optimized release build (with LTO, stripping, single codegen unit)
cargo build --release

# Check compilation without building
cargo check
```

### Testing
```bash
# Run all unit tests with debug output
RUST_LOG=debug cargo test -- --nocapture

# Run a single test
cargo test test_open_keepass_database -- --nocapture

# Run a single test with debug logs
RUST_LOG=debug cargo test test_open_keepass_database -- --nocapture

# Manual integration testing with test database
RUST_LOG=debug cargo run -- --keepass-path test.kdbx --keepass-keyfile test.key --port 8124

# Test API endpoints (in separate terminal)
curl http://127.0.0.1:8124/root_entry1/username
curl http://127.0.0.1:8124/root_entry1/secret
```

**Test Database:** `test.kdbx` with password `test` and keyfile `test.key`
- Entry: `root_entry1`
- Username: `root-username`
- Password: `root-password`

### Linting & Formatting
```bash
# Format all code
cargo fmt

# Check formatting without modifying files
cargo fmt --check

# Run Clippy linter
cargo clippy

# Run Clippy with all warnings
cargo clippy -- -W clippy::all
```

### Updating Dependencies
```bash
# Update all dependencies automatically (recommended)
./update-dependencies.sh

# Or manually update dependencies
cargo update

# Check for outdated dependencies
cargo outdated
```

The `update-dependencies.sh` script automatically:
1. Updates all dependencies to latest compatible versions
2. Builds the project
3. Runs all tests
4. Runs clippy linter
5. Checks code formatting
6. Shows summary of changes

### Cross-Compilation
```bash
# Windows targets
rustup target add x86_64-pc-windows-gnu
rustup target add x86_64-pc-windows-msvc
cargo build --target x86_64-pc-windows-gnu

# Linux targets (for CI)
cargo build --target x86_64-unknown-linux-gnu
cargo build --target aarch64-unknown-linux-gnu

# macOS targets
cargo build --target aarch64-apple-darwin
```

## Code Style Guidelines

### Indentation & Formatting
- **Indentation:** 4 spaces (from .editorconfig)
- **Line endings:** LF (Unix-style)
- **Encoding:** UTF-8
- **Final newline:** Required
- **Trailing whitespace:** Trim
- **JSON/YAML/Shell scripts:** 2-space indentation
- Follow standard Rust formatting conventions (`cargo fmt`)

### Import Organization
Group imports in the following order with blank lines between groups:
1. External crates (e.g., `actix_web`, `clap`, `keepass`)
2. Standard library imports (e.g., `std::fs::File`, `std::path::PathBuf`)
3. Platform-specific conditional imports (e.g., `#[cfg(target_os = "windows")]`)
4. Local module imports

**Example from main.rs:1-36:**
```rust
use actix_web::{get, http::StatusCode, web::{self, Data}, App, HttpResponse, HttpServer, Responder};
use chacha20poly1305::{aead::{Aead, AeadCore, KeyInit, OsRng}, ChaCha20Poly1305};
use clap::Parser;
use keepass::{db::NodeRef, error::DatabaseOpenError, Database, DatabaseKey};
use log::{debug, info};

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

#[cfg(target_os = "windows")]
mod password_window;
#[cfg(target_os = "windows")]
use password_window::PasswordWindow;
```

### Naming Conventions
- **Functions:** `snake_case` (e.g., `get_entry_from_keepass_cache`, `fill_keepass_cache`)
- **Types/Structs:** `PascalCase` (e.g., `Config`, `PasswordWindow`)
- **Constants:** `SCREAMING_SNAKE_CASE` (e.g., `KEY_USERNAME`, `RESETCACHE`)
- **Local variables:** `snake_case` (e.g., `entry_path`, `keepass_path`)
- **Thread-local statics:** `SCREAMING_SNAKE_CASE` (e.g., `LAST_USER_ACCESS`, `SECRETS_MAP`)

### Type Annotations
- Use explicit type annotations for public APIs and complex types
- Let Rust infer types for simple local variables
- Use `PathBuf` for file paths, not `String`
- Use `Option<T>` and `Result<T, E>` for fallible operations

### Documentation Comments
Use Rust doc comments (`///`) for all public functions with:
- Brief description
- `# Arguments` section with parameter descriptions
- `# Returns` section with return value description
- Optional `# Examples` section for complex functions

**Example from main.rs:115-138:**
```rust
/// Checks if a TCP port is already used by another process.
///
/// # Arguments
///
/// * `port` - The port number to check.
///
/// # Returns
///
/// `true` if the port is in use, `false` otherwise.
fn is_port_in_use(port: u16) -> bool {
    use std::net::TcpListener;
    let addr = format!("127.0.0.1:{port}");
    TcpListener::bind(addr).is_err()
}
```

### Error Handling
- Use `Result<T, E>` for fallible operations (e.g., `Result<HashMap<...>, DatabaseOpenError>`)
- Use `expect()` with descriptive messages for operations that should never fail
- Use `panic!()` for unrecoverable errors during initialization (e.g., file not found at startup)
- Use `log::error!()` for runtime errors that don't require panic
- Use `?` operator for error propagation where appropriate

**Examples:**
```rust
// Panic for initialization errors (main.rs:81-86)
if !config.keepass_path.exists() {
    panic!("KeePass file does not exist: {:?}", keepass_path.into_os_string().into_string());
}

// expect() with context (main.rs:229)
let mut keepass_db_file = File::open(keepass_path).expect("KeePass DB file not found");

// log::error for runtime errors (main.rs:102)
if let Err(error) = watch(keepass_path) {
    log::error!("Error: {error:?}");
}
```

### Logging
Use the `log` crate with appropriate levels:
- `debug!()`: Detailed diagnostic information (function entry/exit, cache operations)
- `info!()`: General informational messages (service start/stop, major operations)
- `log::error!()`: Error conditions that don't require panic

Enable logging at runtime with `RUST_LOG=debug` environment variable.

### Platform-Specific Code
Use conditional compilation attributes for platform-specific code:
```rust
#[cfg(target_os = "windows")]
mod password_window;

#[cfg(target_os = "macos")]
use robius_authentication;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;
```

### Thread Safety & Concurrency
- Use `thread_local!` for thread-local storage (cache, cipher instances)
- Use `std::sync::Mutex` for shared mutable state across threads
- Use `Cell` and `RefCell` for thread-local interior mutability
- Server runs with `workers(1)` to ensure thread safety

### Security Best Practices
- Encrypt sensitive data in memory using ChaCha20Poly1305
- Use proper nonce generation (`ChaCha20Poly1305::generate_nonce(&mut OsRng)`)
- Clear caches on timeout or file changes
- Validate user authorization before serving secrets
- Never log passwords or secret values (log lengths only)

### Project-Specific Patterns
- **Cache management:** Use thread-local `SECRETS_MAP` with timeout-based invalidation
- **KeePass entry paths:** Format as `"group/subgroup/entry_name"` without leading slash
- **HTTP endpoints:** `/{entry_path}/secret` and `/{entry_path}/username`
- **Authorization flow:** Time-based user confirmation with configurable timeout
- **File watching:** Background thread monitors KeePass file and sets `RESETCACHE` flag

## Architecture Notes

- **Single-worker server:** Actix-web runs with 1 worker to ensure thread-local state consistency
- **Thread-local caching:** Encrypted secrets stored in `SECRETS_MAP` with automatic expiration
- **File monitoring:** Separate thread watches KeePass file for changes using `notify` crate
- **In-memory encryption:** All cached passwords/usernames encrypted with ChaCha20Poly1305
- **Authorization timeout:** Separate from cache timeout; controls how often user must re-authorize

## Common Tasks

### Adding a new endpoint
1. Create handler function with `#[get("/path")]` attribute
2. Use `Data<Config>` for accessing configuration
3. Return `impl Responder` (usually `HttpResponse`)
4. Register in `App::new()` with `.service(handler_function)`

### Modifying cache behavior
- Cache logic in `get_entry_from_keepass_cache()` (main.rs:181)
- Invalidation logic in `empty_keepass_cache()` (main.rs:164)
- Fill logic in `fill_keepass_cache()` (main.rs:218)

### Adding platform-specific features
1. Add dependencies in `Cargo.toml` under appropriate `[target.'cfg(...)'.dependencies]`
2. Create platform-specific module files
3. Use `#[cfg(target_os = "...")]` attributes for conditional compilation
4. Test on all supported platforms (Linux, macOS, Windows)
