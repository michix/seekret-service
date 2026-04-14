# Changelog

## Version 1

### 1.4.0

- (Feature) Adds support for `ssh-agent` on Windwos (with Opus 4.6).
- (Fix) macOS password dialog returns typed input on Cancel instead of empty string.

### 1.3.0

- (Feature) Adds support for `ssh-agent` (with Opus 4.6).
- (Feature) Adds native dialogs to MacOS (with Opus 4.6).
- (Fix) Fixes O(n²) recursion: map.clone() inside recurse_db causes quadratic memory allocation (done by MiniMax M2.5 with opencode).
- (Fix) Corrects watching KeePass file for updates (with ChatGPT 4.1).
- (Fix) Restores window focus on MacOS after showing dialogs (with Opus 4.6).
- (Chore) Adds support for AI (testing).
- (Chore) Adds version number to release binaries created in the GitHub.
- (Chore) Removes simple_crypt which is not used anymore.
- (Chore) Updates dependencies.

### 1.2.7

- Adds version number to release binary file names

### 1.2.6

- Adds application name and version number to all popup window titles
- Updates dependencies

### 1.2.5

- Updates dependencies

### 1.2.4

- Adds check on startup if port is already in use
- Updates dependencies

### 1.2.3

- Fixes maximum password length in Windows dialog
- Upgrades Dependencies

### 1.2.2

- Switches from `simple_crypt` to `RustCrypto` (kudos to @xformerfhs)

### 1.2.1

- Fixes encryption in main memory
- Upgrades Dependencies

### 1.2.0

- Monitors KeePass file and reloads it on change

### 1.1.1

- Fixes output of `--version`
- Updates dependencies

### 1.1.0

- Adds Windows support
- Updates dependencies

### 1.0.0

- Renamed to Seekret-Service

## Version 0

### 0.1.0

- Initial Release
