# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Sudo auto-fill detection now uses one consistent rule across keyring lookup
  and command execution: only commands that start with `sudo` trigger password
  auto-fill. Non-leading `sudo` inside shell wrappers or pipelines is left
  untouched.

## [0.0.11] - 2026-06-13

### Security

- `--password-get` no longer prints the stored secret to an interactive terminal (where it would linger in scrollback). On a TTY it now only confirms the key exists; the raw value is emitted **only** when stdout is piped or redirected (e.g. `PW=$(sshx --password-get=key)` or `sshx --password-get=key | pbcopy`), with no decoration for clean capture

### Changed

- `--help` and the no-argument usage screen now print the build version (`Version: <version>`)
- Version flag detection (`--version`/`-v`/`-V`) now stops at the start of the remote command, so a `-v` token inside an unquoted command is no longer mistaken for a version request

### Documentation

- Agent skill (`skills/sshx/SKILL.md`): clarified that the sudo keyring key is resolved per host (named hosts use their own `password_key`; `-pk=`/`SSH_SUDO_KEY` override) and `master` is only the last-resort fallback — so agents no longer assume every host uses `master`

## [0.0.10] - 2026-06-09

### Added

- **Host Configuration Management** - Store and manage frequently used host configurations
  - Configuration file: `~/.sshx/settings.json`
  - Add hosts interactively with `--host-add`
  - List configured hosts with `--host-list`
  - Test host connections with `--host-test=<name>`
  - Test all hosts with `--host-test-all`, get per-host authentication reports, and benefit from a fast 10s dial timeout so unreachable hosts no longer block the run
  - Remove hosts with `--host-remove=<name>`
  - Auto-resolve host details when using `-h=<hostname>`
  - Support for default SSH key path in settings
  - Per-host password key configuration
  - **Per-host SSH key configuration** - each host can use its own SSH private key via `-i=`/`--key=` (with `--host-add`/`--host-update`) or the `key` field in `settings.json`; falls back to the global key when unset
- **Flexible authentication controls**
  - `--no-key`/`--password-only` flag and `SSH_DISABLE_KEY` environment variable to force password-only sessions
  - Automatic password fallback when public key authentication fails on hosts that reject keys
- **`--version` flag** (alias `-v`) prints the build version, which is injected at build time via `-ldflags "-X main.Version=<version>"`
- **Agent skill** (`skills/sshx/SKILL.md`) documenting how to drive `sshx` from an AI agent (JSON mode, exit codes, safety checks, host/secret management)

### Removed

- **MCP (Model Context Protocol) server** - `sshx` is now a focused CLI-only tool. The `mcp-stdio` / `--mcp-stdio` mode and all MCP tools have been removed.
- **SSH connection pool** - removed the connection pool that only served the MCP server; CLI commands use direct connections.

### Changed

- Improved `ExecuteCommandWithOutput()` to capture and report comprehensive error details
  - Now includes full stderr output in error messages
  - Now includes stdout output when command fails
  - Now displays process exit codes for better debugging
  - Provides command and host context in error messages
- Updated usage documentation with host management commands
- `make install` now installs the binary to `~/.local/bin` and the agent skill to `~/.agents/skills/sshx` (previously installed to `$GOPATH/bin` and `~/bin`); `make uninstall` removes both

### Fixed

- Improved error message formatting to include all available diagnostic information
- Fixed EOF error handling in PTY execution mode

## [0.0.7] - 2025-11-13

### Added

- New `-pk` / `--password-key` parameter for flexible sudo password key specification
- Multi-server password management best practices documentation
- Support for managing multiple servers with same username but different passwords

### Changed

- Updated password management documentation with correct command formats
- Improved usage examples with multi-server scenarios
- Enhanced documentation clarity for password key naming conventions

### Fixed

- Corrected password management command examples (use `--password-set` instead of `--set-password`)
- Fixed documentation inconsistencies in password management sections

## [0.0.6] - 2025-11-13

### Changed

- Updated module path to match repository name for better package management

### Fixed

- Fixed module path inconsistencies

## [0.0.5] - 2025-11-13

### Added

- Professional Close error handling with CloseIgnore helper function
- SARIF file post-processing for GitHub Code Scanning compatibility
- Enhanced CI workflow with improved error handling

### Changed

- Updated Go version to 1.24 across all CI workflows
- Upgraded CodeQL action from v2 to v3
- Upgraded golangci-lint to v1.62.2
- Simplified golangci-lint configuration for v2 compatibility
- Removed Windows from test matrix to improve CI performance

### Fixed

- Resolved all 31 golangci-lint errors for code quality
- Fixed SARIF file format to comply with GitHub Code Scanning requirements
- Added permission handling for SARIF file post-processing
- Fixed Windows PowerShell parsing issue by forcing bash shell in tests
- Fixed module path and dependency issues

## [0.0.4] - 2025-11-13

### Fixed

- Fixed installation script architecture detection and binary file extraction issues
- Improved platform and architecture detection with Apple Silicon support
- Enhanced error handling in installation scripts

## [0.0.3] - 2025-11-13

### Added

- One-click installation guide and test installation script
- Automatic installation script with quick start guide

### Fixed

- Added missing line breaks in installation instructions for better readability

## [0.0.2] - 2025-11-13

### Changed

- Refactored password management to use "master" as the default key instead of "ma8"

### Fixed

- Fixed SSH key path handling to support user home directory abbreviation (~)

## [0.0.1] - 2025-11-12

### Added

- Initial release with SSH connection pool and script execution functionality
- CI/CD workflow and automated release process
- Tag creation script

[Unreleased]: https://github.com/talkincode/sshx/compare/v0.0.7...HEAD
[0.0.7]: https://github.com/talkincode/sshx/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/talkincode/sshx/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/talkincode/sshx/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/talkincode/sshx/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/talkincode/sshx/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/talkincode/sshx/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/talkincode/sshx/releases/tag/v0.0.1
