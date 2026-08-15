# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Block direct database client execution in run/script mode: commands that put
  `psql`/`pgcli` in command position — including `docker exec <c> psql ...`,
  `sudo -u postgres psql ...`, `sh -c 'psql ...'`, `kubectl exec ... -- psql`,
  pipes into psql, and command substitution — are rejected before any network
  work with guidance to use the guarded `sshx sql` pipeline instead.
  Availability probes (`which psql`, `psql --version`, `pg_isready`) remain
  allowed, and `--force` still provides an audited explicit bypass.

## [0.4.0] - 2026-08-15

### Added

- Add guarded PostgreSQL execution through `sshx sql`: strict single-statement
  classification, fail-closed policy gates, mandatory DML `EXPLAIN`, row-impact
  estimation, automatic row/table backups, dry-run plans, structured JSON
  results, and SQL-specific audit metadata.
- Add production Docker database support with container-local `psql`,
  remote credential discovery from container environments or deployment env
  files, and short-lived OS-keyring caching with explicit refresh and expiry.
- Extend the embedded Agent skill with the SQL safety contract, backup strategy,
  Docker credential workflow, stable result fields, and operational examples.

### Security

- Keep database passwords out of command arguments and audit records by
  delivering them through SSH stdin and environment passthrough only.
- Permanently block multi-statement input and SQL forms that cannot be safely
  bounded, including psql meta-commands, data-modifying CTE bodies,
  `EXPLAIN ANALYZE`, `SELECT INTO`, `CALL`, dblink delegated execution, `DROP DATABASE/SCHEMA`,
  `ALTER SYSTEM`, `COPY`, `DO`, and transaction-control statements; execute
  accepted reads in a PostgreSQL read-only transaction.
- Redact SQL literal values from audit/JSON output while recording an exact
  SHA-256 digest, create backup artifacts with owner-only permissions, and
  run DML backup and mutation under one transaction plus a target-table write
  lock. Catalog preflight blocks automatic execution when triggers, rewrite
  rules, partitions, or cascading referential actions prevent a bounded backup;
  UPSERT targets are backed up before overwrite.
- Raise the build and CI toolchain to Go 1.25.13, which contains the standard
  library fixes for GO-2026-6218 and GO-2026-5972.

## [0.3.0] - 2026-08-13

### Added

- Add the canonical `sshx run` execution contract with versioned request/result
  models, strict target selectors (`--target`/`--targets`/`--group`/`--tag`/
  `--all-hosts`/`--address`), byte-preserving `--script-file`/`--script-stdin`
  payloads (SHA-256 digest + size limits), bounded multi-host fan-out
  (`--concurrency` default 4 / hard max 32), `--failure-mode=continue|fail_fast`,
  and JSONL run events (`run_started` / `target_*` / `run_finished`).
- Extend host inventory with `groups`, `tags`, `ssh_password_key`, and
  `sudo_password_key` while keeping legacy `password_key` as a sudo-only alias.
- Correlate audit events with `run_id`, selector/payload digests, action intent,
  bypass reason, and per-target completion certainty.

### Changed

- Stop implicitly loading a working-directory `.env` file.
- High-risk trust relaxations (`force`, safety-check disablement, unknown-host
  acceptance, insecure host-key mode) now require explicit CLI/request fields;
  inherited environment values are ignored with a diagnostic.
- Host diagnostics and execution paths no longer treat sudo password keys as SSH
  login credentials.

### Security

- Separate SSH-login and sudo credential roles end-to-end so a host with only
  `sudo_password_key` never attempts password authentication.
- Safety bypass on `sshx run` requires a non-empty `--bypass-reason` recorded in
  dry-run, result, and audit metadata.

## [0.2.0] - 2026-08-12

### Added

- Add `sshx skill install` with a canonical Skill embedded in the binary, an
  idempotent JSON result, configurable destination, atomic writes, conflict
  protection, managed-version digest tracking, and symlink rejection. This
  makes Skill installation and later upgrades available after Homebrew and
  `go install` without another download.

## [0.1.0] - 2026-08-12

### Added

- Add `sshx inspect` with built-in system/resource/network capabilities and a
  schema-valid observation envelope that distinguishes complete, partial,
  unsupported, and failed outcomes.
- Add the Agent-native `sshx plugin create/list/show/validate/test/trust/remove`
  lifecycle. Editable Docker, Nginx, and custom collectors live under the sshx
  runtime root instead of Agent skills.
- Add opt-in, freshness-bounded remote observation snapshots with atomic writes,
  cache-hit metadata, identity invalidation, redaction, and restrictive access.
- Add `SSHX_HOME` so Agent and CI runs can isolate settings, audit, plugins, and
  plugin trust state under one runtime root.
- Add compiled-binary SSH/SFTP E2E coverage for command execution, structured
  results, host trust, permissions, partial completion, dry-run, host import,
  SFTP, server-to-server transfer, keyring-backed sudo, and audit recovery.
- Run the E2E suite on Linux and macOS CI, including production-binary checks
  against an ephemeral macOS Keychain.
- Bundle the matching Agent skill in release archives and install it alongside
  the binary through the Linux/macOS installer.

### Changed

- Separate SSH login and sudo password fields while preserving the documented
  keyring boundary: stored password keys are used for sudo, not SSH login.
- Upgrade the CI cache and Codecov actions to their supported major versions.
- Raise the minimum Go toolchain to 1.25.10 so sshx consumes patched standard
  library code and the patched SSH
  implementation in `golang.org/x/crypto v0.52.0`.
- Fail the release workflow when a tag has no exact versioned changelog entry.
- Allow the tag script to accept an explicit semantic version and reject tags
  without a matching changelog section.

### Security

- Reject new or modified local plugins before network access until their current
  manifest, collector, and schema digest is explicitly trusted.
- Treat remote observation snapshots as untrusted input by enforcing schema and
  size limits, owner-only permissions, authenticated UID binding, clean paths,
  parent-directory checks, symlink rejection, and host-key/boot-ID identity.
- Reject a symlinked remote observation root before creating any managed cache
  directories, preventing writes outside the intended cache tree.

### Fixed

- Make public-key rejection correctly trigger an explicitly configured SSH
  password fallback; the previous check matched a server-side error type that
  the SSH client does not return.
- Keep local audit write failures visible at error log level without changing
  a successfully completed remote command into a false execution failure.

### Documentation

- Document the built-in/application capability split, local plugin contract,
  observation cache, and the rule that Agent skills do not own collector scripts.
- Reposition sshx as an agent-native remote host execution tool: SSH is the
  trusted channel and X is execution. Add the efficiency and security model,
  hard product boundaries, future directions, and an evidence-based capability
  coverage matrix with mandatory E2E floors.

## [0.0.14] - 2026-07-17

### Added

- Selective host import from the OpenSSH client config:
  `sshx --host-import` lists importable `~/.ssh/config` entries (with
  everything skipped and why) and lets you pick by number, name, or `all`;
  `--host-import=<name1,name2>` imports exactly the named entries
  non-interactively (all-or-nothing); `--ssh-config=<path>` selects a
  different source file. Imports map `HostName`/`Port`/`User`/`IdentityFile`
  onto a settings host and always skip wildcard/negated patterns, existing
  names, duplicate addresses, `Host *` defaults, unsupported options
  (reported as ignored), and `%`-token identity files — nothing is imported
  blindly. Covered by `--dry-run` plan preview and the local audit trail.

## [0.0.13] - 2026-07-02

### Added

- Direct server-to-server file transfer:
  `sshx --transfer=<src-host>:<src-path> --to=<dst-host>:<dst-path>` streams
  files from one server to another over SFTP, relaying data through the local
  machine without writing to local disk. Supports single files and recursive
  directory transfers, preserves file permission bits, and places the source
  inside the destination when it is an existing directory. Both endpoints can
  be configured host names (resolved from `~/.sshx/settings.json` with their
  own SSH key/user/port) or IP addresses. Transfer invocations are covered by
  `--dry-run` plan preview (`transfer_source`/`transfer_destination` fields)
  and the local audit trail.

## [0.0.12] - 2026-07-01

### Added

- Local structured audit events are written by default to
  `~/.sshx/audit/sshx-YYYY-MM-DD.jsonl`. Use `--audit-output=<dir>` to choose a
  directory or `--no-audit` / `SSHX_NO_AUDIT=true` to disable audit writing.
  Audit events omit stdout/stderr and never store plaintext passwords or private
  key contents.
- `--dry-run` prints a local execution plan without connecting, executing,
  reading keyring secrets, mutating `known_hosts`, or writing local/remote
  state. Combine with `--json` for agent-readable plan output.
- An mdBook documentation site with English and Chinese guides for getting
  started, host management, SFTP, scripting, security, scenarios, and
  troubleshooting.
- Release automation now publishes/updates a Homebrew tap formula
  (`talkincode/homebrew-tap`) on every tagged release, so macOS/Linux users can
  `brew install talkincode/tap/sshx`. The step is opt-in via the
  `HOMEBREW_TAP_TOKEN` repository secret and no-ops otherwise.

### Changed

- Sudo auto-fill detection now uses one consistent rule across keyring lookup
  and command execution: only commands that start with `sudo` trigger password
  auto-fill. Non-leading `sudo` inside shell wrappers or pipelines is left
  untouched.
- SSH login password fallback now only occurs when an SSH login password is
  explicitly provided; keyring passwords remain scoped to sudo auto-fill.
- Install scripts verify downloaded release checksums before extracting.

### Fixed

- `--json` blocked-command results now redact password, token, secret, and API
  key style arguments in both the `command` field and `error` text, matching the
  audit trail redaction behavior.
- Remote command tokens after the command start or `--` separator are preserved,
  so flags such as `-v`, `--help`, and `--force` are passed to the remote
  command instead of being consumed as local `sshx` flags.
- Recursive SFTP removal now joins remote paths with POSIX-style separators on
  all platforms.

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

[Unreleased]: https://github.com/talkincode/sshx/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/talkincode/sshx/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/talkincode/sshx/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/talkincode/sshx/compare/v0.0.14...v0.1.0
[0.0.14]: https://github.com/talkincode/sshx/compare/v0.0.13...v0.0.14
[0.0.13]: https://github.com/talkincode/sshx/compare/v0.0.12...v0.0.13
[0.0.12]: https://github.com/talkincode/sshx/compare/v0.0.11...v0.0.12
[0.0.7]: https://github.com/talkincode/sshx/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/talkincode/sshx/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/talkincode/sshx/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/talkincode/sshx/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/talkincode/sshx/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/talkincode/sshx/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/talkincode/sshx/releases/tag/v0.0.1
