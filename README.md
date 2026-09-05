<!-- markdownlint-disable MD033 MD036 MD040 MD041 -->

```
 $$$$$$\   $$$$$$\  $$\   $$\ $$\   $$\
$$  __$$\ $$  __$$\ $$ |  $$ |$$ |  $$ |
$$ /  \__|$$ /  \__|$$ |  $$ |\$$\ $$  |
\$$$$$$\  \$$$$$$\  $$$$$$$$ | \$$$$  /
 \____$$\  \____$$\ $$  __$$ | $$  $$<
$$\   $$ |$$\   $$ |$$ |  $$ |$$  /\$$\
\$$$$$$  |\$$$$$$  |$$ |  $$ |$$ /  $$ |
 \______/  \______/ \__|  \__|\__|  \__|


Agent-Native Remote Execution over SSH
```

<div align="center">

[![Go Version](https://img.shields.io/github/go-mod/go-version/talkincode/sshx?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![Release](https://img.shields.io/github/v/release/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://github.com/talkincode/sshx/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/talkincode/sshx?style=flat-square)](https://goreportcard.com/report/github.com/talkincode/sshx)
[![Coverage](https://img.shields.io/badge/coverage-48.4%25-yellowgreen?style=flat-square&logo=go)](https://github.com/talkincode/sshx)

[![GitHub Stars](https://img.shields.io/github/stars/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx/network/members)
[![GitHub Issues](https://img.shields.io/github/issues/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx/pulls)

[![GitHub Downloads](https://img.shields.io/github/downloads/talkincode/sshx/total?style=flat-square&logo=github)](https://github.com/talkincode/sshx/releases)
[![GitHub Contributors](https://img.shields.io/github/contributors/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx/graphs/contributors)
[![Last Commit](https://img.shields.io/github/last-commit/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx/commits/main)
[![Repo Size](https://img.shields.io/github/repo-size/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx)

[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=flat-square&logo=linux&logoColor=white)](https://github.com/talkincode/sshx/releases)
[![Made with Go](https://img.shields.io/badge/Made%20with-Go-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://github.com/talkincode/sshx/pulls)

English | [简体中文](./README_CN.md)

</div>

---

# SSHX

> **SSH is the channel. X is execution.**

`sshx` is an **agent-native remote host execution tool**. It uses SSH/SFTP to reach existing hosts and brings target resolution, execution preview, safety checks, command and file actions, structured results, and audit evidence into one CLI invocation.

## Why You Need It?

Agents do not need another interactive SSH shell. They need a stable, composable remote execution contract with explicit side effects. `sshx` reduces argument assembly through named hosts, removes text guessing through JSON, exit codes, and error kinds, and lowers operational risk through dry-run plans, safety guardrails, the OS keyring or explicit local vault, host-key verification, and local auditing.

It remains a single binary with one-shot invocations and no resident component on remote hosts: **efficient, secure, and auditable remote execution for agents over SSH.** Human operators use the same command, preview, and audit semantics for supervision and troubleshooting.

## Project Structure

- `cmd/sshx`: Main binary entry point, responsible for command-line argument parsing and password management features.
- `internal/sshclient`: Core SSH/SFTP/script execution logic and command security validation.
- `internal/app`: CLI command routing, host configuration management, and password management.

## Key Features

1. Agent-friendly JSON/JSONL, stable exit codes, separated stdout/stderr, and classified failures.
2. Canonical `sshx run` contract: strict selectors, byte-preserving scripts, and bounded multi-host fan-out.
3. Dry-run execution plans and default-on local structured auditing with safe redaction.
4. Named host management with groups/tags and selective OpenSSH config import.
5. Strict host-key verification, destructive-command guardrails, and explicit bypass semantics.
6. OS-keyring or explicit local-vault password management with distinct SSH-login and sudo credential roles.
7. Cross-platform SSH/SFTP command and file actions.
8. Direct server-to-server transfer, streamed through the local machine without touching local disk.
9. One-shot host inspection with built-in system/network capabilities, local
   sshx-owned plugins, explicit digest trust, and freshness-bounded observations.
10. Guarded single-file apply: hash precondition, backup, and atomic replace.
11. Built-in stdio MCP server (`sshx mcp`): the same execution contract, safety
    gates, and audit trail exposed as Model Context Protocol tools.
12. Human-only `sshx login` onto a named host, with optional `--sudo` privileged
    shell. Not part of the Agent/MCP contract.
13. Source address binding (`--bind=<ip|iface>`) matching OpenSSH `-b` /
    `BindAddress` / `BindInterface`.

## Installation

### Quick Install with Go (Recommended for Go Users)

If you have Go 1.21+ installed, you can use Go's built-in tools:

#### Run directly without installation (like npx)

```bash
# Run the latest version
go run github.com/talkincode/sshx/cmd/sshx@latest --help

# Run specific version
go run github.com/talkincode/sshx/cmd/sshx@v0.0.6 -h=192.168.1.100 "uptime"
```

#### Install globally

```bash
# Install latest version to $GOPATH/bin
go install github.com/talkincode/sshx/cmd/sshx@latest

# Then use it anywhere
sshx --help
sshx -h=192.168.1.100 "uptime"

# Install the matching Agent skill from the binary
sshx skill install
```

**Note:** Make sure `$GOPATH/bin` (typically `~/go/bin`) is in your PATH.

### Homebrew (macOS / Linux)

```bash
brew install talkincode/tap/sshx
sshx skill install
```

This pulls prebuilt binaries from the [talkincode/homebrew-tap](https://github.com/talkincode/homebrew-tap) repository, updated automatically on every tagged release.
The binary embeds the matching Agent skill; the second command installs it to
`~/.agents/skills/sshx/SKILL.md` without another download.

### One-Line Installation Script

#### Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/talkincode/sshx/main/install.sh | bash
```

The installer verifies the release checksum, installs the binary, and invokes
`sshx skill install --force` to install the matching embedded Agent skill at
`~/.agents/skills/sshx/SKILL.md`.

Or download and run:

```bash
wget https://raw.githubusercontent.com/talkincode/sshx/main/install.sh
chmod +x install.sh
./install.sh
```

Install specific version:

```bash
./install.sh v0.0.2
```

#### Windows

Open PowerShell as Administrator and run:

```powershell
irm https://raw.githubusercontent.com/talkincode/sshx/main/install.ps1 | iex
```

Or download and run:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/talkincode/sshx/main/install.ps1" -OutFile "install.ps1"
.\install.ps1
```

Install specific version:

```powershell
.\install.ps1 -Version v0.0.2
```

### Manual Installation

Download pre-built binaries from [Releases](https://github.com/talkincode/sshx/releases):

**Linux / macOS:**

```bash
# Download and extract (replace <platform>-<arch> with your system)
tar -xzf sshx-<platform>-<arch>.tar.gz

# Move to system path
sudo mv sshx /usr/local/bin/

# Make executable
sudo chmod +x /usr/local/bin/sshx

# Verify installation
sshx --help
```

**Windows:**

1. Download `sshx-windows-amd64.zip`
2. Extract the archive
3. Move `sshx.exe` to a directory in your PATH (e.g., `C:\Program Files\sshx`)
4. Or add the extracted directory to your system PATH

### Build from Source

```bash
# Clone repository
git clone https://github.com/talkincode/sshx.git
cd sshx

# Build command-line tool
go build -o bin/sshx ./cmd/sshx

# Print the version (also exposed via the binary's --version flag)
make version

# Install to system (optional)
# Installs the binary to ~/.local/bin and the agent skill to ~/.agents/skills/sshx
make install

# Check the installed version
sshx --version
```

## Quick Start

```bash
# Execute remote command
sshx -h=192.168.1.100 -u=root "uptime"

# Save password for easier access (interactive input)
sshx --password-set=root

# Or set password for specific host
sshx --password-set=192.168.1.100-root

# Use the saved password for sudo auto-fill
sshx -h=192.168.1.100 -u=root "sudo df -h"

# Transfer a file directly from one server to another (streamed, no local copy)
sshx --transfer=192.168.1.100:/var/log/app.log --to=192.168.1.101:/backup/app.log
```

## Agent / Scripting Mode

`sshx` is designed to be driven by scripts and AI agents, not just humans. The
command-execution path gives you a stable, machine-readable contract.

By default:

- **stdout and stderr stay separate** and stream live (no PTY, no terminal
  control characters mixed in).
- **The remote command's exit status is propagated** as `sshx`'s own exit code.

### Exit codes

| Code     | Meaning                                                             |
| -------- | ------------------------------------------------------------------- |
| `0`      | Command succeeded                                                   |
| `1..254` | Remote command's exit status, propagated verbatim                  |
| `255`    | `sshx`-level failure (connect / auth / host-key / timeout / blocked) |

### `--json` structured output

Add `--json` to get a single JSON object on stdout (diagnostics still go to
stderr, so stdout stays pure):

```bash
sshx -h=prod-web --json "systemctl is-active nginx"
```

```json
{
  "host": "192.168.1.100",
  "port": "22",
  "user": "root",
  "command": "systemctl is-active nginx",
  "exit_code": 0,
  "success": true,
  "stdout": "active\n",
  "stderr": "",
  "duration_ms": 142,
  "auth_method": "key"
}
```

On an `sshx`-level failure the object has `exit_code: -1` and a non-empty
`error_kind` (one of `timeout`, `auth`, `host_key`, `connect`, `blocked`,
`exit_missing`, `config`, `error`), so it is always distinguishable from a
remote command that happens to exit `255`.

### Canonical `sshx run` contract

Prefer `sshx run` for strict aliases, complex scripts, and bounded multi-host
execution:

```bash
sshx run --target=prod-web --json -- "systemctl is-active nginx"
sshx run --group=prod-web --tag=env=prod --concurrency=4 --jsonl -- "uptime"
sshx run --target=prod-web --script-file=./check.sh --json
```

Multi-target exit codes: `0` all succeeded, `1` partial failure/skip/uncertain,
`255` request-level failure (invalid selectors, zero matches, bad input).

### `--dry-run` execution plan preview

Add `--dry-run` to see how `sshx` would interpret an invocation before it opens
an SSH connection, executes a command, performs an SFTP operation, reads keyring
secrets, updates `known_hosts`, or writes settings. Combine it with `--json` for
agent-readable output:

```bash
sshx -h=prod-web --dry-run --json "sudo systemctl restart nginx"
```

Dry-run is a local plan preview. It reports host resolution, mode/action,
sudo-key selection, safety-check result, and whether a real run would connect,
execute, read a secret, or mutate state. It does **not** prove the remote command
would succeed.

### Bind review to execution and inspect effects

Remote previews add a nested `sshx.plan.v1` plan, `plan_hash`, and scalar
`risk` (`read|mutation|privileged|destructive`). After reviewing a bindable
preview, repeat the same invocation with `--expect-plan="$reviewed_hash"`.
The hash must be `sha256:` plus 64 lowercase hex characters. This works for
command/run, apply, SQL, SFTP, transfer and inspect; mismatch fails before
secrets or network work, even with `--force`.

Binding needs explicit IP targets, usable public-key sidecars when key auth
is enabled, and strict available host trust. DNS-only targets, missing pins,
relaxed trust and remotely discovered SQL identities cannot be bound.
The entire sorted trust-record snapshot is hashed, so unrelated `known_hosts`
edits conservatively invalidate a plan. A plan does not freeze remote state.

Results add `execution_id`, `parent_execution_id`, `execution_fingerprint`,
`effects`, `change_state`, nullable `executed`, `verified`, `verification`,
and condition arrays. Unknown commands/scripts default to mutation with
unknown effects; caller `intent=read` is not proof. Success is not verification,
and unknown change state is not “unchanged.” Inspect partial/unknown outcomes
before retrying. Raw output and secret values are not fingerprinted.
See [Plans, Outcomes, and Safe Retries](docs/execution-contract.md).

### Local audit trail

Every non-dry-run invocation writes one JSONL audit event by default:

```text
~/.sshx/audit/sshx-YYYY-MM-DD.jsonl
```

Use `--audit-output=<dir>` to place audit events next to a project, runbook, or
incident record:

```bash
sshx -h=prod-web --audit-output=./.sshx-audit "systemctl reload nginx"
```

Audit events record metadata and outcomes such as mode/action, host resolution,
sudo/keyring decisions, safety status, auth method, exit code, and error kind.
They do **not** record plaintext passwords, private key contents, or
stdout/stderr. Command text is included for provenance but redacted for common
password/token-style arguments. Use `--no-audit` or `SSHX_NO_AUDIT=true` to
disable audit writing for a single invocation or environment.

Use `sshx audit query --execution-id=<id> --json` to correlate an execution.
Corrupt-line diagnostics distinguish damaged records from an empty query.
Audit persistence is best-effort and separate from execution success: a logging
failure is not a reason to repeat a successful mutation.

### `--timeout` and `--pty`

```bash
# Limit the command wait to 30 seconds (also accepts 2m, etc.)
sshx -h=prod-web --timeout=30s "apt-get update"

# Opt back into a PTY for commands that insist on a terminal
# (note: a PTY merges stderr into stdout; it cannot be combined with --json)
sshx -h=prod-web --pty "top -b -n1"
```

The timeout can also be set via the `SSH_TIMEOUT` environment variable.
Optional `--host-timeout` covers an admitted target; `--global-timeout` also
covers queue time. Existing `--timeout` semantics and defaults are unchanged.
For fan-out, `--fail-fast` (alias of `--failure-mode=fail_fast`) and
`--max-failures=N` stop **new admission only**; active targets finish and may add
failures. Cancellation/deadlines can stop active local transports, but do not
guarantee remote process termination or rollback.

### MCP server (stdio)

MCP-capable agents can consume the same execution contract as native tools:

```bash
sshx mcp
```

```json
{
  "mcpServers": {
    "sshx": { "command": "sshx", "args": ["mcp"] }
  }
}
```

The server speaks MCP over stdio only, is spawned and owned by the client, and
re-enters sshx as a one-shot child process per tool call — identical safety
gates, keyring roles, and audit trail (events carry `entry: "mcp"`). Exposed
tools: `sshx_run`, `sshx_sql`, `sshx_apply`, `sshx_inspect`, `sshx_sftp`,
`sshx_transfer`, `sshx_host_list`. Password management is deliberately not
exposed over MCP. See [docs/mcp.md](docs/mcp.md).

## Guarded SQL Execution

Use `sshx sql` instead of sending raw `psql` or `sqlite3` commands through
`sshx run`. It accepts exactly one statement, classifies it locally, blocks
unbounded or unsupported forms, backs up affected data, and records a
structured audit event. Direct `psql`/`pgcli`/`sqlite3` invocations in
run/command mode are blocked.

For PostgreSQL, sshx runs `EXPLAIN (FORMAT JSON)` before DML. Psql backslash
commands, data-modifying CTE bodies, `EXPLAIN ANALYZE`, `SELECT INTO`, `CALL`,
and dblink delegated execution are blocked. Accepted reads run in a
PostgreSQL read-only transaction to prevent writes through the current
connection.

```bash
# Read-only query
sshx sql -h=prod-db --db=app --json "SELECT count(*) FROM users"

# Preview classification, gates, and backup plan without connecting
sshx sql -h=prod-db --db=app --dry-run --json \
  "UPDATE users SET active=false WHERE id=42"

# Execute with a keyring-backed database password
sshx sql -h=prod-db --db=app --db-user=app \
  --db-password-key=app-db --json \
  "UPDATE users SET active=false WHERE id=42"
```

`UPDATE`/`DELETE` without a top-level `WHERE` requires
`--allow-full-table`. Destructive DDL requires `--force --no-backup`; sshx does
not claim an automatic restorable backup for schema destruction. Skipping a DML
backup also requires both `--no-backup` and `--force`. Small changes receive a
row CSV snapshot; complex or large changes receive a full-table CSV snapshot
under `~/.sshx/sql-backups/`. Backup and mutation run in one PostgreSQL
transaction while holding a target-table write lock, closing the concurrency
window between them. Catalog preflight blocks automatic execution when
triggers, rewrite rules, partitions, or cascading referential actions can
affect related tables; proceed only after an independent backup with
`--force --no-backup`.
UPSERTs are treated as overwrites and receive a table backup.
Backups are created with owner-only permissions. Audit records and JSON results
replace literal values with a redacted statement while retaining the exact
statement's SHA-256 digest.

For PostgreSQL running in a production container, execute the database clients
inside the container and resolve credentials from its environment:

```bash
# --docker alone reads the container environment for the role and database,
# so images whose POSTGRES_USER is not "postgres" work without --db-user.
sshx sql -h=prod --docker=pg-prod --json "SELECT count(*) FROM orders"

sshx sql -h=prod --docker=pg-prod \
  --db-cred-from=docker:pg-prod --json \
  "UPDATE users SET active=false WHERE id=42"

sshx sql -h=prod --docker=pg-prod \
  --db-cred-from=env-file:/opt/app/.env \
  --cred-cache=1h --json "SELECT count(*) FROM orders"
```

Remotely resolved credentials are cached for 15 minutes by default. Secret
values live only in the secret backend; local metadata records identity and expiry.

SQLite files live on the application host. Pass an absolute path; there is no
database role or password:

```bash
sshx sql -h=app --engine=sqlite --db-file=/var/lib/app/app.db --json \
  "SELECT count(*) FROM users"

sshx sql -h=app --engine=sqlite --db-file=/var/lib/app/app.db --json \
  "UPDATE users SET active=0 WHERE id=42"
```

SQLite reads open `file:<path>?mode=ro`. Bounded DML snapshots the table to
CSV; overwrites and unbounded changes take a whole-file `sqlite3 .backup`
under `BEGIN IMMEDIATE`. `ATTACH`, sqlite3 dot-commands, `load_extension`,
and writable `PRAGMA` are blocked.
Use `--cred-cache=off` to disable caching or `--cred-refresh` to discard and
resolve the current value again.

## Host Inspection and Local Plugins

Use one structured inspection instead of repeatedly probing an unfamiliar host:

```bash
sshx inspect -h=prod-web system.baseline --json
```

Stable system/network capabilities are built in. Docker, Nginx, and private
application collectors are plugins stored under `~/.sshx/plugins/`—never in an
Agent skill and never installed persistently on the target.

```bash
sshx plugin create docker.environment \
  --template=docker \
  --privilege=optional \
  --json
sshx plugin validate docker.environment --json
sshx plugin test docker.environment --fixture=complete --json
sshx plugin trust docker.environment --json
sshx inspect -h=prod-web docker.environment --json
```

New and edited plugins are untrusted until their current manifest/collector/schema
digest is explicitly trusted. `inspect` checks that trust before opening SSH,
streams the collector through stdin for that session only, validates one JSON
result, and applies field redaction. Plugin trust is not a sandbox; review custom
collectors before trusting them.

Remote observation reuse is opt-in:

```bash
sshx inspect -h=prod-web docker.environment \
  --cache=remote-prefer \
  --max-age=10m \
  --json
```

Only normalized, redacted JSON is saved below the remote user's
`~/.sshx/observations/v1/`. Cache reuse is bound to plugin digest, host-key
fingerprint, platform, boot ID, privilege, parameters, and TTL. Use `--refresh`
to collect again or `--allow-stale` to explicitly accept a matching expired
observation.

The local runtime root defaults to `~/.sshx`; set `SSHX_HOME` to isolate settings,
audit, plugins, and trust state for an Agent or CI run. See
[Inspection Capabilities and Local Plugins](docs/inspection-plugins.md) for the
manifest, lifecycle, cache, and security contracts.

## Host Configuration Management

**NEW!** Manage your frequently used hosts in `~/.sshx/settings.json` for quick access.

### Quick Setup

```bash
# Add hosts interactively
sshx --host-add

# Add host with command line options
sshx --host-add --host-name=prod-web -h=192.168.1.100 -u=root --host-desc="Production Web Server"

# Add a host that uses its own SSH private key
sshx --host-add --host-name=prod-db -h=192.168.1.200 -u=admin -i=~/.ssh/prod-db.pem

# List all configured hosts
sshx --host-list

# Test connection to a configured host
sshx --host-test=prod-web

# Use configured host (auto-resolves from settings)
sshx -h=prod-web "systemctl status nginx"

# Test every configured host and show auth methods
sshx --host-test-all
```

### Configuration File Format

Location: `~/.sshx/settings.json`

```json
{
  "key": "/Users/username/.ssh/id_rsa",
  "hosts": [
    {
      "name": "prod-web",
      "description": "Production Web Server",
      "host": "192.168.1.100",
      "port": "22",
      "user": "root",
      "password_key": "prod-web-password",
      "type": "linux"
    },
    {
      "name": "prod-db",
      "description": "Production Database",
      "host": "192.168.1.200",
      "port": "22",
      "user": "admin",
      "key": "/Users/username/.ssh/prod-db.pem",
      "type": "linux"
    }
  ]
}
```

> The top-level `key` is the default SSH private key for all hosts. A per-host `key` overrides the default for that host only.

### Host Management Commands

- `--host-add` - Add new host (interactive or with options)
- `--host-import` - Selectively import hosts from `~/.ssh/config` (interactive picker; `--host-import=<name1,name2>` for non-interactive, `--ssh-config=<path>` to choose the source file). Wildcard patterns, existing names, duplicate addresses, and unsupported options are always skipped and reported — nothing is imported blindly.
- `--host-list` - List all configured hosts
- `--host-test=<name>` - Test connection to a host
- `--host-test-all` - Test connections to all hosts (per-host 10s dial timeout) and show auth method used
- `--host-remove=<name>` - Remove a host from configuration

**Benefits:**

- 📝 Store connection details once, use everywhere
- 🚀 Connect with just a name: `sshx -h=prod-web "command"`
- 🔐 Integrate with password manager for each host
- ✅ Test connections before use

## Password Management

`sshx` stores secrets in the operating system's native credential manager by
default. On headless servers without Secret Service / Keychain, set
`SSHX_SECRET_BACKEND=local-vault` to use an encrypted local vault instead.
The vault is write-only: Agents confirm keys with `--password-check` and
never read values; sshx injects them over stdin during execution.

### Supported Platforms

- **macOS**: Uses Keychain Access
- **Linux**: Uses Secret Service (GNOME Keyring / KDE Wallet)
- **Windows**: Uses Credential Manager
- **Headless Linux / CI**: Encrypted local vault (`SSHX_SECRET_BACKEND=local-vault`)

### Password Commands

#### Save Password

```bash
# Save default sudo password (interactive input, recommended)
sshx --password-set=master

# Save password for specific user
sshx --password-set=root

# Save password for specific host+user combination
sshx --password-set=192.168.1.100-root

# Set password inline (not recommended, insecure)
sshx --password-set=master:yourpassword
```

You will be prompted to enter the password securely (input is hidden).

#### Check Saved Password

```bash
# Check if password exists
sshx --password-check=master
sshx --password-check=root

# Output example:
# ✓ Password exists for key: master
```

#### List Saved Passwords

```bash
# List common password keys
sshx --password-list

# Output example:
# Checking password keys in system keyring...
# Service: sshx
#
# Common keys:
#   ✓ master (exists)
#   ✓ root (exists)
#     sudo (not set)
```

#### Get Password

```bash
# Read a stored password. On a terminal sshx only confirms the key exists; to
# obtain the value, pipe stdout — it is emitted raw, with no decoration.
PW=$(sshx --password-get=master)        # capture into a variable
sshx --password-get=master | pbcopy     # copy to clipboard (macOS)

# Interactive output example (the secret is NOT printed to the terminal):
# ✓ Password exists for key 'master' (service: sshx)
#   Not printing the secret to a terminal. To use it, pipe stdout:
#     sshx --password-get=master | pbcopy
#     sshx --password-get=master | cat
```

`--password-get` is refused when `SSHX_SECRET_BACKEND=local-vault`. Use
`--password-check` and let sshx inject the secret.

#### Local vault (headless)

```bash
export SSHX_SECRET_BACKEND=local-vault
export SSHX_VAULT_PASSPHRASE='a long passphrase'
# or: export SSHX_VAULT_KEY_FILE=/etc/sshx/vault.key   # must be 0600

sshx --password-set=prod-web          # prompt or stdin; value is never printed
sshx --password-check=prod-web
sshx -h=prod-web -pk=prod-web "sudo systemctl status nginx"
```

There is no silent fallback: if the keyring is missing, sshx fails unless
you explicitly select `local-vault`. Dry-run and audit report
`secret_backend` and `secret_unlock` without secret values.

#### Delete Password

```bash
# Delete password
sshx --password-delete=master
sshx --password-delete=root

# Confirmation message:
# ✓ Password deleted from system keyring
#   Service: sshx
#   Key: master
```

### Using Stored Passwords

Once a password is saved, commands that start with `sudo` will automatically retrieve the password from system keyring:

```bash
# 1. First save sudo password
sshx --password-set=master

# 2. Execute sudo commands (automatically uses stored password)
sshx -h=192.168.1.100 -u=root "sudo systemctl status nginx"
sshx -h=192.168.1.100 -u=root "sudo reboot"

# 3. Multi-server scenario: save different passwords for different servers
sshx --password-set=server-A
sshx --password-set=server-B
sshx --password-set=server-C

# 4. Use -pk parameter to specify sudo password key temporarily
sshx -h=192.168.1.100 -pk=server-A "sudo systemctl restart nginx"
sshx -h=192.168.1.101 -pk=server-B "sudo systemctl restart nginx"
sshx -h=192.168.1.102 -pk=server-C "sudo systemctl restart nginx"
```

## Host Key Verification 🔐

`sshx` now enforces strict host key verification just like the OpenSSH client. Instead of silently trusting unknown hosts, the tool reads the trust store from `~/.ssh/known_hosts` (or the path you provide) and aborts the connection if the host is missing or the key changes.

Ways to manage host keys:

- **Add hosts manually** (recommended): `ssh-keyscan -H <host> >> ~/.ssh/known_hosts`
- **One-time automatic trust**: `sshx --accept-unknown-host -h=<host> ...` (or set `SSH_ACCEPT_UNKNOWN_HOST=1`). The first connection records the key; subsequent runs stay strict.
- **Custom trust store**: `sshx --known-hosts=/path/to/known_hosts` or `SSH_KNOWN_HOSTS=/path/to/known_hosts`.
- **Legacy insecure mode (last resort)**: `sshx --insecure-hostkey ...` or `SSH_INSECURE_HOST_KEY=1`. This re-enables the previous `InsecureIgnoreHostKey` behavior and should only be used in controlled environments.

If the host key ever changes, `sshx` clearly explains how to remove the old entry before re-connecting, protecting you from potential man-in-the-middle attacks.

### Password Key Names

- **master**: Default sudo password key name, used for sudo commands
- **root**: Password for root user
- **Custom keys**: You can use any key name, e.g., `server-A`, `server-B`, `prod-db`, etc.

### Best Practices for Multi-Server Password Management

If you manage multiple servers with the same username but different passwords, use this strategy:

```bash
# Scenario: Manage 3 servers, all with root user but different passwords

# 1. Save password for each server (use meaningful key names)
sshx --password-set=prod-web      # Production web server
sshx --password-set=prod-db       # Production database server
sshx --password-set=dev-server    # Development server

# 2. Execute commands using -pk parameter to specify password key
sshx -h=192.168.1.10 -u=root -pk=prod-web "sudo systemctl status nginx"
sshx -h=192.168.1.20 -u=root -pk=prod-db "sudo systemctl status mysql"
sshx -h=192.168.1.30 -u=root -pk=dev-server "sudo docker ps"

# 3. You can also use aliases to simplify commands (add to ~/.zshrc or ~/.bashrc)
alias ssh-prod-web='sshx -h=192.168.1.10 -u=root -pk=prod-web'
alias ssh-prod-db='sshx -h=192.168.1.20 -u=root -pk=prod-db'
alias ssh-dev='sshx -h=192.168.1.30 -u=root -pk=dev-server'

# Then use simply:
ssh-prod-web "sudo systemctl restart nginx"
ssh-prod-db "sudo systemctl restart mysql"
ssh-dev "sudo docker-compose up -d"
```

### Sudo Key Environment Variables

You can customize the sudo password key name via environment variable (but using `-pk` parameter is more flexible):

```bash
# Use environment variable (can only specify one at a time, needs constant modification)
export SSH_SUDO_KEY=my-sudo-password
sshx --password-set=my-sudo-password
sshx -h=192.168.1.100 "sudo ls -la /root"

# Recommended: Use -pk parameter, more flexible, no need to modify environment variables
sshx -h=192.168.1.100 -pk=server-A "sudo ls -la /root"
sshx -h=192.168.1.101 -pk=server-B "sudo ls -la /root"
```

### Security Notes

- ✅ Passwords are stored using OS-native encryption, or an explicit encrypted local vault
- ✅ Passwords are never stored in plaintext
- ✅ Password keys can be named per host, user, or environment
- ✅ Password input is hidden during entry
- ✅ Local vault never displays secret values to Agents
- ⚠️ OS keyring requires the platform credential manager
- ⚠️ On Linux desktops, Secret Service usually runs automatically; headless hosts should use `local-vault`

### Connection Environment Variables

You can use environment variables to avoid typing credentials repeatedly:

```bash
# Set in .env file or export in shell
export SSH_KEY_PATH=~/.ssh/prod.pem
export SSH_SUDO_KEY=prod-web
export SSH_TIMEOUT=30s
# Optional: isolate all sshx runtime state for an Agent/CI run
export SSHX_HOME="$PWD/.sshx-runtime"
export SSHX_SECRET_BACKEND=local-vault   # optional; headless hosts without a keyring
export SSHX_VAULT_PASSPHRASE='…'         # required with local-vault unless SSHX_VAULT_KEY_FILE is set

# Then run with fewer repeated options
sshx -h=prod-web "sudo uptime"
```

### Audit Environment Variables

```bash
# Write audit events to a project-specific directory
export SSHX_AUDIT_OUTPUT=./.sshx-audit

# Disable audit writing
export SSHX_NO_AUDIT=true
```

### SSH Authentication Preferences

- `sshx` prioritizes SSH keys and falls back to password authentication only when an SSH login password is already provided, for example through `SSH_PASSWORD`. Keyring passwords are used for sudo auto-fill, not silently loaded for ordinary SSH login.
- Use `--no-key` (alias `--password-only`) to disable key authentication for a single command. You can re-enable it by supplying `--key=<path>` again.
- Set `SSH_DISABLE_KEY=true` in your environment to permanently disable key authentication (useful on hosts that never accept keys). This override is respected even if a default key path exists in `~/.sshx/settings.json`.
- When key auth is enabled and no explicit path is provided, `sshx` still auto-loads `~/.ssh/id_rsa` (or the path specified in settings) before falling back to passwords.

#### Log Level Configuration

You can control the logging verbosity using the `SSHX_LOG_LEVEL` environment variable:

```bash
# Set log level to DEBUG (shows detailed debugging information)
export SSHX_LOG_LEVEL=debug

# Set log level to INFO (default)
export SSHX_LOG_LEVEL=info

# Set log level to WARNING
export SSHX_LOG_LEVEL=warning

# Set log level to ERROR
export SSHX_LOG_LEVEL=error
```

Debug level logs include:

- Detailed SSH/SFTP operation processes
- Authentication method selection and fallback details

### Example Workflow

```bash
# 1. Save sudo password (interactive input)
sshx --password-set=master
# Enter password for key 'master': ******

# 2. Verify it's saved
sshx --password-check=master
# ✓ Password exists for key: master

# 3. Use for SSH commands (sudo automatically uses stored password)
sshx -h=192.168.1.100 -u=root "sudo systemctl status docker"
sshx -h=192.168.1.100 -u=root "sudo df -h"

# 4. Use for SFTP operations
sshx -h=192.168.1.100 -u=root --upload=local.txt --to=/tmp/remote.txt
sshx -h=192.168.1.100 -u=root --download=/etc/hosts --to=./hosts.txt

# 5. List all saved password keys
sshx --password-list
# Common keys:
#   ✓ master (exists)
#     root (not set)

# 6. When done, optionally delete the password
sshx --password-delete=master
# ✓ Password deleted from system keyring
```

## Troubleshooting

### "sshx: command not found"

**Solution:**

- Ensure `/usr/local/bin` (or your installation directory) is in your PATH
- Restart your terminal after installation
- Or run with full path: `/usr/local/bin/sshx`

### macOS Security Warning

macOS may block the binary on first run:

```bash
sudo xattr -rd com.apple.quarantine /usr/local/bin/sshx
```

Or go to System Preferences → Security & Privacy → Click "Allow Anyway"

### Windows SmartScreen Warning

Click "More info" and then "Run anyway" if Windows Defender SmartScreen shows a warning.

### Permission Denied

```bash
# Make sure the binary has execute permissions
sudo chmod +x /usr/local/bin/sshx
```

## Development

The project's target state, hard non-goals, and capability coverage matrix live in the [Project Profile and Direction](docs/roadmap.md). The frozen v1 CLI/JSON/`error_kind` commitment is in [Contract Freeze Policy](docs/contract.md). Every new top-level capability must add a Happy Path E2E and update the matrix; high-risk, permission-sensitive, and state-changing capabilities must also meet the corresponding failure, permission-state, and recovery coverage floors.

```bash
# Run fast unit/component tests
make test-short

# Run compiled-binary SSH/SFTP E2E tests
make test-e2e

# Format code
gofmt -w .

# Build for all platforms
make build-all

# Run linter
make lint
```

> The lint target requires `golangci-lint` v2.6.1 or newer. Install it with `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.1`.

The normal E2E run uses an isolated, test-only keyring provider. CI additionally
checks the production binary against an ephemeral macOS Keychain.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the
development workflow, testing requirements (including the acceptance-matrix
rule for new features), and PR expectations, and [AGENT.md](AGENT.md) for the
project's mission and scope boundaries.

The project currently has a single primary maintainer. Issues labeled
`good first issue` are the intended on-ramp; if the maintainer is unavailable,
those labeled issues plus CONTRIBUTING.md and AGENT.md are the succession
record for continuing the contract without expanding scope.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**[Documentation](https://github.com/talkincode/sshx/wiki)** •
**[Issues](https://github.com/talkincode/sshx/issues)** •
**[Discussions](https://github.com/talkincode/sshx/discussions)** •
**[Releases](https://github.com/talkincode/sshx/releases)**

Made with ❤️ by [talkincode](https://github.com/talkincode)

</div>
