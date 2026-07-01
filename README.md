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


Secure SSH & SFTP Client with Built-in Password Manager
```

<div align="center">

[![Go Version](https://img.shields.io/github/go-mod/go-version/talkincode/sshx?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![Release](https://img.shields.io/github/v/release/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://github.com/talkincode/sshx/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/talkincode/sshx?style=flat-square)](https://goreportcard.com/report/github.com/talkincode/sshx)
[![Coverage](https://img.shields.io/badge/coverage-20.0%25-yellow?style=flat-square&logo=go)](https://github.com/talkincode/sshx)

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

`sshx` is a barrier-free, cross-platform SSH/SFTP command-line client with a built-in system keyring password manager, making it easy to manage and operate multiple remote servers.

## Why You Need It?

Managing multiple servers means juggling different passwords and repeatedly entering sudo passwords. `sshx` securely stores passwords in your system keyring and auto-fills sudo passwords, so you can run commands across many servers without the password hassle. One command, multiple servers, zero password hassle.

**New!** Host Configuration Management - Store your frequently used host configurations in `~/.sshx/settings.json` and connect with just a name instead of typing full connection details every time. Each host can have its own SSH private key. Add hosts interactively!

## Project Structure

- `cmd/sshx`: Main binary entry point, responsible for command-line argument parsing and password management features.
- `internal/sshclient`: Core SSH/SFTP/script execution logic and command security validation.
- `internal/app`: CLI command routing, host configuration management, and password management.

## Key Features

1. Cross-platform SSH/SFTP operations (supports sudo auto-fill).
2. Password management (Keychain / Secret Service / Credential Manager).
3. Host configuration management with per-host SSH keys.
4. Dry-run execution plan preview for humans and agents.
5. Local structured audit trail with safe default redaction.
6. Script execution and command security validation.

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
```

**Note:** Make sure `$GOPATH/bin` (typically `~/go/bin`) is in your PATH.

### Homebrew (macOS / Linux)

```bash
brew install talkincode/tap/sshx
```

This pulls prebuilt binaries from the [talkincode/homebrew-tap](https://github.com/talkincode/homebrew-tap) repository, updated automatically on every tagged release.

### One-Line Installation Script

#### Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/talkincode/sshx/main/install.sh | bash
```

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

### `--timeout` and `--pty`

```bash
# Kill the command if it runs longer than 30 seconds (also accepts 2m, etc.)
sshx -h=prod-web --timeout=30s "apt-get update"

# Opt back into a PTY for commands that insist on a terminal
# (note: a PTY merges stderr into stdout; it cannot be combined with --json)
sshx -h=prod-web --pty "top -b -n1"
```

The timeout can also be set via the `SSH_TIMEOUT` environment variable.

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

`sshx` provides secure password storage using the operating system's native credential manager, eliminating the need to enter passwords repeatedly or store them in plaintext.

### Supported Platforms

- **macOS**: Uses Keychain Access
- **Linux**: Uses Secret Service (GNOME Keyring / KDE Wallet)
- **Windows**: Uses Credential Manager

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

- ✅ Passwords are stored using OS-native encryption
- ✅ Passwords are never stored in plaintext
- ✅ Password keys can be named per host, user, or environment
- ✅ Password input is hidden during entry
- ⚠️ Requires OS credential manager to be available
- ⚠️ On Linux, requires Secret Service daemon running (usually automatic with desktop environments)

### Connection Environment Variables

You can use environment variables to avoid typing credentials repeatedly:

```bash
# Set in .env file or export in shell
export SSH_KEY_PATH=~/.ssh/prod.pem
export SSH_SUDO_KEY=prod-web
export SSH_TIMEOUT=30s

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

```bash
# Run tests
go test ./...

# Format code
gofmt -w .

# Build for all platforms
make build-all

# Run linter
make lint
```

> The lint target requires `golangci-lint` v2.6.1 or newer. Install it with `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.1`.

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
