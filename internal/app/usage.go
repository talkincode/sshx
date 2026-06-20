package app

import "fmt"

// Version is the sshx build version, set by the main package at startup
// (injected via -ldflags). Defaults to "dev" for go test / go run builds.
var Version = "dev"

// PrintUsage prints the usage information for the sshx command.
func PrintUsage() {
	fmt.Printf("\nSSH & SFTP Remote Tool with Password Manager (Cross-Platform)\nVersion: %s\n", Version)
	fmt.Println(`
Usage:
  sshx -h=<host> [options] <command>              # SSH mode
  sshx -h=<host> [options] --upload=<file>        # SFTP upload
  sshx -h=<host> [options] --download=<file>      # SFTP download
  sshx --password-set=<key>[:<password>]          # Set password in keyring
  sshx --password-get=<key>                       # Get password from keyring
  sshx --password-delete=<key>                    # Delete password from keyring
  sshx --password-list                            # List common password keys
  sshx --host-add                                 # Add host configuration
  sshx --host-update                              # Update host configuration
  sshx --host-list                                # List configured hosts
  sshx --host-test=<name>                         # Test host connection
  sshx --host-test-all                            # Test all host connections
  sshx --host-remove=<name>                       # Remove host configuration

SSH Options:
  -h, --host=HOST          Remote host address (required)
  -p, --port=PORT          SSH port (default: 22)
  -u, --user=USER          SSH username (default: master)
  -i, --key=PATH           SSH private key path (default: ~/.ssh/id_rsa)
  -pk, --password-key=KEY  Sudo password keyring key name (default: master)
                           Used only when the remote command starts with sudo
  --dry-run                Print the local execution plan without side effects
  --audit-output=DIR       Write audit JSONL files to DIR (default: ~/.sshx/audit)
  --no-audit               Disable local audit event writing for this invocation
  --timeout=DURATION       Command execution timeout (e.g. 30s, 2m, or 30 = seconds)
  --json                   Emit a single structured JSON result on stdout
  --pty                    Request a PTY (merges stderr into stdout; off by default)
  --version                Show version information (alias: -v)
  --help                   Show this help message

Agent / Scripting Mode:
  By default command output streams live with stdout and stderr kept on
  separate channels (no PTY), and the remote command's exit status is
  propagated as sshx's own exit code.

  --json emits one JSON object on stdout:
    {host, port, user, command, exit_code, success, stdout, stderr,
     stdout_truncated, stderr_truncated, duration_ms, auth_method,
     error_kind, error}

  Exit codes:
    0          command succeeded
    1..254     remote command's exit status (propagated verbatim)
    255        sshx-level failure (connect/auth/host-key/timeout/blocked/...)
    In --json mode an sshx-level failure has exit_code -1 and a non-empty
    error_kind (timeout, auth, host_key, connect, blocked, exit_missing,
    config, error), so it is always distinguishable from a remote exit 255.

Sudo Auto-fill:
  sshx auto-fills a sudo password only when the remote command starts with
  sudo, for example:
    sshx -h=host "sudo systemctl status nginx"

  Non-leading sudo is not auto-filled and does not trigger keyring lookup:
    sshx -h=host "sh -c 'sudo whoami'"
    sshx -h=host "echo sudo"

  This keeps keyring lookup, stdin password injection, and future audit fields
  on one clear rule. Put sudo at the beginning of the remote command when you
  want sshx to auto-fill it.

Dry-run Plan Preview:
  Add --dry-run to see how sshx would interpret an invocation before any
  connection, command execution, keyring secret lookup, known_hosts mutation, or
  settings write. Use --json with --dry-run for an agent-readable plan.

  Examples:
    sshx -h=prod-web --dry-run "sudo systemctl restart nginx"
    sshx -h=prod-web --dry-run --json --upload=local.txt --to=/tmp/local.txt

  Dry-run is a local plan preview only. It does not prove the remote command
  would succeed.

Audit Trail:
  sshx writes one structured JSONL audit event per non-dry-run invocation to
  ~/.sshx/audit/sshx-YYYY-MM-DD.jsonl by default. Use --audit-output=<dir> to
  save audit events next to a project or incident record.

  Audit events record metadata and outcomes such as mode/action, host
  resolution, sudo/keyring decisions, safety status, auth method, exit code, and
  error kind. They do not record plaintext passwords, private key contents, or
  stdout/stderr. Command text is best-effort redacted for password/token-style
  arguments.

Safety Options:
  -f, --force           Force execution, bypass safety checks (use with caution!)
  --no-safety-check     Disable safety checks completely (not recommended)

  Safety checks protect against:
    - Destructive operations (rm -rf /, mkfs, dd)
    - System shutdown/reboot commands
    - Critical file modifications (/etc/passwd, /etc/shadow)
    - Dangerous pipe operations (curl | sh)
    - Fork bombs and other malicious patterns

SFTP Options:
  --upload=<local>      Upload file (use with --to=<remote>)
  --download=<remote>   Download file (use with --to=<local>)
  --to=<path>           Target path for upload/download
  --list=<path>         List directory contents (alias: --ls)
  --mkdir=<path>        Create remote directory
  --rm=<path>           Remove remote file or directory

Password Management (Cross-Platform):
  --password-set=<key>[:<password>]   Set password in system keyring
                                      If password omitted, will prompt
  --password-get=<key>                Output the password (raw value only when piped; on a terminal just confirms it exists)
  --password-check=<key>              Check if password exists (alias: --password-exists)
  --password-delete=<key>             Delete password from keyring (alias: --password-del)
  --password-list                     List common password keys (alias: --password-ls)

  Platform Support:
    macOS:   Uses Keychain
    Linux:   Uses Secret Service (gnome-keyring/kwallet)
    Windows: Uses Credential Manager

Host Management:
  --host-add                          Add new host (interactive or with options)
  --host-update                       Update existing host configuration
  --host-list                         List all configured hosts (alias: --host-ls)
  --host-test=<name>                  Test connection to configured host
  --host-test-all                     Test connections for all configured hosts
  --host-remove=<name>                Remove host from configuration (alias: --host-rm)

  Host Add/Update Options:
    --host-name=<name>                Host name (unique identifier, required for update)
    --host-desc=<description>         Host description
    -h=<address>                      Host address (IP or hostname)
    -p=<port>                         SSH port
    -u=<user>                         SSH username
    -i=<key>, --key=<key>            SSH private key path for this host (optional)
    -pk=<key>                         Password key name
    --host-type=<type>                System type (linux/windows/macos)

  Configuration file: ~/.sshx/settings.json

Environment Variables (.env):
  SSH_PASSWORD          SSH password (not recommended, use SSH keys or keyring)
  SSH_KEY_PATH          SSH private key path
  SSH_SUDO_KEY          Sudo password keyring key name (default: master)
  SSH_NO_SAFETY_CHECK   Disable safety checks (true/false)
  SSH_FORCE             Force execution mode (true/false)
  SSH_TIMEOUT           Command execution timeout (e.g. 30s, 2m, or 30 = seconds)
  SSHX_AUDIT_OUTPUT     Audit output directory (default: ~/.sshx/audit)
  SSHX_NO_AUDIT         Disable audit writing (true/false)

SSH Examples:
  # Execute simple command (default user: master)
  sshx -h=192.168.1.100 "uptime"

  # Execute sudo command (auto password from keyring: master)
  sshx -h=192.168.1.100 "sudo systemctl status docker"

  # Use custom sudo password key for specific server
  sshx -h=192.168.1.100 -pk=server-A "sudo systemctl restart nginx"
  sshx -h=192.168.1.101 -pk=server-B "sudo systemctl restart nginx"

  # Custom SSH port
  sshx -h=192.168.1.100 -p=2222 "ps aux | grep nginx"

  # Structured JSON output for scripts/agents (one object on stdout)
  sshx -h=192.168.1.100 --json "systemctl is-active nginx"

  # Preview the execution plan without connecting or reading secrets
  sshx -h=prod-web --dry-run --json "sudo systemctl restart nginx"

  # Save audit events for this project
  sshx -h=prod-web --audit-output=./.sshx-audit "systemctl reload nginx"

  # Bound a command with a timeout (kills it after 30s)
  sshx -h=192.168.1.100 --timeout=30s "apt-get update"

  # Dangerous command will be blocked
  sshx -h=192.168.1.100 "sudo rm -rf /tmp/*"  # Safe
  sshx -h=192.168.1.100 "sudo rm -rf /"       # ⚠️ BLOCKED!

  # Force execute (bypass safety check - use with caution!)
  sshx -h=192.168.1.100 --force "sudo reboot"
  sshx -h=192.168.1.100 -f "sudo systemctl reboot"

SFTP Examples:
  # Upload file
  sshx -h=192.168.1.100 --upload=local.txt --to=/tmp/remote.txt

  # Download file
  sshx -h=192.168.1.100 --download=/var/log/app.log --to=./app.log

  # List directory
  sshx -h=192.168.1.100 --list=/var/log

  # Create directory
  sshx -h=192.168.1.100 --mkdir=/tmp/newdir

  # Remove file
  sshx -h=192.168.1.100 --rm=/tmp/oldfile.txt

  # Batch upload
  for file in *.txt; do
    sshx -h=192.168.1.100 --upload=$file --to=/backup/$file
  done

Password Management Examples:
  # Set default sudo password (interactive prompt)
  sshx --password-set=master

  # Set sudo password (inline, not recommended for security)
  sshx --password-set=master:mypassword

  # Set passwords for different servers with same username
  sshx --password-set=server-A
  sshx --password-set=server-B
  sshx --password-set=server-C

  # Use different password keys for different servers
  sshx -h=192.168.1.100 -pk=server-A "sudo systemctl status nginx"
  sshx -h=192.168.1.101 -pk=server-B "sudo systemctl status nginx"
  sshx -h=192.168.1.102 -pk=server-C "sudo systemctl status nginx"

  # Set password for specific user
  sshx --password-set=root
  sshx --password-set=admin

  # Get password from keyring
  sshx --password-get=master

  # Check if password exists
  sshx --password-check=server-A

  # List common password keys
  sshx --password-list

  # Delete password from keyring
  sshx --password-delete=server-A

Host Management Examples:
  # Add host interactively
  sshx --host-add

  # Add host with command line options
  sshx --host-add --host-name=prod-web -h=192.168.1.100 -u=root -pk=prod-web --host-desc="Production Web Server"

  # Add host with its own SSH private key
  sshx --host-add --host-name=prod-db -h=192.168.1.200 -u=admin -i=~/.ssh/prod-db.pem

  # Update host IP address
  sshx --host-update --host-name=prod-web -h=192.168.1.101

  # Update host SSH key
  sshx --host-update --host-name=prod-web -i=~/.ssh/new-key.pem

  # Update host password key
  sshx --host-update --host-name=prod-web -pk=new-password-key

  # Update multiple fields
  sshx --host-update --host-name=prod-web -h=192.168.1.101 -u=admin -pk=new-key

  # List all configured hosts
  sshx --host-list

  # Test connection to a configured host
  sshx --host-test=prod-web

  # Test all configured hosts and get a report with auth methods
  sshx --host-test-all

  # Remove a host from configuration
  sshx --host-remove=prod-web

  # Use configured host (looks up from settings if not an IP)
  sshx -h=prod-web "uptime"

Note:
  - SSH key authentication is tried first; password auth is used only when SSH_PASSWORD is provided
  - Sudo password is auto-filled only when the remote command starts with sudo
  - Dry-run never connects, executes, reads keyring secrets, or writes state
  - Audit events are JSONL files under ~/.sshx/audit by default
  - SFTP operations use the same SSH connection
  - Password manager works across macOS/Linux/Windows
  - Default user: master, Default sudo key: master
  - Host configurations are stored in ~/.sshx/settings.json`)
}
