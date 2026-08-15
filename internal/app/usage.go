package app

import "fmt"

// Version is the sshx build version, set by the main package at startup
// (injected via -ldflags). Defaults to "dev" for go test / go run builds.
var Version = "dev"

// PrintUsage prints the usage information for the sshx command.
func PrintUsage() {
	fmt.Printf("\nSSHX — Agent-native remote host execution over SSH\nVersion: %s\n", Version)
	fmt.Println(`
Usage:
  sshx -h=<host> [options] <command>              # SSH mode (compatibility)
  sshx run [selectors] [options] -- <command>     # Canonical execution contract
  sshx run --script-file=PATH ...                 # Byte-preserving script payload
  sshx -h=<host> [options] --upload=<file>        # SFTP upload
  sshx -h=<host> [options] --download=<file>      # SFTP download
  sshx --transfer=<host>:<path> --to=<host>:<path> # Server-to-server transfer
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
  sshx skill install [options]                    # Install/update the bundled Agent skill
  sshx plugin create <id> [options]               # Scaffold a local inspection plugin
  sshx plugin list [--json]                       # List built-in and local capabilities
  sshx inspect -h=<host> <capability> [options]   # Run one structured host inspection
  sshx sql -h=<host> --db=<name> [options] "SQL"  # Guarded SQL via remote psql/sqlite3

SSH Options:
  -h, --host=HOST          Remote host address (required in compatibility mode)
  -p, --port=PORT          SSH port (default: 22)
  -u, --user=USER          SSH username (default: master)
  -i, --key=PATH           SSH private key path (default: ~/.ssh/id_rsa)
  -pk, --password-key=KEY  Sudo password keyring key name (default: master)
                           Used only when the remote command starts with sudo
  --ssh-password-key=KEY   SSH login password keyring key (never used for sudo)
  --dry-run                Print the local execution plan without side effects
  --audit-output=DIR       Write audit JSONL files to DIR (default: ~/.sshx/audit)
  --no-audit               Disable local audit event writing for this invocation
  --timeout=DURATION       Command execution timeout (e.g. 30s, 2m, or 30 = seconds)
  --json                   Emit a single structured JSON result on stdout
  --pty                    Request a PTY (merges stderr into stdout; off by default)
  --version                Show version information (alias: -v)
  --help                   Show this help message

Run Contract (preferred for Agents):
  sshx run --target=prod-web --json -- "systemctl is-active nginx"
  sshx run --group=prod-web --tag=env=prod --concurrency=4 --jsonl -- "uptime"
  sshx run --target=prod-web --script-file=./check.sh --json
  cat ./check.sh | sshx run --target=prod-web --script-stdin --json

  Selectors (configured hosts only; multi-host never treats names as DNS):
    --target=NAME            strict alias (repeatable via --targets=a,b)
    --group=NAME             union with other names/groups (repeatable)
    --tag=key=value          AND filter (repeatable)
    --all-hosts              all configured hosts before tag filters
    --address=HOST           explicit single literal address (not for fan-out)

  Limits / policy:
    --concurrency=N          default 4, hard max 32
    --failure-mode=continue|fail_fast   default continue
    --intent=read|change|unknown
    --force / --no-safety-check require --bypass-reason=TEXT
    --jsonl                  stream run_started/target_*/run_finished events

  Multi-target exit codes:
    0    all selected targets succeeded
    1    run accepted but at least one target failed/skipped/uncertain
    255  request-level failure (bad selectors, zero matches, invalid input)

Agent / Scripting Mode:
  By default command output streams live with stdout and stderr kept on
  separate channels (no PTY), and the remote command's exit status is
  propagated as sshx's own exit code.

  Compatibility --json emits one JSON object on stdout:
    {host, port, user, command, exit_code, success, stdout, stderr,
     stdout_truncated, stderr_truncated, duration_ms, auth_method,
     error_kind, error}
  sshx run --json adds versioned fields (schema_version, run_id, status,
  phase, completion, structured error).

  Exit codes (single-host compatibility mode):
    0          command succeeded
    1..254     remote command's exit status (propagated verbatim)
    255        sshx-level failure (connect/auth/host-key/timeout/blocked/...)
    In --json mode an sshx-level failure has exit_code -1 and a non-empty
    error_kind (timeout, auth, host_key, connect, blocked, exit_missing,
    config, error), so it is always distinguishable from a remote exit 255.

  Trust note: high-risk bypasses (force, no-safety-check, accept-unknown-host,
  insecure-hostkey) require explicit CLI flags. Inherited env values and
  working-directory .env files are ignored for those decisions.

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
    - Direct database client execution (psql/pgcli, incl. docker exec,
      sudo -u, sh -c, kubectl exec wrappers) — use 'sshx sql' instead

SFTP Options:
  --upload=<local>      Upload file (use with --to=<remote>)
  --download=<remote>   Download file (use with --to=<local>)
  --to=<path>           Target path for upload/download
  --list=<path>         List directory contents (alias: --ls)
  --mkdir=<path>        Create remote directory
  --rm=<path>           Remove remote file or directory

Server-to-Server Transfer:
  --transfer=<src-host>:<src-path> --to=<dst-host>:<dst-path>

  Streams files directly from one server to another through the local
  machine (nothing is written to local disk). Supports single files and
  recursive directory transfers, and preserves file permission bits.
  Both hosts can be configured host names (from ~/.sshx/settings.json)
  or IP addresses, each using its own SSH key/user/port from settings.

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
  --host-import                       Selectively import hosts from ~/.ssh/config (interactive)
  --host-import=<name1,name2>         Import only the named ssh_config hosts (non-interactive)
  --ssh-config=<path>                 ssh_config file to import from (default: ~/.ssh/config)
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

Inspection Capabilities:
  sshx inspect -h=<host> <capability> [options]

  Built in:
    system.identity, system.resources, system.baseline
    network.interfaces, network.routes, network.dns
    network.listeners, network.firewall

  --cache=off|remote-prefer  Reuse/write a remote observation (default: off)
  --refresh                  Ignore a reusable observation and run the collector
  --max-age=DURATION         Require observations no older than this duration
  --allow-stale              Explicitly allow an expired observation
  --sudo                     Use sudo for an optional-privilege plugin

  Collectors execute once through SSH stdin and are never installed on the
  target. With remote-prefer caching, only redacted JSON is stored below the
  remote user's ~/.sshx/observations/v1 directory.

Guarded SQL Execution:
  sshx sql -h=<host> --db=<name> [options] "<single SQL statement>"
  sshx sql -h=<host> --engine=sqlite --db-file=/abs/path.db [options] "SQL"
  sshx sql -h=<host> --db=<name> [options] -- <SQL words...>

  Statements run through the database client already present on the remote
  host (psql or sqlite3). sshx embeds no database driver and opens no tunnel.
  Exactly one statement per invocation. Unknown or dangerous statement heads
  (DROP DATABASE/SCHEMA, ALTER SYSTEM, COPY, DO, ATTACH, sqlite3 dot-commands,
  transaction control, multi-statement input), psql meta-commands,
  EXPLAIN ANALYZE, data-modifying CTE bodies, SELECT INTO, CALL, dblink,
  load_extension, writable PRAGMA, and other unanalyzable forms are blocked
  fail-closed. PostgreSQL reads run in a read-only transaction; SQLite reads
  open the file URI with mode=ro. Direct psql/pgcli/sqlite3 invocations in
  run/command mode are blocked — use sshx sql. Every invocation is audited
  with a literal-redacted statement, its exact SHA-256 digest, classification,
  backup, and outcome.

  --engine=postgres|sqlite  SQL engine (default: postgres)
  --db=NAME                 PostgreSQL database name, or SQLite path if --db-file is omitted
  --db-file=PATH            Absolute SQLite database file path (required for --engine=sqlite)
  --db-user=USER            Database role (default: remote psql default; sqlite unused)
  --db-host=HOST            Database host as seen from the remote (default: local socket)
  --db-port=PORT            Database port
  --db-password-key=KEY     Keyring key for the DB password; delivered via stdin,
                            never via argv (implies --db-host=127.0.0.1 when unset)
  --docker=CONTAINER        Run psql inside this container via docker exec -i
                            (default connection becomes the container-local socket;
                            backups still land on the host)
  --db-cred-from=SOURCE     Resolve DB credentials on the remote host instead of the
                            local keyring: docker:<container> (container env) or
                            env-file:<path> (KEY=VALUE file). Recognizes PG*,
                            POSTGRES_*, DB_* keys and DATABASE_URL. Mutually
                            exclusive with --db-password-key; --db becomes optional
                            when the source provides the database name.
  --cred-cache=off|DURATION Temporary local cache for remotely resolved credentials
                            (default: 15m). The secret lives only in the OS keyring;
                            ~/.sshx/sql-cred-cache.json records identity + expiry.
                            Expired entries are deleted from the keyring.
  --cred-refresh            Drop the cached entry and re-resolve from the source
  --explain                 Run EXPLAIN only; never executes the statement
  --row-threshold=N         EXPLAIN row estimate that upgrades a row backup to a
                            full-table CSV snapshot (default: 1000)
  --allow-full-table        Required for UPDATE/DELETE without a WHERE clause
  --no-backup               Skip pre-change backup (requires --force)
  --backup-dir=PATH         Remote backup directory (default: ~/.sshx/sql-backups)
  --force, -f               Confirms DDL; destructive DDL also requires --no-backup

  Safety pipeline for data changes: classify locally (fail-closed), gate by
  policy, then snapshot and execute. PostgreSQL runs EXPLAIN (FORMAT JSON)
  and snapshots rows or the table under one transaction plus a SHARE ROW
  EXCLUSIVE lock. SQLite skips row estimates and snapshots the table (CSV)
  or the whole file (sqlite3 .backup) under BEGIN IMMEDIATE. This closes the
  backup-to-mutation race. SELECT and other reads skip EXPLAIN and backups.
  Catalog preflight blocks automatic execution when triggers, rewrite rules,
  partitions, or cascading referential actions can affect related tables;
  proceed only after an independent backup with --force --no-backup. Automatic
  backups are not claimed for destructive DDL, which also requires
  --force --no-backup. Backup directories/files are owner-only. --dry-run
  previews the local plan without connecting; runtime catalog checks may block.

  sshx sql -h=db1 --db=app "SELECT count(*) FROM users"
  sshx sql -h=db1 --db=app --db-user=app --db-password-key=app-db \
      "UPDATE users SET active=false WHERE id=42"
  sshx sql -h=db1 --db=app --explain "DELETE FROM sessions WHERE expires_at < now()"
  sshx sql -h=db1 --db=app --force "TRUNCATE staging_events"
  # Dockerized production DB: credentials live in the container env, psql runs
  # inside the container, resolved credentials are cached in the keyring for 15m
  sshx sql -h=prod --docker=pg-prod --db-cred-from=docker:pg-prod \
      "UPDATE users SET active=false WHERE id=42"
  sshx sql -h=prod --docker=pg-prod --db-cred-from=env-file:/opt/app/.env \
      --cred-cache=1h "SELECT count(*) FROM orders"
  sshx sql -h=app --engine=sqlite --db-file=/var/lib/app/app.db --json \
      "UPDATE users SET active=0 WHERE id=42"

Plugin Management:
  sshx plugin create <id> [--runner=sh] [--platform=linux|darwin]
                          [--privilege=never|optional|required]
                          [--template=generic|docker|nginx] [--replace] [--json]
  sshx plugin list [--json]
  sshx plugin show <id> [--json]
  sshx plugin validate <id> [--json]
  sshx plugin test <id> [--fixture=<name>] [--json]
  sshx plugin trust <id> [--json]
  sshx plugin remove <id> [--json]

  Local plugins belong to sshx, not to an Agent skill. They are stored under
  ~/.sshx/plugins/<id> and remain untrusted until their current digest is
  explicitly trusted. Editing a trusted manifest, schema, or collector changes
  the digest and blocks remote execution until it is trusted again.

Agent Skill Installation:
  sshx skill install [--dir=<path>] [--force] [--json]

  The canonical sshx Agent skill is embedded in the binary, so installation
  does not need a network download or a release archive next to the executable.
  The default target is ~/.agents/skills/sshx/SKILL.md. Pass --dir to select
  another sshx skill directory.

  A matching installed skill is left unchanged (or repaired to mode 0644).
  A prior sshx-managed version is updated using its digest sidecar. Differing
  unmanaged content is preserved unless --force is explicit. Symlinked targets
  are rejected. JSON status is installed, current, repaired, or updated;
  failures use conflict, unsafe_target, or install_error.

Environment Variables (.env):
  SSH_PASSWORD          SSH password (not recommended, use SSH keys or keyring)
  SSH_KEY_PATH          SSH private key path
  SSH_SUDO_KEY          Sudo password keyring key name (default: master)
  SSH_NO_SAFETY_CHECK   Disable safety checks (true/false)
  SSH_FORCE             Force execution mode (true/false)
  SSH_TIMEOUT           Command execution timeout (e.g. 30s, 2m, or 30 = seconds)
  SSHX_AUDIT_OUTPUT     Audit output directory (default: ~/.sshx/audit)
  SSHX_NO_AUDIT         Disable audit writing (true/false)
  SSHX_HOME             Override the local sshx runtime root (default: ~/.sshx)

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

Inspection Examples:
  # Inspect stable system/network state in one invocation
  sshx inspect -h=prod-web system.baseline --json

  # Create a locally editable Docker capability, validate it, then trust it
  sshx plugin create docker.environment --template=docker --privilege=optional --json
  sshx plugin validate docker.environment --json
  sshx plugin test docker.environment --fixture=complete --json
  sshx plugin trust docker.environment --json

  # Inspect once and persist only the redacted observation on the target
  sshx inspect -h=prod-web docker.environment --cache=remote-prefer --json

Agent Skill Example:
  # Install after Homebrew/go install, or refresh after upgrading sshx
  sshx skill install

  # Replace a locally modified copy after reviewing the difference
  sshx skill install --force --json

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

Server-to-Server Transfer Examples:
  # Transfer a file directly between two servers (by IP)
  sshx --transfer=192.168.1.100:/var/log/app.log --to=192.168.1.101:/backup/app.log

  # Transfer between configured hosts (from settings.json)
  sshx --transfer=prod-web:/etc/nginx/nginx.conf --to=staging-web:/etc/nginx/nginx.conf

  # Transfer a whole directory recursively
  sshx --transfer=prod-db:/var/backups --to=backup-server:/mnt/archive/db

  # If the destination is an existing directory, the source is placed inside it
  sshx --transfer=prod-web:/var/log/app.log --to=log-server:/var/logs/

  # Preview the transfer plan without connecting
  sshx --transfer=prod-web:/data --to=prod-db:/data --dry-run

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
