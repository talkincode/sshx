---
name: sshx
description: Operate remote servers with the `sshx` CLI — inspect hosts with built-in or locally created plugins, run commands over SSH, transfer files over SFTP, apply a single remote file with hash/backup/atomic replace, manage named hosts, store SSH/sudo passwords in the OS keyring, and run guarded PostgreSQL or SQLite statements through the remote psql/sqlite3 client (with classification, backups, and strict auditing). Use when the user wants structured host discovery, custom application inspection, remote command execution, safe config file changes, upload/download, service operations, host management, keyring-backed secrets, or safe production database queries and changes. Prefer `--json` for programmatic/agent use.
---

# sshx

`sshx` is a single-binary, cross-platform SSH/SFTP client with a built-in OS-keyring
password manager and named-host config. Every invocation opens one connection, does
its work, and exits — there is no daemon, tunneling, or port forwarding.
`sshx login` is a human-only TTY session; agents must not use it.

> One command, multiple servers, zero password hassle.

## When to use

- Run a one-shot command on a remote host (optionally with `sudo`).
- Execute complex scripts byte-for-byte with `sshx run --script-file` / `--script-stdin`.
- Fan out one action to a bounded host set with `--group` / `--tag` / `--targets`.
- Upload/download a file or list/make/remove remote paths over SFTP.
- Replace one remote regular file with `sshx apply` (hash precondition, backup, atomic write).
- Manage frequently used hosts by short name (`~/.sshx/settings.json`).
- Store/fetch SSH or sudo passwords in the OS keyring (never plaintext).
- Run one guarded SQL statement against a remote PostgreSQL (plain or Dockerized)
  or a remote SQLite file, with classification, backups, and a full audit trail.
- Inspect system/network state in one call and create custom application plugins in the sshx runtime directory.

## Inspect before repeating discovery commands

When the goal is to understand an unfamiliar host, list reusable capabilities
before issuing many independent commands:

```bash
sshx plugin list --json
sshx inspect -h=prod-web system.baseline --json
```

Application-specific scripts are sshx runtime assets under
`~/.sshx/plugins/<id>` (or `$SSHX_HOME/plugins/<id>`). **Do not embed or maintain
collector scripts in this skill.** If no suitable plugin exists, ask sshx to
create the complete scaffold, then edit the generated collector in that path:

```bash
sshx plugin create private.environment \
  --template=generic \
  --platform=linux \
  --privilege=optional \
  --json
sshx plugin validate private.environment --json
sshx plugin test private.environment --fixture=complete --json
sshx plugin test private.environment --json
sshx plugin trust private.environment --json
```

Remote execution is refused until the current plugin digest is trusted. Editing
the collector invalidates trust. Review it, validate/test it, then trust the new
digest explicitly.

```bash
sshx inspect -h=prod-web private.environment --dry-run --json
sshx inspect -h=prod-web private.environment --json
sshx inspect -h=prod-web private.environment --cache=remote-prefer --max-age=10m --json
```

Remote caching is opt-in and stores only a redacted JSON observation below the
remote user's `~/.sshx/observations/v1`; plugin code stays local and executes
only through the SSH session's stdin. Branch on observation `status`
(`complete|partial|unsupported|failed`) and cache `hit/stale` fields. Never
interpret `partial` or permission errors as application absence.

## Do not use `sshx login` from an agent

`sshx login` attaches a human TTY to a remote shell (optional `--sudo` privileged
login). It has no Agent JSON contract, is rejected without a TTY, and is not an
MCP tool. For programmatic work keep using `sshx run` / `sshx inspect` /
`sshx apply` / `sshx sql` with `--json`.

## Golden rule for agents: prefer `sshx run` + `--json`/`--jsonl`

For any non-interactive/programmatic use, prefer the canonical run contract:

```bash
sshx run --target=prod-web --json -- "systemctl is-active nginx"
sshx run --group=prod-web --tag=env=prod --concurrency=4 --jsonl -- "uptime"
sshx run --target=prod-web --script-file=./check.sh --json
```

Compatibility mode `sshx -h=prod-web --json "cmd"` still works and emits the
legacy single-object shape. `sshx run --json` adds versioned fields
(`schema_version`, `run_id`, `status`, `phase`, `completion`, structured
`error`). Multi-target runs stream JSONL events:
`run_started` → `target_started`/`target_finished` → `run_finished`.

Branch on `success` / `status` first; on failure read `error.kind` or
`error_kind` (do not parse free-form text). For change actions, inspect
`completion` before any retry (`not_started|partial|completed|completed_unconfirmed|unknown`).

Selectors resolve only configured host aliases. Literal addresses require
`--address=` and cannot enter group/tag fan-out. Zero matches is exit `255`
with no network access.

Safety/force/host-key relaxations require explicit CLI flags plus
`--bypass-reason=` on `sshx run`. Inherited `SSH_FORCE` /
`SSH_NO_SAFETY_CHECK` / `SSH_INSECURE_HOST_KEY` / `SSH_ACCEPT_UNKNOWN_HOST`
and working-directory `.env` files do not authorize bypasses.

SSH login secrets use `--ssh-password-key` / `ssh_password_key`. Sudo secrets
use `-pk` / `sudo_password_key` (legacy `password_key` is sudo-only).

## Preview before executing: use `--dry-run --json`

When you need to verify what sshx would do before touching a server, pass
`--dry-run --json`. It prints a local execution plan and does not connect,
execute, read keyring secrets, mutate `known_hosts`, or write settings.

```bash
sshx -h=prod-web --dry-run --json "sudo systemctl restart nginx"
```

Dry-run reports host resolution, mode/action, sudo key selection, safety-check
status, and whether a real run would connect, execute, read a secret, or mutate
state. It does not simulate remote command success.

## Audit trail

Every non-dry-run invocation writes one JSONL audit event by default:
`~/.sshx/audit/sshx-YYYY-MM-DD.jsonl`.

Use `--audit-output=<dir>` when the audit record should live with a project or
incident folder:

```bash
sshx -h=prod-web --audit-output=./.sshx-audit --json "systemctl reload nginx"
```

Audit events record metadata and outcomes such as mode/action, host resolution,
sudo/keyring decisions, safety status, auth method, exit code, and error kind.
They do not record plaintext passwords, private key contents, or stdout/stderr.
Command text is included but best-effort redacted for password/token-style
arguments. Use `--no-audit` only when the user explicitly wants no local audit
event for that invocation.

## Exit codes (and how to read failures)

| Exit code | Meaning                                                       |
|-----------|---------------------------------------------------------------|
| `0`       | command succeeded                                             |
| `1..254`  | the remote command's own exit status (propagated verbatim)   |
| `255`     | sshx-level failure (connect/auth/host-key/timeout/blocked/…)  |

In `--json` mode an sshx-level failure has `exit_code: -1` and a non-empty
`error_kind`, so it is always distinguishable from a remote `exit 255`.

`error_kind` values: `timeout`, `auth`, `host_key`, `connect`, `blocked`,
`exit_missing`, `config`, `error`. SQL mode adds `explain_failed`,
`impact_check_failed`, `remote_exit`, and
`cred_source_failed`. Apply mode adds `precondition` when `--expect-sha256`
does not match the current remote file.

## Command execution

```bash
# Default user is "master"; key auth is tried first.
# Password auth fallback only happens when SSH_PASSWORD is already provided.
sshx -h=192.168.1.100 "uptime"

# Address a host by its configured name (resolved from settings.json).
sshx -h=prod-web "df -h"

# Custom user / port / private key.
sshx -h=10.0.0.5 -u=root -p=2222 -i=~/.ssh/prod.pem "ps aux | grep nginx"

# Bound the runtime; kills the command after the timeout (accepts 30s, 2m, or 30).
sshx -h=prod-web --timeout=30s "apt-get update"

# Stream output live (human use). Add --pty only when a TTY is required
# (e.g. interactive prompts); --pty merges stderr into stdout.
sshx -h=prod-web --pty "top -b -n1"
```

### sudo with auto-filled password

If the remote command starts with `sudo`, sshx pulls the password from the OS
keyring and feeds it over stdin (never interpolated into the command string).
Non-leading `sudo` inside shell wrappers or pipelines is not auto-filled. The
keyring key is **not always `master`** — it is resolved per invocation in this
order:

1. `-pk=<key>` / `--password-key=<key>` on the command line (highest priority).
2. The `SSH_SUDO_KEY` environment variable.
3. The named host's own `password_key` from `~/.sshx/settings.json`, applied
   automatically when you address the host by name and no `-pk=`/`SSH_SUDO_KEY` is set.
4. `master`, only as the final fallback when nothing above is configured.

So **do not assume every host uses `master`.** Each server can (and usually should)
have its own keyring entry. For a named host the right key is chosen automatically;
for an ad-hoc IP, pass `-pk=<key>` matching the entry that holds that host's secret.

```bash
# Named host: sshx auto-uses prod-web's configured password_key — no -pk needed.
sshx -h=prod-web "sudo systemctl status docker"

# Ad-hoc IP: name the keyring key explicitly (don't rely on "master").
sshx -h=192.168.1.100 -pk=server-A "sudo systemctl restart nginx"
sshx -h=192.168.1.101 -pk=server-B "sudo systemctl restart nginx"

# Falls back to the "master" entry only when no per-host key and no -pk are given.
sshx -h=10.0.0.9 "sudo whoami"
```

Check what a host is set to use, and that the secret exists, before relying on it:

```bash
sshx --host-list                 # shows each host's Password Key
sshx --password-check=server-A   # verify the keyring entry exists
```

## Safety checks (block destructive commands)

By default sshx blocks obviously destructive commands (`rm -rf /`, `mkfs`, `dd`,
fork bombs, `curl | sh`, edits to `/etc/passwd|shadow`, shutdown/reboot). A blocked
command never touches the network and reports `error_kind: "blocked"`.

Direct database client execution is also blocked in run/script mode: any
command that puts `psql`/`pgcli`/`sqlite3` in command position — including
wrapped forms like `docker exec <c> psql ...`, `sudo -u postgres psql ...`,
`sudo -u app sqlite3 ...`, `sh -c 'psql ...'`, `kubectl exec ... -- psql ...`,
or `echo "SQL" | psql` — is rejected with a pointer to `sshx sql`.
Availability probes stay allowed (`which psql`, `psql --version`,
`pg_isready`, `sqlite3 --version`). Do not `--force` around this; run the
statement through `sshx sql` instead.

```bash
sshx -h=host "sudo rm -rf /tmp/*"   # allowed
sshx -h=host "sudo rm -rf /"        # BLOCKED

# Bypass only when you are certain (use sparingly):
sshx -h=host --force "sudo reboot"        # -f bypasses the check for this run
sshx -h=host --no-safety-check "<cmd>"    # disables checks entirely (not recommended)
```

This is a guardrail against mistakes, not a security sandbox.

## Guarded SQL execution (PostgreSQL)

`sshx sql` runs **exactly one** SQL statement through the `psql`
clients already on the remote host (or inside a container). sshx embeds no
database driver and opens no tunnel. The pipeline is fail-closed:
classify locally → policy gates → `EXPLAIN (FORMAT JSON)` for every DML →
automatic backup → execute → structured result + audit event.

```bash
# Reads run directly; no EXPLAIN, no backup.
sshx sql -h=db1 --db=app --json "SELECT count(*) FROM users"

# DML with WHERE: rows are snapshotted to CSV on the remote host first.
sshx sql -h=db1 --db=app --db-user=app --db-password-key=app-db --json \
    "UPDATE users SET active=false WHERE id=42"

# Preview impact without executing.
sshx sql -h=db1 --db=app --explain "DELETE FROM sessions WHERE expires_at < now()"

# Local plan preview: classification, gates, backup plan, commands. No connection.
sshx sql -h=db1 --db=app --dry-run --json "UPDATE users SET x=1 WHERE id=5"
```

Safety contract (what an agent must expect):

- Multi-statement input, psql backslash meta-commands, data-modifying CTE
  bodies,   `EXPLAIN ANALYZE`, `SELECT INTO`, `CALL`, dblink delegated execution, unknown statement heads,
  `DROP DATABASE/SCHEMA`, `ALTER SYSTEM`, `COPY`, `DO`, and transaction control
  are always blocked (`error_kind: "blocked"`). Accepted reads execute inside
  a PostgreSQL read-only transaction so side-effecting functions fail.
- `UPDATE`/`DELETE` without a top-level `WHERE` requires `--allow-full-table`;
  destructive DDL requires `--force --no-backup`; any DML `--no-backup`
  requires `--force`.
- Backups are automatic for DML: small change sets get a row-level CSV
  snapshot; missing/complex WHERE, UPSERT, or an EXPLAIN estimate above
  `--row-threshold` (default 1000) get a full-table CSV snapshot. The snapshot
  and mutation run under one database transaction and table write lock, so no
  row can enter the affected set between backup and execution. Backups land
  on the remote host under `~/.sshx/sql-backups/` (`--backup-dir=` to override)
  with owner-only permissions and the JSON result carries a `restore_hint`.
  A catalog preflight blocks automatic execution when triggers, rewrite rules,
  partitions, or cascading referential actions can affect related tables.
  Continue only after an independent backup with `--force --no-backup`. UPSERT
  (`INSERT ... ON CONFLICT DO UPDATE`) is treated as an overwrite and backed up.
- Audits and JSON results contain a literal-redacted statement plus its exact
  SHA-256 digest, classification, backup, and outcome. The DB password is
  delivered via stdin/env passthrough — never argv.
- JSON result fields to branch on: `success`, `error_kind`, `class`, `verb`,
  `statement_sha256`, `estimated_rows`, `affected_rows`, `backup.kind`,
  `backup.path`.

### Dockerized production databases

When PostgreSQL runs in a container and its credentials live in the production
environment (container env or a deploy `.env`) rather than any local keyring:

```bash
# psql runs inside the container; credentials are read from the container env
# (POSTGRES_*/PG*/DB_*/DATABASE_URL) and cached locally for 15 minutes.
sshx sql -h=prod --docker=pg-prod --db-cred-from=docker:pg-prod --json \
    "UPDATE users SET active=false WHERE id=42"

# Credentials from a deployment env file, cached for 1 hour.
sshx sql -h=prod --docker=pg-prod --db-cred-from=env-file:/opt/app/.env \
    --cred-cache=1h --json "SELECT count(*) FROM orders"
```

- `--docker=<container>` executes psql via `docker exec -i` and defaults
  to the container-local socket; backups still stream to the **host**.
- `--db-cred-from=docker:<container>` or `env-file:<path>` resolves the DB user,
  password, and database name remotely; `--db` becomes optional when the source
  provides it. Mutually exclusive with `--db-password-key`.
- Resolved secrets are cached only in the OS keyring with a TTL
  (default 15m; `--cred-cache=off|<duration>`, `--cred-refresh` to force
  re-resolution). Expired entries are actively deleted. The JSON result reports
  `cred_source` and `cred_cache` (`hit`/`stored`/`resolved`).

### SQLite files on the remote host

SQLite is a file, not a server. Identity is an absolute path; there is no
database role or password flag.

```bash
sshx sql -h=app --engine=sqlite --db-file=/var/lib/app/app.db --json \
    "SELECT count(*) FROM users"

sshx sql -h=app --engine=sqlite --db-file=/var/lib/app/app.db --dry-run --json \
    "UPDATE users SET active=0 WHERE id=42"

sshx sql -h=app --engine=sqlite --db-file=/var/lib/app/app.db --json \
    "UPDATE users SET active=0 WHERE id=42"

sshx sql -h=app --engine=sqlite --db-file=/var/lib/app/app.db --sudo --json \
    "UPDATE users SET active=0 WHERE id=42"
```

- Reads open `file:<path>?mode=ro`. DML does not use EXPLAIN row estimates:
  a bounded `UPDATE`/`DELETE` snapshots the table to CSV; overwrites
  (`REPLACE`, `INSERT OR REPLACE`, UPSERT) and unbounded changes take a
  whole-file `sqlite3 .backup` under `BEGIN IMMEDIATE`.
- Always blocked: sqlite3 dot-commands (`.shell`, `.read`, `.once`),
  `ATTACH`/`DETACH`, `load_extension`, writable `PRAGMA`, `VACUUM INTO`,
  URI or `:memory:` identities, and relative paths.
- Table CSV snapshots still run trigger/FK preflight. A whole-file backup
  already covers related tables, so that check is skipped.
- `--db-user`, `--db-password-key`, `--docker`, and `--db-cred-from` are
  rejected. `--db=` may be used as an alias for the absolute file path.
- `--sudo` runs the remote client via `sudo -S` (empty prompt). Use it when
  the SSH user cannot read or write the database file. The host sudo key is
  delivered on stdin ahead of the SQL — never in argv. JSON reports `sudo`.

## Guarded file apply

Prefer `sshx apply` over `sed -i`, in-place editors, or upload-then-`install`
when replacing one remote regular file. The pipeline is fail-closed:
absolute path → optional hash precondition → owner-only backup → atomic
replace → structured result. Reload/restart is a separate `sshx run`.

```bash
sshx apply -h=prod-web --path=/etc/nginx/nginx.conf --from=./nginx.conf \
    --expect-sha256=<current> --sudo --json
sshx apply -h=prod-web --path=/etc/nginx/nginx.conf --from=./nginx.conf \
    --dry-run --json
```

- `--path` must be a clean absolute file path. Symlinks, directories, and
  device nodes are blocked (`error_kind: "blocked"`).
- `--expect-sha256` is optional CAS. Mismatch is `error_kind: "precondition"`
  with `completion: "not_started"` and no write.
- Backups default to `~/.sshx/file-backups/`. `--no-backup` requires `--force`.
- `--sudo` stages the payload over SFTP, then installs with a privileged
  stdin script. Use it when the SSH user cannot write the target.
- `/etc/passwd`, `/etc/shadow`, and `/etc/sudoers` require
  `--force --bypass-reason=`.
- JSON fields to branch on: `success`, `changed`, `created`, `completion`,
  `error_kind`, `before_sha256`, `after_sha256`, `backup.path`,
  `rollback_available`. Identical content is success with `changed=false`.

## SFTP file operations

```bash
sshx -h=host --upload=local.txt --to=/tmp/remote.txt     # upload
sshx -h=host --download=/var/log/app.log --to=./app.log  # download
sshx -h=host --list=/var/log                             # list (alias: --ls)
sshx -h=host --mkdir=/tmp/newdir                         # make dir
sshx -h=host --rm=/tmp/oldfile.txt                       # remove
```

## Host management (`~/.sshx/settings.json`)

```bash
# Add (flags or interactive). Each host may carry its own key (-i) and password key (-pk).
sshx --host-add --host-name=prod-web -h=192.168.1.100 -u=root -pk=prod-web --host-desc="Prod web"
sshx --host-add --host-name=prod-db  -h=192.168.1.200 -u=admin -i=~/.ssh/prod-db.pem

sshx --host-update --host-name=prod-web -h=192.168.1.101   # change one or more fields
sshx --host-list                                           # list (alias: --host-ls)
sshx --host-test=prod-web                                  # test one host
sshx --host-test-all                                       # test all (fast 10s dial timeout)
sshx --host-remove=prod-web                                # remove (alias: --host-rm)
```

After a host is configured, just reference it by name: `sshx -h=prod-web "uptime"`.

## Password / secret management (OS keyring)

Secrets live only in the OS keyring (macOS Keychain / Linux Secret Service /
Windows Credential Manager) under service name `sshx`.

```bash
sshx --password-set=master            # prompt (no echo) — preferred
sshx --password-set=master:secret     # inline (convenient but warned against)
sshx --password-get=master            # confirm exists on a TTY; pipe (e.g. `| pbcopy`) to emit the raw value
sshx --password-check=server-A        # exists? (alias: --password-exists)
sshx --password-list                  # common keys (alias: --password-ls)
sshx --password-delete=server-A       # delete (alias: --password-del)
```

## Authentication & host-key behavior

- Auth order: SSH key first; password fallback only happens when an SSH login
  password is already provided (for example `SSH_PASSWORD`). Keyring passwords
  are for sudo auto-fill, not ordinary SSH login. Force password-only with
  `--no-key` / `--password-only`.
- Strict `known_hosts` verification by default. Opt-in overrides (loud, last-resort):
  `--accept-unknown-host` (records the key once), `--insecure-hostkey`,
  `--known-hosts=<path>`.

## Useful environment variables

`SSH_PASSWORD`, `SSH_KEY_PATH`, `SSH_DISABLE_KEY`, `SSH_KNOWN_HOSTS`,
`SSH_ACCEPT_UNKNOWN_HOST`, `SSH_INSECURE_HOST_KEY`, `SSH_SUDO_KEY`,
`SSH_NO_SAFETY_CHECK`, `SSH_FORCE`, `SSH_TIMEOUT`, `SSHX_LOG_LEVEL`,
`SSHX_HOME` (isolated settings/audit/plugins/trust runtime root).

## Install or refresh this skill

The canonical skill is embedded in every sshx binary. After Homebrew or
`go install`, install it without another network request:

```bash
sshx skill install
```

The default destination is `~/.agents/skills/sshx/SKILL.md`. A matching file is
left unchanged, while a prior sshx-managed version is updated automatically
using `.sshx-managed.json`. If unmanaged content differs, review it before
explicitly replacing it with `sshx skill install --force`. Use `--dir=<path>`
for another Agent skill directory.

With `--json`, successful status is `installed`, `current`, `repaired`, or
`updated`. Installation failures use `conflict`, `unsafe_target`, or
`install_error`; `conflict` leaves the existing file untouched.

## Meta

```bash
sshx --version   # print version (alias: -v); install.sh relies on this
sshx --help      # full reference
```

## Agent checklist

1. Use `--json` and branch on `success` / `error_kind`, not on stdout text.
2. Add `--timeout=` to anything that can hang (package installs, network ops).
3. Prefer named hosts; store secrets in the keyring, never inline in shared scripts.
   Don't assume the sudo key is `master` — named hosts resolve their own `password_key`;
   for ad-hoc IPs pass `-pk=<key>`. Use `--host-list` to see each host's key.
4. Trust the safety check — only `--force` a blocked command when you are certain.
5. Treat `exit_code` 1..254 as the remote program's status; `255` / `-1` is an sshx error.
6. For database work use `sshx sql`, never raw `psql` or `sqlite3` strings
   through `sshx run`: it classifies the statement, backs up affected data,
   and audits everything. Preview with `--dry-run --json` first. PostgreSQL
   adds `--docker=<container>` / `--db-cred-from=` for containerized DBs;
   SQLite uses `--engine=sqlite --db-file=/abs/path.db`. Add `--sudo` when
   the SSH user cannot open the database file. Direct `psql` /
   `sqlite3` invocations are blocked — rework as `sshx sql`, do not `--force`.
7. For remote file edits use `sshx apply`, never `sed -i` or upload-then-`install`.
   Preview with `--dry-run --json`. Branch on `changed` and `error_kind`
   (`precondition` means the file was not written). Validate or reload with a
   separate `sshx run` after apply succeeds.
