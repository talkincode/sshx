---
name: sshx
description: Operate remote servers with the `sshx` CLI — run commands over SSH, transfer files over SFTP, manage named hosts, and store SSH/sudo passwords in the OS keyring. Use when the user wants to execute a command on a remote host, upload/download files, check or restart services on servers, manage `~/.sshx/settings.json` host entries, or store/retrieve secrets in the system keyring. Prefer `--json` for any programmatic/agent use so results are machine-parseable.
---

# sshx

`sshx` is a single-binary, cross-platform SSH/SFTP client with a built-in OS-keyring
password manager and named-host config. Every invocation opens one connection, does
its work, and exits — there is no daemon, shell, tunneling, or port forwarding.

> One command, multiple servers, zero password hassle.

## When to use

- Run a one-shot command on a remote host (optionally with `sudo`).
- Upload/download a file or list/make/remove remote paths over SFTP.
- Manage frequently used hosts by short name (`~/.sshx/settings.json`).
- Store/fetch SSH or sudo passwords in the OS keyring (never plaintext).

## Golden rule for agents: use `--json`

For any non-interactive/programmatic use, **always pass `--json`** in command mode.
It emits exactly one JSON object on stdout; diagnostic logs go to stderr, so stdout
stays a clean machine-readable stream. `--json` cannot be combined with `--pty`.

```bash
sshx -h=prod-web --json "systemctl is-active nginx"
```

JSON result fields:

```json
{
  "host": "...", "port": "22", "user": "...", "command": "...",
  "exit_code": 0, "success": true, "stdout": "...", "stderr": "...",
  "stdout_truncated": false, "stderr_truncated": false,
  "duration_ms": 0, "auth_method": "key|password|...",
  "error_kind": "", "error": ""
}
```

Branch on `success` first; on failure read `error_kind` (do not parse free-form text).

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
`exit_missing`, `config`, `error`.

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

```bash
sshx -h=host "sudo rm -rf /tmp/*"   # allowed
sshx -h=host "sudo rm -rf /"        # BLOCKED

# Bypass only when you are certain (use sparingly):
sshx -h=host --force "sudo reboot"        # -f bypasses the check for this run
sshx -h=host --no-safety-check "<cmd>"    # disables checks entirely (not recommended)
```

This is a guardrail against mistakes, not a security sandbox.

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
`SSH_NO_SAFETY_CHECK`, `SSH_FORCE`, `SSH_TIMEOUT`, `SSHX_LOG_LEVEL`.

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
