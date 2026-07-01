# Agent And Script Mode

`sshx` is designed to be called by scripts and AI agents. The contract is intentionally simple: predictable streams, predictable exit codes, optional JSON, and optional local audit events.

## Default Stream Behavior

By default `sshx` does not request a PTY. That keeps stdout and stderr separate and avoids terminal control characters in script output.

```bash
sshx -h=prod-web "systemctl is-active nginx"
```

The remote command exit code becomes the `sshx` process exit code when the remote command runs.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Remote command succeeded. |
| `1..254` | Remote command failed with that exit code. |
| `255` | `sshx` failed before or around execution, such as connect, auth, host-key, timeout, blocked command, config, or other local error. |

In JSON mode, `sshx`-level failures use `exit_code: -1` and a non-empty `error_kind`, so automation can distinguish them from a remote command that exits `255`.

## JSON Output

```bash
sshx -h=prod-web --json "systemctl is-active nginx"
```

Example shape:

```json
{
  "host": "192.168.1.100",
  "port": "22",
  "user": "deploy",
  "command": "systemctl is-active nginx",
  "exit_code": 0,
  "success": true,
  "stdout": "active\n",
  "stderr": "",
  "duration_ms": 142,
  "auth_method": "key"
}
```

Agent branching example:

```bash
result="$(sshx -h=prod-web --json "systemctl is-active nginx")"
if printf '%s' "$result" | jq -e '.success == true' >/dev/null; then
  echo "nginx is active"
else
  printf '%s\n' "$result" | jq '{exit_code, error_kind, stderr}'
fi
```

## Dry-Run For Change Review

Before a script performs a privileged operation, ask for the plan:

```bash
sshx -h=prod-web --dry-run --json "sudo systemctl restart nginx"
```

Use dry-run to verify host resolution, selected sudo key, safety status, and whether the command would mutate state. Do not treat it as proof that the remote service can restart successfully.

## Timeouts

Always set timeouts for unattended workflows:

```bash
sshx -h=prod-web --timeout=30s --json "systemctl is-active nginx"
sshx -h=prod-web --timeout=2m --json "sudo apt-get update"
```

## Audit Events

Non-dry-run invocations write local JSONL audit events by default:

```text
~/.sshx/audit/sshx-YYYY-MM-DD.jsonl
```

Store audit events next to a project or incident directory:

```bash
sshx -h=prod-web --audit-output=./.sshx-audit "systemctl reload nginx"
```

Audit events are for provenance. They record metadata and outcomes, but they do not record plaintext passwords, private key contents, stdout, or stderr.

## PTY Is Explicit

Some commands need terminal behavior:

```bash
sshx -h=prod-web --pty "top -b -n1"
```

Do not combine `--pty` with `--json`. A PTY merges stderr into stdout and makes structured automation less reliable.
