# Agent And Script Mode

`sshx` is designed to be called by scripts and AI agents. The contract is intentionally simple: predictable streams, predictable exit codes, optional JSON, and optional local audit events.

## Canonical Run Contract

Prefer `sshx run` for strict alias selection, complex scripts, and multi-host fan-out:

```bash
sshx run --target=prod-web --json -- "systemctl is-active nginx"
sshx run --group=prod-web --tag=env=prod --concurrency=4 --jsonl -- "uptime"
sshx run --target=prod-web --script-file=./check.sh --dry-run --json
cat ./check.sh | sshx run --target=prod-web --script-stdin --json
```

- Selectors resolve configured hosts only. Use `--address=` for one literal address.
- Script payloads are streamed on SSH stdin and are not reconstructed through shell joining.
- The script's `#!` line selects the interpreter, so a `#!/usr/bin/env bash` payload keeps bash semantics (`set -o pipefail`, arrays, `[[ ]]`). Use `--shell=NAME` to override it. Supported: `sh`, `bash`, `zsh`, `dash`, `ksh`, `ash`; any other interpreter is rejected as `error_kind: config` without connecting. The choice appears as `action.script_runner`.
- Dry-run and results expose payload SHA-256 and byte length, not raw script contents.
- Multi-target `--jsonl` streams `run_started`, per-target events, and `run_finished`.
- Multi-target exit codes: `0` all succeeded, `1` partial/failed/skipped/uncertain, `255` request-level failure.
- High-risk bypasses require explicit flags; command mode and `sshx run` require `--bypass-reason=` with `--force` / `--no-safety-check`.
- Working-directory `.env` files are not loaded. Inherited `SSH_FORCE` /
  `SSH_NO_SAFETY_CHECK` / host-key env switches do not authorize trust relaxation.

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

## Guarded File Apply

Prefer `sshx apply` when replacing one remote regular file. Branch on
`changed`, `completion`, and `error_kind`. A `precondition` failure means the
file was not written.

```bash
sshx apply --target=prod-web --path=/etc/nginx/nginx.conf \
    --from=./nginx.conf --expect-sha256="$current" --sudo --json
```

Reload stays a separate `sshx run`. See [Guarded File Apply](apply.md).

## Reusable Host Inspection

Before repeating a chain of discovery commands, list and run a bounded
inspection capability:

```bash
sshx plugin list --json
sshx inspect -h=prod-web system.baseline --json
```

Application-specific collectors are sshx runtime assets, not skill assets. An
Agent can scaffold one without inventing its file layout:

```bash
sshx plugin create docker.environment --template=docker --privilege=optional --json
sshx plugin test docker.environment --fixture=complete --json
sshx plugin trust docker.environment --json
sshx inspect -h=prod-web docker.environment --json
```

Branch on observation `status` (`complete`, `partial`, `unsupported`, or
`failed`) and typed `errors`. Do not interpret permission-limited `partial` as
service absence. New or edited plugins must be trusted by digest before sshx
connects to the target.

Remote reuse is explicit:

```bash
sshx inspect -h=prod-web docker.environment \
  --cache=remote-prefer --max-age=10m --json
```

The remote cache stores only normalized, redacted observation JSON. It is
host-scoped and freshness-bounded, not an authoritative inventory. See
[Inspection Capabilities And Local Plugins](inspection-plugins.md) for the full
manifest, trust, redaction, and invalidation contract.

## Dry-Run For Change Review

Before a script performs a privileged operation, ask for the plan:

```bash
sshx -h=prod-web --dry-run --json "sudo systemctl restart nginx"
```

Use dry-run to verify host resolution, selected sudo key, safety status, and whether the command would mutate state. Do not treat it as proof that the remote service can restart successfully.

## Timeouts

Always set timeouts for unattended workflows. `sshx run` defaults the command
timeout to 60s when `--timeout` / `SSH_TIMEOUT` are unset; compatibility
`sshx -h=...` command mode still has no command timeout unless you set one.
The SSH dial timeout is independent (30s).

```bash
sshx -h=prod-web --timeout=30s --json "systemctl is-active nginx"
sshx -h=prod-web --timeout=2m --json "sudo apt-get update"
sshx run --target=prod-web --json -- "uptime"   # command timeout defaults to 60s
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
