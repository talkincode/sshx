# Audit Query and Export

sshx writes one JSONL audit event per non-dry-run invocation under
`~/.sshx/audit/sshx-YYYY-MM-DD.jsonl` (or `--audit-output=<dir>`).

`sshx audit` is a **read-only** consumption surface. It does not rotate,
delete, upload, or rewrite audit files, and it does not write an audit event
for the query itself.

## Query

```bash
sshx audit query --json
sshx audit query --since=2026-09-01 --until=2026-09-02 --target=prod-web
sshx audit query --run-id=<id> --error-kind=blocked --bypass-only --json
```

Filters compose (AND):

| Flag | Matches |
| --- | --- |
| `--since=` / `--until=` | RFC3339 or `YYYY-MM-DD` on `timestamp` |
| `--target=` | `host_input`, `host_resolved`, or `host_name` |
| `--action=` | `action` or `mode` |
| `--run-id=` | `run_id` or `event_id` |
| `--error-kind=` | `outcome.error_kind` |
| `--bypass-only` | `force` or a non-empty `bypass_reason` |

Empty results exit 0. `--json` emits `sshx.audit.query.v1` with `success`,
`count`, and `events` (an empty array when nothing matches).

## Export

```bash
sshx audit export --to=./incident.jsonl --run-id=<id>
sshx audit export --to=./siem.jsonl --since=2026-09-01 --json
```

Writes matching events as JSONL to `--to=`. sshx is not a SIEM; export is a
bounded handoff file with owner-only permissions.
