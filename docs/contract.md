# sshx Contract Freeze Policy

Agent ecosystems punish interface drift. This document is the public commitment
for what is frozen in the v1 schemas and when a change requires `v2`.

## Frozen v1 surface

Within a major schema version, changes are **additive-only**. Removing,
renaming, or changing the meaning of a field, flag, exit code, or
`error_kind` is a breaking change.

| Surface | Frozen names | Notes |
| --- | --- | --- |
| Request schema | `sshx.request.v1` | `sshx run` request envelope |
| Result schema | `sshx.result.v1` | Single-target run / compatibility JSON |
| Event schema | `sshx.event.v1` | JSONL `run_started` / `target_started` / `target_finished` / `run_finished` |
| Host inventory | `sshx.hosts.v1` | `--host-list` and host mutation/test JSON |
| Secrets | `sshx.secrets.v1` | `--password-check` / `--password-list` / `--password-set` JSON |
| Audit events | `sshx.audit.v1` | One JSONL object per non-dry-run invocation |
| Audit query | `sshx.audit.query.v1` | `sshx audit query/export --json` |
| Exit codes | `0`, `1..254`, `255` | Remote status vs sshx-level failure |
| JSON sshx failure | `exit_code: -1` | Distinguishes a remote `exit 255` |
| `error_kind` | `timeout`, `auth`, `host_key`, `connect`, `blocked`, `exit_missing`, `config`, `error`, plus SQL/apply additions | Branch on this field, not prose |
| JSONL event types | `run_started`, `target_started`, `target_finished`, `run_finished` | |

CLI flags listed in `sshx --help` for a released minor version remain valid
for the rest of that major line. New flags may be added. Required flags must
not be introduced for an existing invocation shape.

## Compatibility policy

- Additive fields may appear on v1 documents at any time. Agents must ignore
  unknown fields.
- A breaking change requires a new schema (`sshx.result.v2`, …) and an N-1
  support window: the previous schema remains emitted or accepted until the
  next major sshx release after the new schema ships.
- `--json` stdout stays a machine document. Human logs belong on stderr.
- MCP tools return the CLI JSON verbatim. MCP does not grow a parallel schema.

## 1.0 gate checklist

1.0 is not a date. It is this checklist:

- [x] stdio MCP server (`sshx mcp`) ships and is execution-equivalent to the CLI
- [x] Windows unit-test + build matrix is green for the CLI/SSH core
- [x] `internal/keyringstore` has unit coverage for system and e2e backends
- [x] Versioned JSON contracts exist for run, sql, apply, hosts, secrets, audit
- [ ] Windows E2E for plugin/skill/tests packages (tracked separately)
- [x] No known contract-breaking TODOs on the frozen v1 field names above
- [x] This policy is linked from README and AGENT.md

Until 1.0, minor versions may still add first-level capabilities. They must
not break the frozen names in this document.
