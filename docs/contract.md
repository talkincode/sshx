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
| Run result schema | `sshx.result.v1` | Single-target run; compatibility command JSON retains its legacy fields |
| Plan schema | `sshx.plan.v1` | Nested in existing previews; does not replace `sshx.request.v1` |
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

## Additive execution hardening

[Plans, Outcomes, and Safe Retries](execution-contract.md) defines
`--expect-plan`, scalar risk and effects, execution identity/fingerprint,
nullable execution observation, verification, deadlines and safe retry decisions.
These fields do not redefine legacy `intent`, `changed`, `force`, completion,
or exit status. New `plan_mismatch`, `plan_unresolved`, `cancelled`, and
`verification_failed` categories are additive; parse categories, not error prose.

Do not assume every historical JSON response had a schema tag or the same
envelope. Run, apply, SQL, inspection, compatibility command and file operations
retain their domain-specific payloads. Common metadata is additive, not a
replacement JSON object. JSONL event names remain unchanged.

## 1.0 evidence gates

1.0 is not a date or a blanket checked box. Each gate needs evidence:

| Gate | Evidence and remaining boundary |
| --- | --- |
| CLI/MCP contract parity | `internal/app/mcp_test.go`, `tests/e2e/mcp_e2e_test.go`; malformed streams and shutdown require their own tests |
| Windows correctness | Native CI jobs, not a cross-build; POSIX permissions, login and signals are not Windows guarantees |
| Secret backend lifecycle | `internal/keyringstore` plus isolated native-keyring runs; the e2e backend does not prove native integration |
| Frozen JSON/JSONL and exits | Contract fixtures and compiled-binary tests; legacy envelopes must remain consumable |
| Mutation/recovery evidence | Real file/SQL state and backup checks; mocked SQL counts do not prove engine transactions |

See the [acceptance matrix](roadmap.md#issue-71-execution-hardening-evidence)
for concrete test paths and named prerequisites. A test existing in the tree
does not mean it ran on every platform.

Until 1.0, minor versions may still add first-level capabilities. They must
not break the frozen names in this document.
