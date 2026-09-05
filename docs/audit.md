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
sshx audit query --execution-id=<id> --json
```

Filters compose (AND):

| Flag | Matches |
| --- | --- |
| `--since=` / `--until=` | RFC3339 or `YYYY-MM-DD` on `timestamp` |
| `--target=` | `host_input`, `host_resolved`, or `host_name` |
| `--action=` | `action` or `mode` |
| `--run-id=` | `run_id` or `event_id` |
| `--execution-id=` | `execution_id` or `parent_execution_id` (independent of legacy run IDs) |
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

## Integrity and persistence

Results and audit share finalized plan/execution identity and redacted outcome
evidence. `execution_fingerprint` excludes raw stdout/stderr and secrets; it is
not a digital signature or a tamper-proof log guarantee.
Audit can record public credential-role references (`ssh_password_key`,
`sql_password_key`, `sql_user`), observed `peer_address` /
`host_key_fingerprint`, and `cancellation_cause`, `deadline_scope`, `stop_reason`.
Absent peer evidence is not proof that a connection occurred. None of these
fields contains the referenced password.
Apply audit preserves observed `apply_expect_sha256`, `apply_payload_sha256`
(including an empty payload), before/after hashes and backup path. When an
outcome exists, `apply_backup_verified` is an explicit boolean; `apply_mode`,
`apply_uid`, `apply_gid`, `apply_cleanup_pending` and `apply_replace_method`
retain ownership, cleanup and publication evidence. SQL's engine-specific
evidence is nested under `sql_evidence`. Shared cancellation/deadline fields
come from the same finalized metadata, not a separate audit inference.

Malformed/partial JSONL records are skipped with visible diagnostics while
valid records remain available. Do not equate a damaged file with a clean empty
query. File read/scan and export-write failures are errors, not successful
zero-match results. Valid unknown fields are retained by query/export.
JSON includes nonzero `skipped_records` and `warnings` when needed; warnings
identify the file and line with `error_kind: audit_record_invalid|local_io`,
without including malformed record content. Skipping malformed, non-object or
partial records alone retains `success=true` and the valid records.
The legacy flat query error remains `error_kind: config`;
`error_details.kind` adds the owned I/O classification without breaking it.
On read/scan/write failure, `success=false` can accompany retained valid
`events`; do not discard those records or treat the partial response as complete.
Other readable files are still processed. Valid raw unknown fields and values
are preserved unchanged in export.

Execution audit writing remains best-effort. Persistence status/warnings are
separate from the execution outcome and do not turn a successful mutation into
a failed operation to retry. Repair the audit destination independently.
Lifecycle JSON reports `audit_status: written|failed|disabled`; this status is
not part of the execution fingerprint.
See [the outcome decision table](execution-contract.md#interpret-outcomes-before-retrying).
