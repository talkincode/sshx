# Plans, Outcomes, and Safe Retries

This is the additive execution-hardening contract for issue #71. Existing
flags, intent/force meanings, result envelopes, exit codes, and JSONL event
names remain valid. See [Contract Freeze Policy](contract.md) for compatibility
and [the acceptance matrix](roadmap.md#issue-71-execution-hardening-evidence)
for evidence and external prerequisites.

## Review and bind a local plan

Noninteractive command, `run`, `apply`, `sql`, SFTP, transfer, and `inspect`
previews expose a nested `plan` with `schema_version: "sshx.plan.v1"`, plus
`plan_hash` and `risk`. Run previews retain their `sshx.request.v1` envelope.

```bash
sshx run --target=prod-web --script-file=./deploy.sh --dry-run --json
# Review plan.bindable, plan.unresolved, risk, effects, targets and inputs.
# Paste the reviewed sha256:<64 lowercase hex characters> value unchanged:
sshx run --target=prod-web --script-file=./deploy.sh \
  --expect-plan="$reviewed_hash" --json
```

`--expect-plan` is optional. It compares the prepared invocation against the
reviewed hash before secret lookup or network work. It is not an approval
service; the caller must protect the reviewed hash. A malformed digest is
`config`, a different digest is `plan_mismatch`, and a matching but unbindable
plan is `plan_unresolved`. `--force` cannot bypass this comparison. Rejection
may write the normal redacted audit event.

Ordinary `--dry-run` remains **offline, secret-free, and write-free**, including
no audit, trust, cache, or payload-spool writes. It reads public configuration,
public key/trust material and local payload bytes; it does not read private keys
or consult the secret backend for values.

### What the hash binds

The hash is `sha256:` over a canonical JSON semantic projection, not over the
displayed JSON. Targets and map keys are sorted; meaningful command/script/SQL
bytes remain significant. Durations use normalized integer nanoseconds. Schema
and execution-semantics versions are part of the projection.

Included inputs cover resolved endpoint roles, addresses/users/ports/source
bind, public credential identity and role references, trust snapshot, payload
digests/lengths, interpreter/PTY/privilege, paths and mutation destinations,
SQL classification/identity/backup policy, inspection plugin digest/cache
policy, safety bypasses, conditions, and effective execution/failure limits.
IDs, timestamps, formatting, audit destination, raw output, passwords and private
keys are not semantic plan inputs. A local payload source path is not an identity
when identical snapshotted bytes define the operation; a download destination is.
`selector_digest` still describes selection, not this broader execution binding.

**Trust invalidation is intentionally conservative:** the current implementation
hashes the sorted nonblank, noncomment records of the **entire** selected
`known_hosts` file, not just records for the selected host. An unrelated trust
record edit can invalidate a reviewed plan. Bound execution uses the admitted
trust snapshot rather than reopening a changed file.

### When a preview is unbindable

- DNS-only targets: offline preview does not resolve or freeze DNS answers.
  Use a configured literal IP for binding.
- Key authentication without a usable `<private-key-path>.pub` sidecar:
  preview cannot derive public identity by reading the private key. The loaded
  signer is checked against the admitted public-key fingerprint.
- Missing/unavailable trust material, untrusted peers, or relaxed host-key
  settings (`--accept-unknown-host` / `--insecure-hostkey`). A live peer-key
  rejection still has the established `host_key` category.
- SQL identity supplied only by remote discovery/client defaults. Specify the
  database and role; container/`--db-cred-from` discovery is not offline-pinned
  and is rejected in bound mode.

Password-only binding describes the explicit principal, backend and credential
reference, not the secret bytes. Secret rotation or a changed remote role policy
is not frozen by a local hash. Unbound invocations retain their existing behavior.

Script/apply bytes and bound uploads execute from local snapshots. Remote rows,
file contents, recursive directory membership, executable versions, permissions
and observation-cache contents are **not** implicitly snapshotted by the plan.
Remote preconditions run after local admission. The hash is not a remote lock.

## Risk is not intent or authorization

`risk` is a scalar: `read < mutation < privileged < destructive`.
`effects` retains `unknown`, `remote_write`, `local_write`, `privileged` and
`destructive` facts so the scalar does not hide overlapping effects.

Opaque commands and scripts default to `mutation` with unknown effects;
passing `--intent=read` does not prove they are read-only. A sudo read is
privileged; removal is destructive; uploads/apply/relay write remotely.
Downloads can be remote `read` while explicitly writing a local destination.
Inspection with remote caching includes cache writes; custom collectors are
not assumed pure. The existing safety gates and bypass requirements still
decide admission. Classification is neither permission nor a sandbox.

## Interpret outcomes before retrying

Shared fields are additive to each verb's existing result:

| Field | Meaning |
| --- | --- |
| `execution_id`, `parent_execution_id` | Invocation/target correlation; caller request IDs and legacy run IDs retain their meanings |
| `plan_hash`, `risk`, `effects` | Admitted public plan and anticipated effects |
| `execution_fingerprint` | Digest of finalized redacted execution evidence, not a signature or replay-prevention token |
| `peers`, `target_fingerprints` | Observed public peer/auth identities and, for a run parent, its finalized target fingerprints |
| `change_state` | `changed`, `unchanged`, or `unknown`; unknown must not be treated as false |
| `executed` | Nullable execution observation; `null` means not known, not “did not run” |
| `verified`, `verification` | Whether required evidence was verified, and its status; process success alone is not effect verification |
| `preconditions`, `postconditions` | Optional condition arrays with `kind`, `subject`, `expected`, `observed`, `status` |

Raw stdout/stderr, secret values, and presentation are not fingerprinted.
Fingerprints provide correlation against a trusted reference, not tamper-proof
audit storage. A result can be successful yet lack effect verification; a
failed result can describe a change that already happened. Apply's old `changed`
and `created` booleans remain for compatibility; use `change_state` on failures.
Only the finalized shared projection is covered by the fingerprint; do not
assume every legacy envelope field is included. Reported peer/auth fields
outside that projection are not automatically bound by it.
The shared `peers` projection now binds actual transport address, host-key
fingerprint, auth method, effective user and SSH/sudo credential references.
Target fingerprints include these observed facts; the parent binds them
transitively through `target_fingerprints`. Collection occurs after successful
connection/authentication: failures before that point do not promise retained
observed peers. Missing address/key observations are not invented from planned
target settings, and credential references do not include secret values.

For run, the parent execution ID is also its run ID; target execution IDs are
derived deterministically from the parent and canonical target identity/index.
The single-target result uses the target's metadata, not the run parent's.
The parent `run_finished` metadata retains sorted finalized target fingerprints.
Caller `request_id` is correlation only.

When the JSONL writer remains writable, `seq` is contiguous starting at 1 and
every selected target gets one terminal event. Skipped, never-admitted targets
have no `target_started` event. Final counts satisfy:

```text
Selected = Succeeded + Failed + Skipped
Started  = admitted = Succeeded + Failed
Uncertain is a subset of Failed, not an additional total
```

Selector-rejected candidates are not included in the selected counts.
Uncertain completion includes `partial`, `completed_unconfirmed` and `unknown`
outcomes. An established connection alone is not execution acknowledgement.
Generic executed commands do not verify effects: opaque/risky operations
retain unknown change state, `verified=false`, and unsupported verification.

| Command transport observation | Result certainty |
| --- | --- |
| No exec request attempted (session/PTY/preflight failure) | `completion=not_started`, `executed=false` |
| Exec request attempted but acknowledgement lost | `completion=unknown`, `executed=null`, `change_state=unknown` |
| Positive start acknowledgement | Execution established; completion still depends on exit evidence |
| Exit status observed | Command completion established independently of start-ack reporting |

A timeout, cancellation or disconnect after an attempted exec request must
not be downgraded to “not started” merely because the start acknowledgement
was lost.

| Observation | Next action |
| --- | --- |
| `config`, `plan_mismatch`, `plan_unresolved`, or blocked admission | Correct/review inputs; do not loosen trust just to make a hash pass |
| `precondition` before commit | Re-read/review the remote state; preserve the intended precondition |
| `verification_failed`, partial/unknown completion, or missing acknowledgement | Inspect state and backup evidence before considering a retry |
| `timeout` / `cancelled` after admission | Treat remote effects as potentially partial/unknown; transport retryability alone is insufficient |
| Audit persistence failure after successful execution | Recover audit delivery separately; do not repeat the mutation to create a log |

## Mutation guarantees are backend-specific

**Apply:** a verified no-op can be `unchanged` without a write or backup.
After replacement, readback/hash evidence matters; preserve before/after/payload
hashes and any known backup on failures. Atomic replacement depends on the
server's rename primitive. There is no delete-then-create fallback guarantee.
Rechecking a hash near replacement does **not** provide general compare-and-swap
against arbitrary concurrent SFTP writers. `--force` retains its existing
hash-precondition bypass; it does not bypass `--expect-plan`.

**SFTP/transfer:** inspect the returned operation/effect metadata rather than
treating a successful copy as proof of content equality. Size-only verification
is not a digest comparison. A staged single-file replacement does not imply
directory-wide atomicity or rollback. Interrupted recursive transfers may have
published some files; relay reads the source and writes only the destination.

**SQL:** execution acknowledgement, commit acknowledgement, row counts, backup
state and verified effects are distinct. PostgreSQL matched/processed counts,
SQLite `changes()` and MySQL affected-row counts have different meanings.
Positive counts do not universally prove an UPDATE changed values; zero counts
are not a universal no-side-effects proof. Unsupported verification must remain
explicit. A lost commit acknowledgement is not safe to retry.

SQL's nested `evidence` distinguishes:

| Field | Meaning |
| --- | --- |
| `affected_rows_semantics` | `postgres_command_tag`, `sqlite_changes`, or `mysql_row_count`; legacy `affected_rows` retains the engine count |
| `state_change` | All mutations currently remain `unknown`, including zero counts; reads are `unchanged` |
| `commit` | `not_started`, `unknown`, or `acknowledged` |
| `verification`, `verification_method` | Nonce-bound client-protocol validation, not a postimage check |
| `effect_verification` | Distinct effect verification; generic mutation postconditions remain unsupported |
| `backup_status`, `backup_consistency`, `backup_format` | Whether a planned backup was acknowledged, its locked-preimage consistency and actual format |
| `outcome_uncertain` | Missing commit acknowledgement for a mutation |

`evidence.verification=protocol_verified` must not be read as
`verified=true` for value changes. PostgreSQL/SQLite UPDATE counts can describe
processed rows even when assigned values are identical.
Malformed or missing required evidence reports `protocol_error` or
`verification_failed`; neither is proof that an admitted mutation rolled back.

PostgreSQL, including Docker execution, streams its CSV preimage in one locked
transaction. Volatile/parenthesized predicates escalate row backups to a
whole-table snapshot; multiline table snapshots remain supported.
SQLite table CSV captures the full table. SQLite's mutation client holds
`BEGIN IMMEDIATE`; whole-file `.backup` runs through a **second read-only
client** while that writer lock is held. Mutation is sent only after successful
snapshot completion. Running `.backup` on the same active write-transaction
connection can fail with `database is locked`; that is not the strategy.

Guarded MySQL backups support simple single-table UPDATE/DELETE on InnoDB, with
an explicit write lock and one mutation session (`innodb_table_locks=1`,
`autocommit=0`, `LOCK TABLES ... WRITE`). The table must be plain and unqualified:
aliases, joins, subqueries, RETURNING and guarded-backup DDL are unsupported.
InnoDB/related-effect checks run after acquiring the lock; triggers/cascades and
unsupported table engines are rejected. The data preimage is streamed and persisted before mutation;
no server-side backup table or backup DDL is created. Format
`SSHX_MYSQL_HEX_ROWS_V1` uses hex column/type headers and NULL-aware binary-safe
row values, stored as `.mysql-hex` with `evidence.backup_format=mysql_hex_rows_v1`.
It is **not CSV**, a schema/database dump, or an automatic restore.

Do not generalize supported strategies into universal MySQL atomicity:
separate unlocked snapshot/mutation sessions and implicit-commit DDL are not
atomic. Real-engine concurrent-writer/rollback evidence is required for the
advertised strategy. Unsupported forms require rejection or an explicit
independent-backup bypass with reduced guarantees. See the acceptance matrix
for which real-engine tests have actually run.

## Deadlines and admission stops

- `--timeout` / `SSH_TIMEOUT` retains command/session semantics and existing
  defaults: run defaults to 60s, compatibility command mode remains unset.
  Dial, handshake and password fallback share one connection budget; fallback
  does not restart that budget. Command timeout remains command-only.
- Optional `--host-timeout` covers an admitted target, including setup and
  verification. Optional `--global-timeout` covers the operation including queue
  time. Unset new limits do not silently impose new per-host limits; run retains
  its existing derived aggregate budget when no global override is supplied.
- `--fail-fast` aliases `--failure-mode=fail_fast`. `--max-failures=N` stops
  admission after the threshold; conflicting policies are configuration errors.
  **Already admitted targets finish** and can add further failures. This is not
  a bound on the final number of failures: up to `concurrency-1` other admitted
  targets can fail after the stopping threshold is recorded.
- Cancellation and deadlines independently cancel active transport work.
  `cancelled` is distinct from `timeout`. Closing a local SSH connection or
  terminating an MCP child **does not guarantee remote termination or rollback**.
  Native secret APIs may be noninterruptible; they are checked around the call,
  not made cancellable by launching unbounded background goroutines.

MCP remains a stdio, one-shot-child adapter. Its process watchdog and progress
delivery limits are adapter limits, not remote execution guarantees. Missing or
truncated final JSONL must not be interpreted as completed fan-out.
Fan-out records admission/failure thresholds before publishing events. The
first event-writer failure stops further publishing and returns a local I/O
failure while retaining collected target outcomes internally; a broken output
sink does not undo or redefine those remote outcomes. Missing terminal events
on that sink are not evidence that their targets never ran.

## Platform and evidence limits

Local paths follow the client OS; remote SFTP paths use slash separators.
POSIX mode/owner/signal guarantees do not imply Windows ACL or process semantics.
Native Windows tests, real SQL engines/clients, and an isolated native OS keyring
are separate prerequisites. A cross-build, a mocked SQL client, and the test-only
secret backend do not prove those boundaries. Audit is best-effort, redacted
local evidence; [query diagnostics](audit.md) distinguish corrupt records from
empty results. None of this adds a daemon, workflow engine, scheduler, or
resident remote component.

The native SQL CI lane supplies PostgreSQL 16 / MySQL 8.4. Compiled-CLI
`TestSQLRealEngineReliability` is opt-in with `SSHX_E2E_REAL_SQL=1` and explicit
disposable loopback database credentials; missing clients/services fail an
enabled run. `internal/sqlsafe/real_engine_integration_test.go` separately tests
rollback/commit and concurrent writers. Both exact tests passed for actual
PostgreSQL 17.11 and MySQL 8.4.11 in isolated, network-disabled Docker fixtures,
using real clients via session-owned `docker exec` adapters. This is generated
SQL/real-client/real-server **component integration**, not a mock and not a
compiled-CLI SSH E2E result. The compiled-CLI native SQL opt-in initially failed
for missing host `psql`/`mysql` and still awaits its own CI/client prerequisites.
The Windows-selected portable/CLI subset passed on macOS, but native Windows
still requires CI; a local cross-build/platform lint does not substitute.
See [native SQL prerequisites](roadmap.md#native-sql-prerequisites).
