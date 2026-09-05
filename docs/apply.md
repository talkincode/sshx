# Guarded File Apply

`sshx apply` replaces one remote regular file. It is the file equivalent of `sshx sql`: classify the target, check a hash precondition, write a backup, then atomically replace the file. Reload and restart stay outside this command.

```bash
sshx apply -h=prod-web --path=/etc/nginx/nginx.conf --from=./nginx.conf \
    --expect-sha256=<current> --sudo --json
```

## What Apply Does

1. Refuse anything that is not a clean absolute regular-file path.
2. Block `/etc/passwd`, `/etc/shadow`, and `/etc/sudoers` unless `--force --bypass-reason=` is explicit.
3. Read the current file (if it exists) and compare `--expect-sha256` when provided.
4. Copy the current file to `~/.sshx/file-backups/` unless `--no-backup --force` is set.
5. Write a same-directory temp file, preserve mode and owner, then rename over the target.
6. Return hash/backup evidence, `change_state`, nullable `executed`, `verified`,
   `verification`, conditions and `completion`, alongside legacy `changed` /
   `created` fields.

If the remote content already matches the payload, apply succeeds with `changed=false` and does not write a backup.

## Verification and concurrency limits

Use the shared `change_state` (`changed|unchanged|unknown`) on failures; an old
boolean `changed=false` must not be interpreted as proof that no write occurred.
A no-op can be verified and unchanged without a mutation. A post-write
`verification_failed` can mean replacement happened but readback failed or
did not match: inspect before/after/payload hashes and any known `backup.path`
before retrying. A backup is recovery evidence, not automatic rollback.
`backup.verified` records backup readback/hash verification;
`rollback_available` requires that verification, not merely an existing path.
It still does not mean a tested restore or an automatic rollback. Owned staging
artifacts are cleaned up best-effort; `cleanup_pending` names possible leftovers after interrupted or
failed cleanup. Inspect those paths before removing anything.

| Observation | Execution/change evidence |
| --- | --- |
| Content already matches | `executed=false`, `change_state=unchanged`, `verified=true` |
| Publication acknowledged, required readback fails | `executed=true`, `completion=completed`, `change_state=changed`; operation fails verification |
| Rename acknowledgement missing | `executed=null`, `completion=unknown`, `change_state=unknown`; inspect before retry |

When publication is attempted, `replace_method` identifies `posix_rename`,
`sftp_rename`, or privileged `same_directory_mv`. Do not infer a stronger
primitive than the reported method.

The target hash is checked close to replacement, but SFTP has no general atomic
compare-and-swap against arbitrary concurrent writers. Atomic rename depends
on the server primitive; do not infer delete-then-create safety or filesystem
durability from a successful SSH exit. Privileged apply likewise requires a
valid readback report, not just exit zero.
If the POSIX-rename extension returns `SSH_FX_OP_UNSUPPORTED`, apply may try
ordinary rename, which can refuse an existing destination. It never upgrades
that failure into delete-then-create replacement.

`--force` retains its old hash-precondition bypass and backup/critical-path
approval meanings. It cannot bypass `--expect-plan`.

## Privileged Paths

SFTP runs as the SSH user. Use `--sudo` when the target is not writable by that user. sshx stages the payload under the remote home directory, then runs a privileged stdin script to install it. The script is never left on the host.

```bash
sshx apply --target=prod-web --path=/etc/nginx/nginx.conf \
    --from=./nginx.conf --sudo --json
```

Validation and service reload are separate `sshx run` invocations:

```bash
sshx run --target=prod-web --json -- "sudo nginx -t"
sshx run --target=prod-web --json -- "sudo systemctl reload nginx"
```

## Preview

```bash
sshx apply -h=prod-web --path=/etc/nginx/nginx.conf --from=./nginx.conf --dry-run --json
```

Dry-run hashes the local file and prints the local plan. It does not connect or mutate the remote file.
For strict local review-to-execution binding, inspect the nested
`sshx.plan.v1` / `plan_hash` and repeat with `--expect-plan="$reviewed_hash"`.
Payload bytes and public identity/trust must still match; remote contents are
governed by explicit conditions, not implicitly frozen by the plan.
See [Plans, Outcomes, and Safe Retries](execution-contract.md).

## When To Keep Using SFTP

Use `--upload` / `--download` for moving bytes without a backup contract. Use
`apply` for replacement with a hash, backup, and explicit change/verification
evidence, including uncertainty after failures.
