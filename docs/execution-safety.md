# Execution safety in v0.20

This release repairs execution boundaries without adding a resident service or
weakening file integrity, host-key trust, or safe-retry semantics.

## Sudo authentication is not application input

Noninteractive command auto-fill, `run --sudo`, `apply --sudo`,
`inspect --sudo`, `sql --sudo`, and privileged `text` reads use a session-owned
prompt/readiness handshake:

1. A random prompt marker identifies a sudo authentication request.
2. Only that request authorizes sending one credential line.
3. A separate child-ready marker authorizes sending the application payload.
4. NOPASSWD, cached authentication and root do not receive a credential line.
5. Repeated prompts, missing readiness, cancellation and I/O errors fail closed.

Markers are removed from stderr even when split across SSH packets. Secrets
never enter argv, environment variables or temporary secret files. The
handshake has a 30-second readiness limit; configured command/host/global
limits can end it earlier. Passwords containing NUL/CR/LF are rejected rather
than creating ambiguous input framing.

Auto-fill still applies only to a **leading sudo**. The readiness wrapper uses
`sh -c` with positional argv; quoted arguments and outer pipelines remain at
the original shell boundary. This requires permission to run that shell under
sudo. A command-only sudoers grant may therefore reject auto-fill; do not use
force or expand privileges automatically. Use an operator-approved execution
path instead. Ambiguous sudo shell/login options (`-s`, `-i`) are rejected by
the noninteractive auto-fill path. Do not redirect its control stderr away;
missing readiness does not authorize an unconditional password write.

**Human login:** `sshx login HOST --sudo` runs `sudo -i` with authentication
handled by the human TTY. It no longer reads or prefills the stored sudo
credential. SSH-login credential references are unaffected.

### Verification

`TestSudoInputBoundary` exercises the compiled CLI and actual shells under both
password-consuming and non-consuming policies. Packet-split and cancellation
regressions cover the control protocol. `TestNativeSudoInputBoundary` is enabled
on disposable Linux CI users and checks native PASSWORD, NOPASSWD, cached,
root and wrong-password cases. It must not be enabled against production
accounts. Other OS sudo policies require their own native verification; an
SSH fixture is not evidence for every PAM or sudo configuration.

## RouterOS

- `ros raw` preserves the supplied command text. It no longer sorts parameters,
  removes quoting, or implicitly adds `without-paging`. Include paging options
  in the raw command when required. Structured commands retain their encoder.
- Recognized device diagnostic lines fail even when SSH reports exit status 0.
  Transport exit, domain acceptance and effect verification remain distinct;
  successful arbitrary mutations do not imply verified postconditions.
- ROS connections use configured jump hosts, SSH credential references and
  host/global budgets. Results and audit share finalized execution evidence.
- File upload/download reuse the guarded SFTP implementation: no direct
  truncate-and-copy path, no silent delete-before-replace, and no symlink
  destination overwrite. Backup/export use unique default remote filenames.
- `script put` retries as `set` only after a positively observed duplicate-name
  diagnostic, never after an uncertain transport outcome.
- ROS offline plan binding is still unsupported: `--expect-plan` is rejected,
  not silently ignored. Raw commands are not a security sandbox.

## SFTP and privileged apply

Transfers use a bounded 1 MiB aperture and at most 32 outstanding requests per
file. This preserves content verification, error ownership and partial-effect
records while avoiding a serial round trip per 32 KiB packet. An upload still
reads the destination back for verification; completion and verification are
not interchangeable. JSON remains one final document.

For a host whose home filesystem lacks space:

```bash
sshx apply -h=prod --sudo --path=/data/app/config.yml --from=./config.yml \
  --stage-dir=/data/sshx-stage --backup-dir=/data/sshx-backups --dry-run --json
```

`--stage-dir` requires `--sudo`, is an absolute remote path and is included in
the reviewed plan. Existing private-directory, symlink and permission checks
remain active. It controls the unprivileged SFTP payload staging area, **not**
the final same-filesystem publication primitive or the backup directory.
Changing it changes the plan hash. MCP apply exposes the same `stage_dir` field.

## Trust, deadlines and audit

- Known host-key algorithms are preferred before fallback negotiation; the
  final host-key/certificate/revocation callback remains authoritative.
  Missing algorithm enrollment is distinct from a changed key of a known type.
- `--host-test` retains its caller's trust path, cancellation context and
  deadlines. Its command probe has a bounded default when no timeout is set.
- Audit redaction covers named secret suffixes (such as `--reverse-token`),
  authorization headers and escaped continuations. Redaction metadata names
  its policy and explicitly reports `completeness=best_effort`.
  Arbitrary program output and unknown secret encodings are not guaranteed
  secret-free; do not print credential-bearing configurations to a shared log.
- Plan schema stays `sshx.plan.v1`; execution semantics advance to
  `sshx.execution.v2`. **Re-preview plans after upgrading.** A pre-upgrade hash
  is not authorization for the changed execution semantics.

Audit persistence remains independent from remote success. A cancellation or
verification failure after publication can still mean the destination changed;
inspect state and known backups before retrying a mutation.
