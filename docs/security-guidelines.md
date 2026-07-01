# Security Guidelines

Remote execution is high impact. These rules are strict because a small mistake can change production systems, leak credentials, or hide the real cause of an incident.

## Non-Negotiable Rules

1. Keep host-key verification strict.
2. Store passwords in the OS keyring, not in files, shell history, tickets, or chat.
3. Send sudo passwords through stdin only; never place them in command strings.
4. Treat `--force`, `--no-safety-check`, and `--insecure-hostkey` as exceptional break-glass choices.
5. Use `--dry-run` before privileged or destructive operations.
6. Use `--json` and explicit exit-code checks for automation.
7. Remember that command safety checks are not a sandbox.

## Production Policy

For production, shared runbooks, CI jobs, and agent-driven operations, treat these as policy instead of suggestions:

- Use named hosts so reviewers can see the intended target.
- Set `--timeout` on every unattended command.
- Use `--audit-output` for project, migration, release, and incident work.
- Require `--dry-run --json` before a privileged mutation.
- Keep `--force` and `--no-safety-check` out of reusable scripts.
- Keep `--insecure-hostkey` out of reusable scripts and CI.
- Do not run commands copied from chat, tickets, or web pages until they are reviewed against the target host and rollback plan.
- Prefer staged file writes: upload to `/tmp`, validate, then install with explicit mode and ownership.
- Prefer one visible step per irreversible action; avoid chaining many privileged changes with `&&`.
- Record the maintenance window, operator, command, result, and rollback decision in your own runbook when the action affects production.

Never make a weak security flag global through shell profiles, CI variables, or shared `.env` files. A break-glass override must be local to one command and easy to remove.

## Host-Key Trust

Default behavior protects against unknown or changed host keys. Use one of these safe paths:

```bash
# Recommended: explicitly add the host key after reviewing the target
ssh-keyscan -H prod-web >> ~/.ssh/known_hosts

# Accept first use for a known controlled host
sshx --accept-unknown-host -h=prod-web "uptime"
```

Avoid:

```bash
sshx --insecure-hostkey -h=prod-web "uptime"
```

Use insecure host-key mode only in short-lived controlled labs where the risk is understood and recorded. Never make it the default in scripts or shared runbooks.

## Secret Handling

Use interactive keyring storage:

```bash
sshx --password-set=prod-web-sudo
```

Avoid inline secrets:

```bash
sshx --password-set=prod-web-sudo:plain-text-password
```

Inline values can leak through shell history, terminal scrollback, process listings, logs, or copied commands.

Keyring password keys are for sudo auto-fill. `SSH_PASSWORD` is an SSH login password and should be treated as a high-risk fallback, not a normal operating mode.

## Sudo Rules

`sshx` auto-fills sudo only when the remote command starts with `sudo`:

```bash
sshx -h=prod-web -pk=prod-web-sudo "sudo systemctl reload nginx"
```

These commands do not trigger sudo auto-fill:

```bash
sshx -h=prod-web "sh -c 'sudo whoami'"
sshx -h=prod-web "echo sudo"
```

This boundary keeps password lookup, stdin injection, and audit metadata aligned to one clear rule.

## Safety Checks Are Guardrails

`sshx` blocks common destructive patterns such as root deletion, disk formatting, shutdown or reboot commands, critical system file edits, fork bombs, and `curl | sh` style pipelines.

That does not make untrusted commands safe. A command validator cannot understand every script, shell expansion, application-specific migration, or data-destruction path.

Before bypassing checks:

```bash
sshx -h=prod-web --dry-run --json "sudo systemctl reboot"
sshx -h=prod-web --force "sudo systemctl reboot"
```

Ask:

- Is the target host correct?
- Is the command reviewed?
- Is there a maintenance window?
- Is rollback possible?
- Is the bypass reason recorded?

If any answer is "no", stop and fix the runbook first. `--force` should mean "I reviewed this exact command for this exact target", not "make the tool stop complaining".

## Agent And Automation Rules

Automation should be more conservative than a human terminal:

- Always set `--timeout`.
- Prefer `--json`.
- Parse `success`, `exit_code`, and `error_kind`.
- Run `--dry-run --json` before privileged changes.
- Do not set `SSH_INSECURE_HOST_KEY=1` globally.
- Do not pass plaintext passwords through environment variables unless there is no safer path and the lifetime is tightly controlled.
- Store audit events with `--audit-output` when a run belongs to a project, migration, or incident.

## Audit Trail Boundaries

Audit events are local JSONL records for provenance. They record metadata such as mode, action, host resolution, sudo/keyring decisions, safety status, authentication method, exit code, error kind, and duration.

They intentionally do not record:

- Plaintext passwords.
- Private key contents.
- stdout.
- stderr.

Command text is included for provenance and redacted for common password or token-style arguments, but do not treat redaction as a reason to place secrets in commands.

## SFTP Safety

For uploads to privileged paths, stage the file first:

```bash
sshx -h=prod-web --upload=./service.conf --to=/tmp/service.conf
sshx -h=prod-web "sudo install -m 0644 /tmp/service.conf /etc/service/service.conf"
```

For removals, list before deleting:

```bash
sshx -h=prod-web --list=/tmp
sshx -h=prod-web --rm=/tmp/old-file
```

Remote SFTP paths are remote paths. Do not rely on local OS path rules for remote targets.

## Incident Response Checklist

When something looks wrong:

1. Stop retrying with weaker security flags.
2. Capture the exact command, exit code, and `error_kind`.
3. Check audit events under `~/.sshx/audit` or the configured `--audit-output`.
4. Verify host-key state with `ssh-keygen -F <host>`.
5. Check whether the failure happened before SSH, during auth, during safety validation, during command execution, or during output collection.
6. Rotate exposed credentials if a secret may have entered shell history, CI logs, issue text, or chat.

## Good Defaults For Shared Runbooks

```bash
sshx -h=<named-host> \
  --timeout=30s \
  --audit-output=./.sshx-audit \
  --dry-run \
  --json \
  "sudo systemctl reload <service>"
```

Then run the real command only after the plan is reviewed:

```bash
sshx -h=<named-host> \
  --timeout=30s \
  --audit-output=./.sshx-audit \
  -pk=<sudo-key> \
  "sudo systemctl reload <service>"
```
