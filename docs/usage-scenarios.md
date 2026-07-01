# Usage Scenarios

This page is intentionally example-heavy. Treat the host names as placeholders and adapt the commands to your own runbooks.

## Scenario 1: First Health Check

You just received access to a server and want a low-risk check.

```bash
ssh-keyscan -H prod-web >> ~/.ssh/known_hosts
sshx -h=prod-web -u=deploy "hostname && uptime && whoami"
```

Why this is useful: it verifies host trust, authentication, the remote user, and basic reachability without changing the server.

## Scenario 2: Add A Production Host Once

```bash
sshx --host-add \
  --host-name=prod-web \
  -h=192.168.1.100 \
  -u=deploy \
  -i=~/.ssh/prod-web.pem \
  -pk=prod-web-sudo \
  --host-desc="Production web node"

sshx --host-test=prod-web
sshx -h=prod-web "hostname"
```

Why this is useful: future commands no longer repeat IP, user, key path, and sudo key.

## Scenario 3: Check A Service Without Changing It

```bash
sshx -h=prod-web "systemctl is-active nginx"
sshx -h=prod-web "systemctl status nginx --no-pager"
```

For automation:

```bash
sshx -h=prod-web --json "systemctl is-active nginx"
```

## Scenario 4: Restart A Service With Review

```bash
sshx -h=prod-web --dry-run --json "sudo systemctl restart nginx"
sshx -h=prod-web -pk=prod-web-sudo "sudo systemctl restart nginx"
sshx -h=prod-web "systemctl is-active nginx"
```

Why this is useful: the dry-run confirms local interpretation before a privileged change.

## Scenario 5: Check Disk Pressure On Several Servers

```bash
for host in prod-web prod-api prod-db; do
  echo "== $host =="
  sshx -h="$host" --timeout=15s "df -h / /var /data"
done
```

Agent-friendly version:

```bash
for host in prod-web prod-api prod-db; do
  sshx -h="$host" --timeout=15s --json "df -h / /var /data"
done
```

## Scenario 6: Collect Logs For An Incident

```bash
mkdir -p incident-2026-07-01/prod-web
sshx -h=prod-web --download=/var/log/nginx/error.log --to=incident-2026-07-01/prod-web/error.log
sshx -h=prod-web --download=/var/log/nginx/access.log --to=incident-2026-07-01/prod-web/access.log
sshx -h=prod-web --audit-output=incident-2026-07-01/audit "journalctl -u nginx --since '30 min ago' --no-pager"
```

Why this is useful: downloaded evidence and local audit metadata stay next to the incident folder.

## Scenario 7: Upload A Config Safely

```bash
sshx -h=prod-web --upload=./nginx.conf --to=/tmp/nginx.conf
sshx -h=prod-web "sudo nginx -t -c /tmp/nginx.conf"
sshx -h=prod-web "sudo install -m 0644 /tmp/nginx.conf /etc/nginx/nginx.conf"
sshx -h=prod-web "sudo nginx -t"
sshx -h=prod-web "sudo systemctl reload nginx"
```

Why this is useful: the file is staged and validated before replacing the production config.

## Scenario 8: Use Different Sudo Keys Per Host

```bash
sshx --password-set=prod-web-sudo
sshx --password-set=prod-db-sudo

sshx -h=prod-web -pk=prod-web-sudo "sudo systemctl reload nginx"
sshx -h=prod-db -pk=prod-db-sudo "sudo systemctl status postgresql"
```

Why this is useful: one operator can manage several servers without reusing one global sudo key.

## Scenario 9: Validate Every Configured Host

```bash
sshx --host-test-all
```

Run this after rotating keys, changing VPN access, or importing a new `settings.json`.

## Scenario 10: Script A Safe Status Report

```bash
for host in prod-web prod-api prod-db; do
  sshx -h="$host" --timeout=20s --json "hostname && uptime" \
    | jq --arg host "$host" '{alias: $host, success, exit_code, error_kind, stdout}'
done
```

Why this is useful: scripts read JSON fields instead of scraping terminal prose.

## Scenario 11: Bound A Risky Long-Running Command

```bash
sshx -h=prod-web --timeout=2m "sudo apt-get update"
```

Why this is useful: unattended commands should not hang forever.

## Scenario 12: Diagnose A Host-Key Failure

If a host key changed, do not bypass it first. Check why it changed.

```bash
ssh-keygen -F prod-web
ssh-keyscan -H prod-web
```

Only update `known_hosts` after confirming the machine was rebuilt, reinstalled, or intentionally rotated.

## Scenario 13: Avoid Shell-Pipe Installers

This command pattern is intentionally high risk:

```bash
sshx -h=prod-web "curl -fsSL https://example.invalid/install.sh | sh"
```

Safer pattern:

```bash
sshx -h=prod-web "curl -fsSL https://example.invalid/install.sh -o /tmp/install.sh"
sshx -h=prod-web "less /tmp/install.sh"
sshx -h=prod-web "sha256sum /tmp/install.sh"
sshx -h=prod-web "sh /tmp/install.sh"
```

## Scenario 14: Use PTY Only When Needed

```bash
sshx -h=prod-web --pty "sudo visudo -c"
```

Prefer non-PTY for scripts because it preserves stdout and stderr separation.

## Scenario 15: Disable Audit For A Single Sensitive Run

If command text itself would reveal sensitive context, disable audit for that invocation and record the reason in your own runbook.

```bash
SSHX_NO_AUDIT=true sshx -h=prod-web "echo redacted"
```

Do not use this as a default. Audit events are useful for explaining what happened.

## Scenario 16: Check Docker Without Opening A Shell

```bash
sshx -h=prod-web --json "docker ps --format '{{json .}}' | head -20"
sshx -h=prod-web "docker inspect nginx --format '{{.State.Status}} {{.RestartCount}}'"
```

Why this is useful: operators can collect container state without starting an interactive SSH session or copying broad logs.

## Scenario 17: Verify A Deployment Artifact Before Releasing

```bash
sshx -h=prod-web --upload=./dist/app.tar.gz --to=/tmp/app.tar.gz
sshx -h=prod-web "sha256sum /tmp/app.tar.gz"
sshx -h=prod-web "tar -tzf /tmp/app.tar.gz | head"
```

Only install the artifact after the checksum and archive contents match the release note.

## Scenario 18: Rotate A Service Config With Rollback

```bash
sshx -h=prod-web --upload=./service.env --to=/tmp/service.env.new
sshx -h=prod-web "sudo cp /etc/myapp/service.env /etc/myapp/service.env.bak.\$(date +%Y%m%d%H%M%S)"
sshx -h=prod-web "sudo install -m 0600 /tmp/service.env.new /etc/myapp/service.env"
sshx -h=prod-web "sudo systemctl restart myapp"
sshx -h=prod-web --json "systemctl is-active myapp"
```

Why this is useful: the backup, install mode, restart, and health check are separate visible steps.

## Scenario 19: Collect A Minimal Support Bundle

```bash
mkdir -p support/prod-web
sshx -h=prod-web --download=/etc/os-release --to=support/prod-web/os-release
sshx -h=prod-web --audit-output=support/audit "uname -a"
sshx -h=prod-web --audit-output=support/audit "df -h"
sshx -h=prod-web --audit-output=support/audit "free -m"
```

Do not download private application data unless the support case explicitly needs it.

## Scenario 20: Use `--` When Remote Flags Look Like Local Flags

```bash
sshx -h=prod-web -- docker run --rm alpine:3.20 sh -c 'echo hello'
sshx -h=prod-web -- echo --force belongs-to-the-remote-command
```

Why this is useful: `--` makes the boundary between local `sshx` flags and remote command arguments obvious.

## Scenario 21: Test A New Host Entry Before Sharing It

```bash
sshx --host-add --host-name=staging-api -h=10.0.8.21 -u=deploy -i=~/.ssh/staging.pem -pk=staging-api-sudo
sshx --host-test=staging-api
sshx -h=staging-api --dry-run --json "sudo systemctl reload api"
```

Only commit or share a runbook after the named host resolves, authenticates, and selects the expected sudo key.

## Scenario 22: Keep A Migration Run Bounded

```bash
sshx -h=prod-db --timeout=10s --json "pg_isready"
sshx -h=prod-db --timeout=5m --dry-run --json "sudo systemctl restart postgresql"
sshx -h=prod-db --timeout=5m -pk=prod-db-sudo "sudo systemctl restart postgresql"
sshx -h=prod-db --timeout=30s --json "pg_isready"
```

Why this is useful: every step has a time budget and a machine-readable result.

## Scenario 23: Remove A Temporary File With Evidence

```bash
sshx -h=prod-web --list=/tmp
sshx -h=prod-web --rm=/tmp/app.tar.gz
sshx -h=prod-web --list=/tmp
```

Deletion should be visible before and after. For high-risk paths, prefer a remote `mv` into a dated quarantine directory before permanent removal.

## Scenario 24: Fail Closed In CI

```bash
result="$(sshx -h=prod-web --timeout=20s --json "systemctl is-active nginx")"
printf '%s\n' "$result" | jq .
printf '%s\n' "$result" | jq -e '.success == true and .stdout == "active\n"'
```

Why this is useful: CI fails when the structured result is missing, the command fails, or the service state is not exactly what the runbook expects.
