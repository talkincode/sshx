# SSHX Documentation

`sshx` is a cross-platform SSH and SFTP command-line client for people and automation agents who operate many remote servers. It keeps the tool shape simple: one command opens one SSH session, does the requested work, writes an optional local audit event, and exits.

The documentation starts in English by default. Use the language switch in the top navigation bar to open the matching Chinese page.

## What SSHX Is Good At

- Run a remote command with predictable stdout, stderr, and exit-code behavior.
- Save sudo passwords in the operating system keyring instead of plaintext files.
- Use short host names from `~/.sshx/settings.json` instead of repeating IP, port, user, and key paths.
- Perform small SFTP tasks without opening an interactive client.
- Produce JSON output that scripts and AI agents can branch on.
- Preview local execution plans with `--dry-run` before connecting, reading secrets, mutating `known_hosts`, or writing host config.
- Keep a local JSONL audit trail without recording plaintext passwords, private keys, stdout, or stderr.

## Mental Model

Think of `sshx` as a safer one-shot remote operation helper, not a shell replacement and not a remote orchestration platform.

```text
human, script, or agent
        |
        v
sshx CLI flags and optional .env
        |
        v
named host resolution and safety checks
        |
        v
SSH command or SFTP action
        |
        v
structured result, exit code, optional audit event
```

## Common First Commands

```bash
# See available flags and examples
sshx --help

# Run a simple command
sshx -h=192.168.1.100 -u=root "uptime"

# Run against a named host
sshx -h=prod-web "systemctl is-active nginx"

# Preview what would happen before connecting
sshx -h=prod-web --dry-run --json "sudo systemctl restart nginx"

# Get machine-readable output for automation
sshx -h=prod-web --json "systemctl is-active nginx"
```

## Safety First

Remote access tools can cause real damage. The safe default path in `sshx` is strict:

- Host keys are checked through `known_hosts`.
- Passwords belong in the OS keyring, not in shell history or config files.
- Sudo passwords are sent through stdin, never interpolated into the command string.
- Obvious destructive commands are blocked unless the user explicitly bypasses checks.
- Safety checks are guardrails against mistakes; they are not a sandbox for untrusted commands.

Read [Security Guidelines](security-guidelines.md) before using `sshx` in production or agent-driven workflows.

## Where To Go Next

- [Getting Started](getting-started.md) gets one host working.
- [Host Management](host-management.md) explains named hosts and key selection.
- [Usage Scenarios](usage-scenarios.md) gives practical examples for daily operations.
- [Agent and Script Mode](agent-scripting.md) explains JSON output, exit codes, timeouts, and audit logs.
- [SFTP Workflows](sftp.md) covers upload, download, list, mkdir, and remove.
