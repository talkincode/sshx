# SSHX Documentation

> **SSH is the channel. X is execution.**

`sshx` is an agent-native remote host execution tool. It uses SSH/SFTP to reach existing hosts and brings target resolution, execution preview, safety checks, command and file actions, structured results, and audit evidence into one CLI invocation.

It keeps the operating model simple: one command opens one connection, performs one explicit action, returns a decidable result, writes a local audit event, and exits. Nothing needs to be installed on the remote host and no long-running control plane is introduced.

The documentation starts in English by default. Use the language switch in the top navigation bar to open the matching Chinese page.

## What SSHX Is Good At

- Run a remote command with predictable stdout, stderr, and exit-code behavior.
- Save sudo passwords in the operating system keyring instead of plaintext files.
- Use short host names from `~/.sshx/settings.json` instead of repeating IP, port, user, and key paths.
- Perform small SFTP tasks without opening an interactive client.
- Replace one remote regular file with a hash, backup, and atomic write.
- Produce JSON output that scripts and AI agents can branch on.
- Preview local execution plans with `--dry-run` before connecting, reading secrets, mutating `known_hosts`, or writing host config.
- Keep a local JSONL audit trail without recording plaintext passwords, private keys, stdout, or stderr.
- Inspect system/network state in one call and create reusable application plugins under the sshx runtime root.

## Mental Model

Think of `sshx` as a remote execution primitive in an agent's toolbox, not an interactive shell replacement and not a desired-state or workflow orchestration platform.

```text
agent, automation, or human operator
        |
        v
agent contract: CLI / JSON / exit code / dry-run
        |
        v
X execution: target / safety / action / audit
        |
        v
SSH channel: auth / host key / SSH exec / SFTP
        |
        v
remote host
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

# Inspect a complete system/network baseline in one call
sshx inspect -h=prod-web system.baseline --json
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

- [Project Profile and Direction](roadmap.md) defines the product position, hard non-goals, and acceptance matrix (currently maintained in Chinese).
- [Getting Started](getting-started.md) gets one host working.
- [Host Management](host-management.md) explains named hosts and key selection.
- [Usage Scenarios](usage-scenarios.md) gives practical examples for daily operations.
- [Agent and Script Mode](agent-scripting.md) explains JSON output, exit codes, timeouts, and audit logs.
- [Inspection Capabilities and Local Plugins](inspection-plugins.md) explains built-ins, `plugin create`, trust, and observations.
- [SFTP Workflows](sftp.md) covers upload, download, list, mkdir, and remove.
- [Guarded File Apply](apply.md) replaces one remote file with backup and hash checks.
