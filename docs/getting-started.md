# Getting Started

This guide walks through a first safe setup. The examples use `prod-web` as the host name; replace it with your own server name or IP address.

## Install

If Go is already installed:

```bash
go install github.com/talkincode/sshx/cmd/sshx@latest
sshx --version
sshx skill install
```

`sshx skill install` writes the canonical skill embedded in the binary to
`~/.agents/skills/sshx/SKILL.md`. The same command should be run after a
Homebrew install or upgrade; prior sshx-managed versions update automatically.
Use `--force` only after reviewing a locally modified existing copy.

You can also run a specific version without installing:

```bash
go run github.com/talkincode/sshx/cmd/sshx@latest --help
```

## Verify SSH Trust First

`sshx` checks host keys by default. Add the server to `known_hosts` before the first connection:

```bash
ssh-keyscan -H prod-web >> ~/.ssh/known_hosts
```

If you deliberately want first-use trust, use:

```bash
sshx --accept-unknown-host -h=prod-web "uptime"
```

Avoid `--insecure-hostkey` except in short-lived controlled labs. It disables the trust check that protects against man-in-the-middle attacks.

## Run The First Command

```bash
sshx -h=prod-web -u=deploy "uptime"
```

Useful variations:

```bash
# Non-standard SSH port
sshx -h=prod-web -p=2222 -u=deploy "uptime"

# Specific SSH key
sshx -h=prod-web -u=deploy -i=~/.ssh/prod-web.pem "uptime"

# Bound a slow command
sshx -h=prod-web --timeout=30s "apt-get update"
```

## Add A Named Host

Named hosts keep connection details in one local file:

```bash
sshx --host-add --host-name=prod-web -h=192.168.1.100 -u=deploy -i=~/.ssh/prod-web.pem --host-desc="Production web node"
```

After that:

```bash
sshx --host-list
sshx --host-test=prod-web
sshx -h=prod-web "uname -a"
```

The settings file is `~/.sshx/settings.json` and is written with `0600` permissions.

## Open An Interactive Login

When you personally need a remote prompt on a host already stored in sshx, do
not copy it into `~/.ssh/config`:

```bash
sshx login prod-web
sshx login prod-web --sudo
sshx login -h=prod-web --sudo
sshx login prod-web --dry-run --json
```

`--sudo` starts a privileged login shell after feeding the host sudo secret
from the OS keyring. Login requires a local TTY, is POSIX-only, and is not
part of the Agent/MCP contract.

## Save A Sudo Password

For commands that start with `sudo`, `sshx` can read a password from the OS keyring and feed it to sudo through stdin.

```bash
sshx --password-set=prod-web-sudo
sshx -h=prod-web -pk=prod-web-sudo "sudo systemctl status nginx"
```

Use interactive input. Avoid inline values such as `--password-set=key:password`; they can leak through shell history or process lists.

## Preview Before Running

`--dry-run` explains how `sshx` interpreted the command without connecting, executing, reading keyring secrets, changing `known_hosts`, or writing host config.

```bash
sshx -h=prod-web --dry-run --json "sudo systemctl restart nginx"
```

Dry-run proves the local plan. It does not prove the remote command would succeed.
