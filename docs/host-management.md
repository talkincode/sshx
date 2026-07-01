# Host Management

Named hosts turn repetitive SSH details into a short, readable alias. They are useful when you manage several servers, when each server uses a different SSH key, or when an agent needs a stable host inventory.

## Add Hosts

Interactive setup:

```bash
sshx --host-add
```

Command-line setup:

```bash
sshx --host-add \
  --host-name=prod-web \
  -h=192.168.1.100 \
  -p=22 \
  -u=deploy \
  -i=~/.ssh/prod-web.pem \
  -pk=prod-web-sudo \
  --host-desc="Production web node" \
  --host-type=linux
```

Then run commands by alias:

```bash
sshx -h=prod-web "hostname && uptime"
```

## Settings File

Host definitions live in `~/.sshx/settings.json`.

```json
{
  "key": "/Users/alice/.ssh/id_rsa",
  "hosts": [
    {
      "name": "prod-web",
      "description": "Production web node",
      "host": "192.168.1.100",
      "port": "22",
      "user": "deploy",
      "key": "/Users/alice/.ssh/prod-web.pem",
      "password_key": "prod-web-sudo",
      "type": "linux"
    }
  ]
}
```

The top-level `key` is the default SSH private key. A per-host `key` overrides it for that host only.

## Daily Host Commands

```bash
# List configured hosts
sshx --host-list

# Test one host
sshx --host-test=prod-web

# Test every host with a per-host dial timeout
sshx --host-test-all

# Update a host
sshx --host-update --host-name=prod-web -u=deploy -i=~/.ssh/prod-web-2026.pem

# Remove a host
sshx --host-remove=old-lab
```

## Practical Naming Patterns

Use names that explain both role and environment:

```text
prod-web-1
prod-db-primary
staging-api
lab-router
customer-a-jump
```

Use password keys that do not expose sensitive topology in public logs. For shared runbooks, prefer placeholders:

```bash
sshx -h=prod-web -pk=<sudo-key> "sudo systemctl reload nginx"
```

## Team And Agent Use

For human operators, named hosts reduce typing errors. For automation agents, they create a stable boundary:

- The agent receives `prod-web`, not a raw IP and key path.
- The operator can review `~/.sshx/settings.json`.
- `--dry-run --json` can confirm which address, port, user, key, and sudo key would be used.
- Audit events can record the resolved host without storing secrets.
