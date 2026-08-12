# Inspection Capabilities And Local Plugins

Repeated host discovery is expensive for an Agent: checking whether Docker is
available, locating Compose projects, reading routes and DNS state, and deciding
whether a missing result means "absent" or "permission denied" otherwise takes
many independent commands. `sshx inspect` turns that work into one versioned,
structured invocation.

## Built-in system capabilities

The stable operating-system layer is compiled into sshx:

- `system.identity`
- `system.resources`
- `system.baseline`
- `network.interfaces`
- `network.routes`
- `network.dns`
- `network.listeners`
- `network.firewall`

Run the complete baseline:

```bash
sshx inspect -h=prod-web system.baseline --json
```

The result is an `sshx.observation/v1` JSON document. `status` is one of
`complete`, `partial`, `unsupported`, or `failed`; permission-limited evidence
is never normalized to an absent service.

## Plugins belong to the sshx runtime

Application collectors are local sshx assets. They do not belong in an Agent
skill and are not installed on the target:

```text
~/.sshx/
├── settings.json
├── audit/
├── plugins/
│   └── <plugin-id>/
│       ├── manifest.json
│       ├── collectors/
│       ├── result.schema.json
│       ├── README.md
│       └── fixtures/
├── plugin-lock.json
└── observations/
```

Set `SSHX_HOME` to replace `~/.sshx` for an isolated project, Agent, or CI run.
Existing settings, audit, plugin, and lock paths all follow the same runtime
root.

## Create a custom plugin

`plugin create` produces a complete, editable scaffold:

```bash
sshx plugin create private.environment \
  --runner=sh \
  --platform=linux \
  --privilege=optional \
  --template=generic \
  --json
```

Available templates are `generic`, `docker`, and `nginx`. The Docker template
collects installation/daemon state, versions, Docker root/storage/cgroup data,
containers, images, ports, networks, mounts, and Compose project metadata. It
does not collect container environment values, registry auth, `.env` contents,
Secret values, or raw Compose files.

Plugin API v1 uses the `sh` runner on Linux or Darwin targets. The sshx
controller itself remains cross-platform; a future Windows-target runner needs
an explicit execution and test contract rather than silently treating
PowerShell as POSIX shell.

Use `--replace` only when replacement is intentional. sshx moves the previous
directory under `~/.sshx/plugin-backups/` before installing the new scaffold.
`plugin remove` is recoverable for the same reason.

## Validate, test, and trust

```bash
sshx plugin validate private.environment --json
sshx plugin test private.environment --fixture=complete --json
sshx plugin test private.environment --json
sshx plugin trust private.environment --json
sshx plugin show private.environment --json
sshx plugin list --json
```

`validate` checks the manifest contract, paths, file types/permissions, entrypoint,
JSON Schema, timeouts, privilege declaration, cache policy, and declared effects.
`test` validates a fixture or explicitly runs the local collector with bounded
stdout/stderr and a minimal environment.

A new or changed local plugin is untrusted. `plugin trust` records the digest of
the manifest, entrypoint, and schema in `plugin-lock.json`. Any later edit changes
the digest, and `inspect` refuses to open an SSH connection until the new digest
is explicitly trusted. Trust is admission and audit metadata, not a sandbox: a
trusted collector can do anything allowed to the SSH identity, so review it first.

## Execute without installing remote code

```bash
sshx inspect -h=prod-web private.environment --json
```

sshx resolves and verifies the plugin locally before connecting. It streams the
collector to a fixed `sh -s --` session over SSH stdin, validates exactly one
JSON document against the plugin schema, applies field redaction, wraps the facts
with target/provenance/freshness metadata, and exits. The collector is never
installed persistently on the target and never receives SSH or keyring secrets.

Privilege is declared by the manifest:

- `never`: `--sudo` is rejected.
- `optional`: normal user by default; use `--sudo` explicitly when necessary.
- `required`: sshx resolves the selected sudo key and feeds it to sudo separately
  from the collector payload.

Preview every boundary without connecting:

```bash
sshx inspect -h=prod-web private.environment \
  --cache=remote-prefer \
  --dry-run \
  --json
```

The plan includes the plugin path, digest, trust state, host resolution, privilege,
secret-read decision, execution decision, known-host impact, and observation write.

## Freshness-bounded remote observations

Remote caching is opt-in:

```bash
sshx inspect -h=prod-web private.environment \
  --cache=remote-prefer \
  --max-age=10m \
  --json
```

Only the normalized, redacted JSON observation is stored under the remote user's
`~/.sshx/observations/v1/`. Plugin code remains local. Files are owner-only and
replaced atomically.

A snapshot is reusable only when its capability ID/version/digest, result schema,
parameters, target host-key fingerprint, platform, authenticated UID, boot ID,
and privilege scope still match. TTL expiry or `--refresh` runs the collector again. `--allow-stale`
is an explicit instruction to return a matching expired snapshot; it never makes
the snapshot appear fresh.

Cached files are untrusted input. sshx rejects symlinked path components, unsafe
permissions, wrong ownership, oversized files, malformed JSON, mismatched
schemas, and identity drift rather than silently treating them as current facts.

This is an observation cache, not a CMDB: it has no fleet search, ownership,
desired state, reconciliation, or claim of authoritative inventory.
