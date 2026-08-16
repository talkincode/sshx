# MCP Server (stdio)

`sshx mcp` serves the sshx execution contract over the Model Context Protocol
so MCP-capable agents (Claude Desktop, IDE agents, custom clients) can call
sshx as native tools instead of shelling out.

```bash
sshx mcp
```

The server speaks MCP over stdio only. It is spawned and owned by the MCP
client, holds no SSH connections, keeps no state, and exits when the client
closes the stream. Every tool call re-enters the sshx binary as a one-shot
child process — the same process model, safety gates, keyring access, and
audit trail as the CLI.

## Client Configuration

Claude Desktop / generic MCP client entry:

```json
{
  "mcpServers": {
    "sshx": {
      "command": "sshx",
      "args": ["mcp"]
    }
  }
}
```

## Tools

| Tool | Maps to | Notes |
| --- | --- | --- |
| `sshx_run` | `sshx run --json` | Selectors, command or byte-preserving script, bounded fan-out, dry-run, force + bypass_reason |
| `sshx_sql` | `sshx sql --json` | Guarded single-statement SQL via remote psql/sqlite3 |
| `sshx_apply` | `sshx apply --json` | Guarded single-file replace; accepts `from_path` or inline `content` |
| `sshx_inspect` | `sshx inspect --json` | Built-in capabilities and trusted local plugins |
| `sshx_sftp` | SFTP flags | upload / download / list / mkdir / remove |
| `sshx_transfer` | `--transfer` | Server-to-server streaming through the local machine |
| `sshx_host_list` | `--host-list --json` | Read-only `sshx.hosts.v1` inventory |

Tool results contain the CLI's versioned JSON verbatim (for example
`sshx.result.v1` from `sshx_run`), so `success`, `error_kind`, `completion`,
and retry guidance keep exactly the semantics documented for the CLI. A
non-zero child exit marks the MCP result as a tool error while preserving the
structured payload.

## Security Model

- **Same gates, same evidence.** Safety checks, host-key verification, keyring
  credential roles, and audit all run in the child process exactly as in
  direct CLI use. `force` / `no_safety_check` require an explicit
  `bypass_reason` argument.
- **Audit attribution.** Child invocations carry `entry: "mcp"` in their audit
  events, so MCP-originated executions are distinguishable from interactive
  CLI use. The marker is metadata only — it never changes trust or safety
  decisions.
- **No secret surface.** Password management (`--password-set` and friends) is
  deliberately not exposed as a tool. Configure credentials with the CLI
  first; MCP tools only ever reference keyring keys.
- **No trust relaxations by omission.** Accepting unknown host keys is not a
  tool parameter. Trust hosts explicitly beforehand (for example with
  `sshx --host-test` or one supervised CLI run).
- **stdio only.** There is no HTTP/SSE transport, no listening socket, and no
  resident service; this boundary is documented in AGENT.md §3.

## Typical Flow

1. Configure and trust hosts with the CLI (`--host-add`, `--host-import`,
   `--host-test`).
2. Store credentials in the OS keyring (`--password-set=...`).
3. Point the MCP client at `sshx mcp`.
4. The agent discovers inventory (`sshx_host_list`), previews with
   `dry_run: true`, executes, and branches on the structured result.
