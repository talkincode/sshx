# MCP 服务器（stdio）

`sshx mcp` 把 sshx 执行契约通过 Model Context Protocol 暴露出去，让支持 MCP
的 Agent（Claude Desktop、IDE agent、自定义客户端）把 sshx 当原生工具调用，
而不必自己拼 shell。

```bash
sshx mcp
```

服务器只讲 stdio 上的 MCP。它由 MCP 客户端拉起并拥有，不持有 SSH 连接、
不保存状态，客户端关闭流就退出。每次工具调用都会把 sshx 二进制再以一次性
子进程重入——进程模型、安全门、keyring 访问和审计轨迹与 CLI 完全相同。

## 客户端配置

Claude Desktop / 通用 MCP 客户端条目：

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

## 工具

| 工具 | 映射到 | 说明 |
| --- | --- | --- |
| `sshx_run` | `sshx run --json` | 选择器、命令或按字节保真的脚本（shebang 或 `shell` 选解释器）、有界扩散、dry-run、force + bypass_reason |
| `sshx_sql` | `sshx sql --json` | 经远端 psql / sqlite3 / mysql 的受控单语句 SQL |
| `sshx_apply` | `sshx apply --json` | 受控单文件替换；接受 `from_path` 或内联 `content` |
| `sshx_inspect` | `sshx inspect --json` | 内置能力与已信任的本地插件 |
| `sshx_sftp` | SFTP flags | upload / download / list / mkdir / remove |
| `sshx_transfer` | `--transfer` | 经本机中转的服务器到服务器流式传输 |
| `sshx_host_list` | `--host-list --json` | 只读 `sshx.hosts.v1` 清单 |

工具结果就是 CLI 的版本化 JSON（例如 `sshx_run` 的 `sshx.result.v1`），因此
`success`、`error_kind`、`completion` 和重试指引与 CLI 文档完全一致。子进程
非零退出会把 MCP 结果标成 tool error，但保留结构化载荷。

当 MCP 客户端在 `sshx_run` 上提供 `progressToken` 时，服务器用 `--jsonl`
跑子进程，并把每条 `target_finished` 事件转成 MCP
`notifications/progress` 通知。进度的 `total` 是选中的目标数。最终工具文档
仍是 CLI 结果：单目标调用返回 `sshx.result.v1`；多目标调用仍返回 JSONL 流。

`--pty` **永久不在 MCP 范围内**。PTY 会把 stderr 并进 stdout，且与 `--json`
不兼容。Agent 应继续使用 `sshx_run` / `sshx_sql` / `sshx_apply`，而不是交互式
终端。

## 安全模型

- **同一套门、同一份证据。** 安全检查、host-key 校验、keyring 凭据角色和审计
  都在子进程里按 CLI 原样执行。`force` / `no_safety_check` 必须带显式
  `bypass_reason`。
- **审计归属。** 子进程调用的审计事件带 `entry: "mcp"`，以便区分 MCP 来源与
  交互式 CLI。该标记只是元数据，不改变信任或安全决策。
- **没有密钥表面。** 密码管理（`--password-set` 等）故意不做成工具。先用 CLI
  配好凭据；MCP 工具只引用 keyring key。
- **不能靠省略来放松信任。** 接受未知 host key 不是工具参数。请事先显式信任
  主机（例如 `sshx --host-test` 或一次有人监督的 CLI 运行）。
- **仅 stdio。** 没有 HTTP/SSE 传输、没有监听套接字、没有常驻服务；这条边界
  写在 AGENT.md §3。

## 典型流程

1. 用 CLI 配置并信任主机（`--host-add`、`--host-import`、`--host-test`）。
2. 把凭据存进 OS keyring（`--password-set=...`）。
3. 把 MCP 客户端指向 `sshx mcp`。
4. Agent 用 `sshx_host_list` 发现清单，用 `dry_run: true` 预览，执行，并按
   结构化结果分支。
