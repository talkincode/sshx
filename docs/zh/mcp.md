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
| `sshx_apply` | `sshx apply --json` | 受控单文件替换；接受 `from_path` 或内联 `content`（允许空字符串） |
| `sshx_inspect` | `sshx inspect --json` | 内置能力与已信任的本地插件 |
| `sshx_sftp` | SFTP flags | upload / download / list / mkdir / remove |
| `sshx_transfer` | `--transfer` | 经本机中转的服务器到服务器流式传输 |
| `sshx_host_list` | `--host-list --json` | 只读 `sshx.hosts.v1` 清单 |

工具结果就是 CLI 的版本化 JSON（例如 `sshx_run` 的 `sshx.result.v1`），因此
`success`、`error_kind`、`completion` 和重试指引与 CLI 文档完全一致。子进程
非零退出会把 MCP 结果标成 tool error，但保留结构化载荷。

当 MCP 客户端在 `sshx_run` 上提供 `progressToken` 时，服务器用 `--jsonl`
跑子进程，并将 `target_finished` 事件通过有界、尽力投递的 MCP
`notifications/progress` 通知发送。进度的 `total` 是选中的目标数。最终工具文档
仍是 CLI 结果：单目标调用返回 `sshx.result.v1`；多目标调用仍返回 JSONL 流。

`--pty` **永久不在 MCP 范围内**。PTY 会把 stderr 并进 stdout，且与 `--json`
不兼容。Agent 应继续使用 `sshx_run` / `sshx_sql` / `sshx_apply`，而不是交互式
终端。

## 计划绑定、期限与投递

远端工具支持 `expect_plan`、`host_timeout_seconds`、`global_timeout_seconds`，
与 CLI 对应；`timeout_seconds` 保留命令/会话含义。run 还支持 `fail_fast` 和
`max_failures`，只停止新准入，不停止已活跃目标。不透明命令/脚本的 mutation 风险
不能由调用方 intent 降级。
SQL 支持可选 `bypass_reason` 记录原有策略批准，不给旧 SQL 调用新增必填理由。
run 的可选 `request_id` 用于调用方关联，不替代唯一 `execution_id`；
inspect 支持相同的 `dry_run` 预览流程。

以 `dry_run: true` 预览、检查 `plan.bindable` / `plan.unresolved`，再以相同输入
和已审核 `expect_plan` 执行。内联 payload 的暂存路径不是身份，字节才是。
公开 IP/key/信任前提、整个信任记录快照的保守失效及远端 SQL 发现限制与 CLI 一致；
共享执行 ID、指纹、变更状态与验证来自 CLI，不另创 MCP schema。

适配器有独立的 30 分钟进程 watchdog；较短的显式全局期限额外保留两分钟报告宽限，
但不超过 watchdog。命令 timeout 不会被乘算成新的 fan-out 限制。
取消先请求子进程协作关闭，再有界升级终止；各平台的本地进程关闭不证明远端终止。
三秒宽限后仅终止本次拥有的进程树（Unix process group 或 Windows job object），
不处理无关进程。

进度投递有界且独立于 stdout 排空，进度通知不是权威完成记录。JSONL 格式错误、
超限/截断、缺少最终完成或输出投递失败是适配器错误，不能合成为成功结果。
重试前应区分执行结果与适配器失败。详见[计划、结果与安全重试](execution-contract.md)。
当前适配器限制：stdout/单事件 64 MiB、stderr 1 MiB、保留 100,000 个事件、
64 条进度队列；进度写入/投递宽限为 250 ms，stdio 会话停滞时关闭会话，
不遗留阻塞的 SDK writer。这是投递限制，不是远端输出或副作用验证保证。

## 安全模型

- **同一套门、同一份证据。** 安全检查、host-key 校验、keyring 凭据角色和审计
  都在子进程里按 CLI 原样执行。run 的 `force` / `no_safety_check` 必须带显式
  `bypass_reason`；apply 保留关键路径理由要求，SQL 保留原批准参数与可选记录理由。
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
