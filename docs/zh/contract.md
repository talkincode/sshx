# sshx 契约冻结策略

Agent 生态会惩罚接口漂移。本文是对 v1 schema 冻结范围、以及何时必须升到
`v2` 的公开承诺。

## 冻结的 v1 表面

在同一个主 schema 版本内，变更只能**增量添加**。删除、重命名或改变字段、
flag、退出码、`error_kind` 的含义，都是破坏性变更。

| 表面 | 冻结名称 | 说明 |
| --- | --- | --- |
| 请求 schema | `sshx.request.v1` | `sshx run` 请求信封 |
| 结果 schema | `sshx.result.v1` | 单目标 run / 兼容 JSON |
| 事件 schema | `sshx.event.v1` | JSONL `run_started` / `target_started` / `target_finished` / `run_finished` |
| 主机清单 | `sshx.hosts.v1` | `--host-list` 以及主机增删改/探测 JSON |
| 密钥 | `sshx.secrets.v1` | `--password-check` / `--password-list` / `--password-set` JSON |
| 审计事件 | `sshx.audit.v1` | 每次非 dry-run 调用一条 JSONL |
| 审计查询 | `sshx.audit.query.v1` | `sshx audit query/export --json` |
| 退出码 | `0`、`1..254`、`255` | 远端状态 vs sshx 层失败 |
| JSON sshx 失败 | `exit_code: -1` | 与远端 `exit 255` 可区分 |
| `error_kind` | `timeout`、`auth`、`host_key`、`connect`、`blocked`、`exit_missing`、`config`、`error`，加上 SQL/apply 扩展 | 按此字段分支，不要解析散文 |
| JSONL 事件类型 | `run_started`、`target_started`、`target_finished`、`run_finished` | |

某次已发布次版本 `sshx --help` 里列出的 CLI flag，在该主版本线剩余时间内
保持有效。可以新增 flag，但不能给已有调用形状引入新的必填 flag。

## 兼容策略

- v1 文档随时可以出现新字段。Agent 必须忽略未知字段。
- 破坏性变更需要新 schema（如 `sshx.result.v2`），并提供 N-1 支持窗口：
  新 schema 发布后，直到再下一个 sshx 主版本之前，旧 schema 仍要发出或接受。
- `--json` 的 stdout 必须是机器文档。人类日志走 stderr。
- MCP 工具原样返回 CLI JSON。MCP 不另起一套 schema。

## 1.0 门槛清单

1.0 不是日期，而是这份清单：

- [x] stdio MCP 服务器（`sshx mcp`）已交付，且与 CLI 执行等价
- [x] Windows 单元测试 + 构建矩阵覆盖 CLI/SSH 核心
- [x] `internal/keyringstore` 覆盖 system 与 e2e 后端
- [x] run / sql / apply / hosts / secrets / audit 已有版本化 JSON 契约
- [ ] plugin/skill/tests 包的 Windows E2E（另行跟踪）
- [x] 上述冻结 v1 字段名没有已知的契约破坏 TODO
- [x] 本策略已从 README 和 AGENT.md 链接

在 1.0 之前，次版本仍可增加一级能力，但不得破坏本文冻结的名称。
