# sshx 契约冻结策略

Agent 生态会惩罚接口漂移。本文是对 v1 schema 冻结范围、以及何时必须升到
`v2` 的公开承诺。

## 冻结的 v1 表面

在同一个主 schema 版本内，变更只能**增量添加**。删除、重命名或改变字段、
flag、退出码、`error_kind` 的含义，都是破坏性变更。

| 表面 | 冻结名称 | 说明 |
| --- | --- | --- |
| 请求 schema | `sshx.request.v1` | `sshx run` 请求信封 |
| Run 结果 schema | `sshx.result.v1` | 单目标 run；兼容命令 JSON 保留原字段 |
| 计划 schema | `sshx.plan.v1` | 嵌套在原预览中，不替换 `sshx.request.v1` |
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

## 增量执行加固

[计划、结果与安全重试](execution-contract.md) 定义 `--expect-plan`、
标量风险与副作用、执行身份/指纹、可空执行观测、验证、期限和重试判断。
这些字段不重定义既有 `intent`、`changed`、`force`、completion 或退出状态。
新增 `plan_mismatch`、`plan_unresolved`、`cancelled`、`verification_failed`
类别遵循增量策略；应解析类别，而非错误散文。

不要假设历史 JSON 都有 schema tag 或相同信封。run、apply、SQL、探测、
兼容命令与文件操作保留各自领域 payload；共享元数据是增量，不是替换结果对象。
JSONL 事件名称保持不变。

## 1.0 证据门槛

1.0 不是日期，也不是整列打勾；每项门槛必须有证据：

| 门槛 | 证据与剩余边界 |
| --- | --- |
| CLI/MCP 契约一致 | `internal/app/mcp_test.go`、`tests/e2e/mcp_e2e_test.go`；损坏流与关闭需要专门测试 |
| Windows 正确性 | 原生 CI 而非交叉编译；POSIX 权限、login 与 signal 不等于 Windows 保证 |
| Secret backend 生命周期 | `internal/keyringstore` 加隔离原生钥匙链测试；e2e backend 不证明原生集成 |
| 冻结 JSON/JSONL 与退出码 | 契约 fixture 与编译后二进制测试；历史信封必须仍可消费 |
| 变更/恢复证据 | 真实文件/SQL 状态与备份校验；模拟行数不证明引擎事务 |

具体测试路径与外部前提见[验收矩阵](../roadmap.md#issue-71-execution-hardening-evidence)。
文件中存在测试不等于所有平台都执行过。

在 1.0 之前，次版本仍可增加一级能力，但不得破坏本文冻结的名称。
