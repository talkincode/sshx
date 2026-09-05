# 审计查询与导出

sshx 每次非 dry-run 调用都会写一条 JSONL 审计事件，默认落在
`~/.sshx/audit/sshx-YYYY-MM-DD.jsonl`（或 `--audit-output=<dir>`）。

`sshx audit` 是**只读**消费面。它不会轮转、删除、上传或改写审计文件，
也不会为这次查询本身再写一条审计事件。

## 查询

```bash
sshx audit query --json
sshx audit query --since=2026-09-01 --until=2026-09-02 --target=prod-web
sshx audit query --run-id=<id> --error-kind=blocked --bypass-only --json
sshx audit query --execution-id=<id> --json
```

过滤器是 AND 组合：

| 参数 | 匹配字段 |
| --- | --- |
| `--since=` / `--until=` | `timestamp`，接受 RFC3339 或 `YYYY-MM-DD` |
| `--target=` | `host_input`、`host_resolved` 或 `host_name` |
| `--action=` | `action` 或 `mode` |
| `--run-id=` | `run_id` 或 `event_id` |
| `--execution-id=` | `execution_id` 或 `parent_execution_id`，独立于原 run ID |
| `--error-kind=` | `outcome.error_kind` |
| `--bypass-only` | `force` 或非空 `bypass_reason` |

空结果退出码为 0。`--json` 输出 `sshx.audit.query.v1`，包含 `success`、
`count` 和 `events`（无匹配时为空数组）。

## 导出

```bash
sshx audit export --to=./incident.jsonl --run-id=<id>
sshx audit export --to=./siem.jsonl --since=2026-09-01 --json
```

把匹配事件以 JSONL 写入 `--to=`。sshx 不是 SIEM；导出只是一份权限为
owner-only 的有界交接文件。

## 完整性与持久化

结果与审计复用最终计划/执行身份和脱敏结果证据。`execution_fingerprint`
不含原始 stdout/stderr 或秘密；它不是数字签名，也不保证日志防篡改。
审计可记录公开凭据角色引用（`ssh_password_key`、`sql_password_key`、
`sql_user`）、观测到的 `peer_address` / `host_key_fingerprint`，
以及 `cancellation_cause`、`deadline_scope`、`stop_reason`。
缺少 peer 证据不能证明建立过连接；这些字段不含所引用的密码。
Apply 审计保留观测的 `apply_expect_sha256`、`apply_payload_sha256`
（包括空 payload）、前后哈希与备份路径。存在 outcome 时，
`apply_backup_verified` 是明确布尔值；`apply_mode`、`apply_uid`、`apply_gid`、
`apply_cleanup_pending`、`apply_replace_method` 保留属主、清理与发布证据。
SQL 引擎证据嵌套在 `sql_evidence`；共享取消/期限字段来自同一最终元数据，
不是审计另行推断。

格式错误/部分写入的 JSONL 行会跳过并给出可见诊断，有效记录继续保留。
损坏文件不能等同于干净的空查询；读取/扫描和导出写入失败应报错，而非零匹配成功。
query/export 保留有效记录中的未知字段。
需要时 JSON 含非零 `skipped_records` 和 `warnings`，警告标明文件、行号及
`error_kind: audit_record_invalid|local_io`，不包含损坏记录内容。
仅跳过格式错误、非对象或部分记录时，保留 `success=true` 和有效记录。
兼容的 flat query 错误仍是 `error_kind: config`，由 `error_details.kind`
增量提供 I/O 边界分类。
读/扫描/写入失败时，`success=false` 仍可携带保留的有效 `events`；
不应丢弃这些记录，也不能把部分响应当成完整结果。
其他可读文件仍继续处理；导出原样保留有效原始记录中的未知字段和值。

执行审计仍是尽力写入，持久化状态/警告与执行结果分开，不会把成功的变更变成
应重试的失败。应独立修复审计目的地。详见[结果决策表](execution-contract.md)。
生命周期 JSON 的 `audit_status: written|failed|disabled` 不纳入执行指纹。
