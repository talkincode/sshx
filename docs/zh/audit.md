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
```

过滤器是 AND 组合：

| 参数 | 匹配字段 |
| --- | --- |
| `--since=` / `--until=` | `timestamp`，接受 RFC3339 或 `YYYY-MM-DD` |
| `--target=` | `host_input`、`host_resolved` 或 `host_name` |
| `--action=` | `action` 或 `mode` |
| `--run-id=` | `run_id` 或 `event_id` |
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
