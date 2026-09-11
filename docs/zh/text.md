# 文本解剖

`sshx text` 是给 Agent 用的远端文件/systemd journal 解剖面：抽取异常块和错误行。
它不是远端 `grep` 包装，也不接受 `--command`。

```bash
sshx text --help
sshx text --help --json
sshx text -h=prod-web --path=/var/log/app.log --preset=exception --json
sshx text -h=prod-web --path=/var/log/app.log --around-line=8821 --context=5 --json
sshx text -h=prod-web --journal=nginx.service --since=1h --preset=error --json
```

## 工作流

1. 先读 `sshx text --help`（或 `--help --json`）。
2. 先拿异常块和计数：`--preset=exception --json`。
3. 用 `--around-line` 和 `--context` 精确切片。
4. 只有需要取证归档时才 `--download` 整文件。

## 源

二选一：

- `--path=/abs/file` — SFTP 流式扫描普通文件。默认 `--scan=end` 读末尾 8MiB。拒绝符号链接、目录和二进制。
- `--journal=UNIT` — sshx 持有的 `journalctl` argv。Agent 不自由拼 journalctl 参数。

`--sudo` 经 stdin 注入 sudo 秘密。

## 结果

JSON schema `sshx.text.v1`。按 `success`、`hits[].kind`、`stats.total_hits` 与
`returned`、`truncated`、`redacted`、`line_origin` 分支。默认脱敏。审计不写命中原文。
