# Agent 与脚本模式

`sshx` 设计上可以被脚本和 AI agent 调用。契约很简单：稳定的 stdout/stderr、稳定退出码、可选 JSON、可选本地审计事件。

## 默认输出流

默认不请求 PTY，这样 stdout 和 stderr 会保持分离，也不会把终端控制字符混进脚本输出。

```bash
sshx -h=prod-web "systemctl is-active nginx"
```

当远程命令成功运行后，远程退出码会成为 `sshx` 进程退出码。

## 退出码

| 退出码 | 含义 |
| --- | --- |
| `0` | 远程命令成功。 |
| `1..254` | 远程命令以该退出码失败。 |
| `255` | `sshx` 层面失败，例如连接、认证、host-key、timeout、命令被阻止、配置或其他本地错误。 |

在 JSON 模式下，`sshx` 层面的失败使用 `exit_code: -1` 和非空 `error_kind`，因此自动化可以把它和远程命令退出 `255` 区分开。

## JSON 输出

```bash
sshx -h=prod-web --json "systemctl is-active nginx"
```

示例结构：

```json
{
  "host": "192.168.1.100",
  "port": "22",
  "user": "deploy",
  "command": "systemctl is-active nginx",
  "exit_code": 0,
  "success": true,
  "stdout": "active\n",
  "stderr": "",
  "duration_ms": 142,
  "auth_method": "key"
}
```

agent 分支示例：

```bash
result="$(sshx -h=prod-web --json "systemctl is-active nginx")"
if printf '%s' "$result" | jq -e '.success == true' >/dev/null; then
  echo "nginx is active"
else
  printf '%s\n' "$result" | jq '{exit_code, error_kind, stderr}'
fi
```

## 用 dry-run 审核变更

在脚本执行特权操作前，先看计划：

```bash
sshx -h=prod-web --dry-run --json "sudo systemctl restart nginx"
```

用 dry-run 核对主机解析、sudo key、安全检查结果，以及真实执行是否会修改状态。不要把 dry-run 当成远程服务一定能重启成功的证明。

## 超时

无人值守工作流应总是设置 timeout：

```bash
sshx -h=prod-web --timeout=30s --json "systemctl is-active nginx"
sshx -h=prod-web --timeout=2m --json "sudo apt-get update"
```

## 审计事件

非 dry-run 调用默认写入本地 JSONL 审计事件：

```text
~/.sshx/audit/sshx-YYYY-MM-DD.jsonl
```

把审计事件保存到项目或事故目录旁边：

```bash
sshx -h=prod-web --audit-output=./.sshx-audit "systemctl reload nginx"
```

审计事件用于溯源。它记录元数据和结果，但不记录明文密码、私钥内容、stdout 或 stderr。

## PTY 需要显式启用

某些命令需要终端语义：

```bash
sshx -h=prod-web --pty "top -b -n1"
```

不要把 `--pty` 和 `--json` 混用。PTY 会把 stderr 合并进 stdout，让结构化自动化变得不稳定。
