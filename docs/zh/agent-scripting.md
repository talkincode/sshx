# Agent 与脚本模式

`sshx` 设计上可以被脚本和 AI agent 调用。契约很简单：稳定的 stdout/stderr、稳定退出码、可选 JSON、可选本地审计事件。

## 规范执行契约 `sshx run`

复杂脚本、严格别名选择和有界多主机执行请优先使用：

```bash
sshx run --target=prod-web --json -- "systemctl is-active nginx"
sshx run --group=prod-web --tag=env=prod --concurrency=4 --jsonl -- "uptime"
sshx run --target=prod-web --script-file=./check.sh --dry-run --json
```

- 选择器只解析已配置主机；字面地址用 `--address=`，不能进入 group/tag 扩散。
- 脚本经 SSH stdin 原样传输，不经本地 `strings.Join` 拼装。
- 脚本的 `#!` 行决定解释器，`#!/usr/bin/env bash` 会真正用 bash 执行（`set -o pipefail`、数组、`[[ ]]` 都可用）。可用 `--shell=NAME` 覆盖。支持 `sh`、`bash`、`zsh`、`dash`、`ksh`、`ash`；其他解释器在本地就以 `error_kind: config` 拒绝，不建立连接。最终解释器体现在 `action.script_runner`。
- dry-run/结果暴露 payload SHA-256 与字节数，默认不回传脚本全文。
- 多主机 `--jsonl` 输出 `run_started` / `target_*` / `run_finished`。
- 多主机退出码：`0` 全成功，`1` 部分失败/跳过/不确定，`255` 请求级失败。
- 高风险绕过需显式 CLI；`sshx run` 还要求 `--bypass-reason=`。
- 不再隐式加载工作目录 `.env`；`SSH_FORCE` 等环境变量不能授权信任降级。

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

## 受控文件 Apply

覆盖一个远程正则文件时优先用 `sshx apply`。根据 `changed`、`completion` 和
`error_kind` 分支。`precondition` 表示文件没有被写入。

```bash
sshx apply --target=prod-web --path=/etc/nginx/nginx.conf \
    --from=./nginx.conf --expect-sha256="$current" --sudo --json
```

reload 仍是另一次 `sshx run`。详见 [受控文件 Apply](apply.md)。

## 可复用主机探测

在重复执行一串环境发现命令前，先列出并调用有界探测能力：

```bash
sshx plugin list --json
sshx inspect -h=prod-web system.baseline --json
```

应用级采集器属于 sshx 运行资产，不属于 skill。Agent 可以直接生成完整骨架：

```bash
sshx plugin create docker.environment --template=docker --privilege=optional --json
sshx plugin test docker.environment --fixture=complete --json
sshx plugin trust docker.environment --json
sshx inspect -h=prod-web docker.environment --json
```

应根据观察结果的 `status`（`complete`、`partial`、`unsupported`、`failed`）
和 typed `errors` 分支，不要把权限受限的 `partial` 解释成服务不存在。新建或
修改后的插件必须先按当前摘要显式信任，sshx 才会建立远端连接。

远端复用必须显式开启：

```bash
sshx inspect -h=prod-web docker.environment \
  --cache=remote-prefer --max-age=10m --json
```

远端缓存只保存规范化、已脱敏的观察 JSON；它有主机边界和有效期，不是权威
资产库。完整 manifest、信任、脱敏与失效规则见
[主机探测能力与本地插件](inspection-plugins.md)。

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
