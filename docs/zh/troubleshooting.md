# 故障排查

先判断失败边界：是 `sshx` 在远程命令运行前失败，还是远程命令已经运行但返回非零退出码？

## 获取结构化错误详情

```bash
sshx -h=prod-web --json "systemctl is-active nginx"
```

重点看：

- `success`
- `exit_code`
- `error_kind`
- `stderr`
- `auth_method`

JSON 模式下，`sshx` 层面的失败会有 `exit_code: -1` 和非空 `error_kind`。

## Host Key 错误

症状：

- 未知 host key。
- host key 发生变化。
- 认证前连接中断。

检查：

```bash
ssh-keygen -F prod-web
ssh-keyscan -H prod-web
```

只有确认主机符合预期后再修复。不要直接跳到 `--insecure-hostkey`。

## 认证错误

检查解析后的主机和选择的 key：

```bash
sshx -h=prod-web --dry-run --json "whoami"
```

常见原因：

- `~/.sshx/settings.json` 中用户写错。
- per-host key 路径错误。
- key 文件权限不正确。
- 服务端不接受选择的认证方式。
- 误以为 keyring 里的 sudo 密码会当作 SSH 登录密码。

Keyring 密码用于 sudo 自动填充，不会被静默用作 SSH 登录密码。

## Sudo 没有自动填充

只有命令以 `sudo` 开头，`sshx` 才会自动填充。

可以触发：

```bash
sshx -h=prod-web -pk=prod-web-sudo "sudo whoami"
```

不会触发：

```bash
sshx -h=prod-web "sh -c 'sudo whoami'"
```

检查 password key 是否存在：

```bash
sshx --password-check=prod-web-sudo
```

## 命令被阻止

通常是安全检查失败。

```bash
sshx -h=prod-web --dry-run --json "sudo rm -rf /"
```

如果特权或破坏性命令确实是预期操作，先审阅、记录原因，再只对这一次使用 `--force`。

## 脚本卡住

设置 timeout：

```bash
sshx -h=prod-web --timeout=30s --json "long-running-command"
```

如果命令必须要终端语义，可以使用 `--pty`，但 PTY 模式不适合结构化自动化。

## JSON 输出无法解析

普通 JSON 模式下，stdout 应该只包含一个 JSON 对象，诊断信息走 stderr。检查这些问题：

- 是否使用了 `--pty`。
- 外层脚本是否在 `sshx` 前后打印了额外文本。
- 调用方是否混合了 stdout 和 stderr。

## SFTP 路径问题

本地文件使用本地路径规则。远程目标使用斜杠分隔的远程路径：

```bash
sshx -h=prod-web --upload=./file.txt --to=/tmp/file.txt
```

## 审计事件缺失

检查是否禁用了审计：

```bash
env | grep SSHX_NO_AUDIT
```

检查默认输出位置：

```bash
ls ~/.sshx/audit
```

如果使用项目内目录：

```bash
sshx -h=prod-web --audit-output=./.sshx-audit "uptime"
ls ./.sshx-audit
```

## command not found

检查安装：

```bash
command -v sshx
sshx --version
```

如果通过 Go 安装，确认 `~/go/bin` 或 `GOPATH/bin` 已加入 `PATH`。
