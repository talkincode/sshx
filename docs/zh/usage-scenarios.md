# 使用场景

这一页故意放了很多例子。请把主机名当成占位符，并按你的 runbook 调整命令。

## 场景 1：第一次健康检查

刚拿到服务器访问权限，先做低风险检查：

```bash
ssh-keyscan -H prod-web >> ~/.ssh/known_hosts
sshx -h=prod-web -u=deploy "hostname && uptime && whoami"
```

这能同时验证 host trust、认证、远程用户和基本连通性，而且不会修改服务器。

## 场景 2：一次性添加生产主机

```bash
sshx --host-add \
  --host-name=prod-web \
  -h=192.168.1.100 \
  -u=deploy \
  -i=~/.ssh/prod-web.pem \
  -pk=prod-web-sudo \
  --host-desc="Production web node"

sshx --host-test=prod-web
sshx -h=prod-web "hostname"
```

这样后续命令不再重复 IP、用户、key 路径和 sudo key。

## 场景 3：只检查服务，不做变更

```bash
sshx -h=prod-web "systemctl is-active nginx"
sshx -h=prod-web "systemctl status nginx --no-pager"
```

自动化版本：

```bash
sshx -h=prod-web --json "systemctl is-active nginx"
```

## 场景 4：带审核地重启服务

```bash
sshx -h=prod-web --dry-run --json "sudo systemctl restart nginx"
sshx -h=prod-web -pk=prod-web-sudo "sudo systemctl restart nginx"
sshx -h=prod-web "systemctl is-active nginx"
```

dry-run 可以在特权变更前确认本地解释是否正确。

## 场景 5：检查多台机器磁盘压力

```bash
for host in prod-web prod-api prod-db; do
  echo "== $host =="
  sshx -h="$host" --timeout=15s "df -h / /var /data"
done
```

agent 友好版本：

```bash
for host in prod-web prod-api prod-db; do
  sshx -h="$host" --timeout=15s --json "df -h / /var /data"
done
```

## 场景 6：为事故收集日志

```bash
mkdir -p incident-2026-07-01/prod-web
sshx -h=prod-web --download=/var/log/nginx/error.log --to=incident-2026-07-01/prod-web/error.log
sshx -h=prod-web --download=/var/log/nginx/access.log --to=incident-2026-07-01/prod-web/access.log
sshx -h=prod-web --audit-output=incident-2026-07-01/audit "journalctl -u nginx --since '30 min ago' --no-pager"
```

下载的证据和本地审计元数据会放在同一个事故目录附近。

## 场景 7：安全上传配置

```bash
sshx -h=prod-web --upload=./nginx.conf --to=/tmp/nginx.conf
sshx -h=prod-web "sudo nginx -t -c /tmp/nginx.conf"
sshx -h=prod-web "sudo install -m 0644 /tmp/nginx.conf /etc/nginx/nginx.conf"
sshx -h=prod-web "sudo nginx -t"
sshx -h=prod-web "sudo systemctl reload nginx"
```

先暂存并验证文件，再替换生产配置。

## 场景 8：不同主机使用不同 sudo key

```bash
sshx --password-set=prod-web-sudo
sshx --password-set=prod-db-sudo

sshx -h=prod-web -pk=prod-web-sudo "sudo systemctl reload nginx"
sshx -h=prod-db -pk=prod-db-sudo "sudo systemctl status postgresql"
```

这样一个操作者可以管理多台服务器，而不需要复用一个全局 sudo key。

## 场景 9：验证所有已配置主机

```bash
sshx --host-test-all
```

轮换 key、调整 VPN、导入新的 `settings.json` 后，可以先跑这条命令。

## 场景 10：生成安全状态报告

```bash
for host in prod-web prod-api prod-db; do
  sshx -h="$host" --timeout=20s --json "hostname && uptime" \
    | jq --arg host "$host" '{alias: $host, success, exit_code, error_kind, stdout}'
done
```

脚本读取 JSON 字段，而不是解析自然语言终端输出。

## 场景 11：限制长命令运行时间

```bash
sshx -h=prod-web --timeout=2m "sudo apt-get update"
```

无人值守命令不应该无限挂住。

## 场景 12：诊断 host-key 失败

如果 host key 发生变化，不要先绕过。先确认为什么变化：

```bash
ssh-keygen -F prod-web
ssh-keyscan -H prod-web
```

只有确认机器被重建、重装或按计划轮换后，才更新 `known_hosts`。

## 场景 13：避免管道安装脚本

这种模式风险很高：

```bash
sshx -h=prod-web "curl -fsSL https://example.invalid/install.sh | sh"
```

更安全的模式：

```bash
sshx -h=prod-web "curl -fsSL https://example.invalid/install.sh -o /tmp/install.sh"
sshx -h=prod-web "less /tmp/install.sh"
sshx -h=prod-web "sha256sum /tmp/install.sh"
sshx -h=prod-web "sh /tmp/install.sh"
```

## 场景 14：只在必要时使用 PTY

```bash
sshx -h=prod-web --pty "sudo visudo -c"
```

脚本中优先使用非 PTY，因为它能保持 stdout 和 stderr 分离。

## 场景 15：单次敏感运行禁用审计

如果命令文本本身会暴露敏感上下文，可以只对这一次禁用审计，并在自己的 runbook 中记录原因。

```bash
SSHX_NO_AUDIT=true sshx -h=prod-web "echo redacted"
```

不要把它作为默认值。审计事件对事后解释很有用。

## 场景 16：不打开 Shell 也能检查 Docker

```bash
sshx -h=prod-web --json "docker ps --format '{{json .}}' | head -20"
sshx -h=prod-web "docker inspect nginx --format '{{.State.Status}} {{.RestartCount}}'"
```

这样可以收集容器状态，而不需要进入交互式 SSH，也不需要复制大量日志。

## 场景 17：发布前校验部署产物

```bash
sshx -h=prod-web --upload=./dist/app.tar.gz --to=/tmp/app.tar.gz
sshx -h=prod-web "sha256sum /tmp/app.tar.gz"
sshx -h=prod-web "tar -tzf /tmp/app.tar.gz | head"
```

只有 checksum 和压缩包内容都符合发布说明后，才继续安装。

## 场景 18：带回滚点地轮换服务配置

```bash
sshx -h=prod-web --upload=./service.env --to=/tmp/service.env.new
sshx -h=prod-web "sudo cp /etc/myapp/service.env /etc/myapp/service.env.bak.\$(date +%Y%m%d%H%M%S)"
sshx -h=prod-web "sudo install -m 0600 /tmp/service.env.new /etc/myapp/service.env"
sshx -h=prod-web "sudo systemctl restart myapp"
sshx -h=prod-web --json "systemctl is-active myapp"
```

备份、权限安装、重启和健康检查是分开的可见步骤，出错时更容易定位。

## 场景 19：收集最小支持包

```bash
mkdir -p support/prod-web
sshx -h=prod-web --download=/etc/os-release --to=support/prod-web/os-release
sshx -h=prod-web --audit-output=support/audit "uname -a"
sshx -h=prod-web --audit-output=support/audit "df -h"
sshx -h=prod-web --audit-output=support/audit "free -m"
```

除非支持工单明确需要，不要下载应用私有数据。

## 场景 20：远程参数像本地参数时使用 `--`

```bash
sshx -h=prod-web -- docker run --rm alpine:3.20 sh -c 'echo hello'
sshx -h=prod-web -- echo --force belongs-to-the-remote-command
```

`--` 可以明确区分本地 `sshx` 参数和远程命令参数，避免把远程参数误当成本地开关。

## 场景 21：共享前先测试新的主机条目

```bash
sshx --host-add --host-name=staging-api -h=10.0.8.21 -u=deploy -i=~/.ssh/staging.pem -pk=staging-api-sudo
sshx --host-test=staging-api
sshx -h=staging-api --dry-run --json "sudo systemctl reload api"
```

只有命名主机能解析、能认证，并且选择了预期 sudo key 后，才把 runbook 共享出去。

## 场景 22：给迁移操作设置边界

```bash
sshx -h=prod-db --timeout=10s --json "pg_isready"
sshx -h=prod-db --timeout=5m --dry-run --json "sudo systemctl restart postgresql"
sshx -h=prod-db --timeout=5m -pk=prod-db-sudo "sudo systemctl restart postgresql"
sshx -h=prod-db --timeout=30s --json "pg_isready"
```

每一步都有时间上限，也都有机器可读结果。

## 场景 23：带证据地删除临时文件

```bash
sshx -h=prod-web --list=/tmp
sshx -h=prod-web --rm=/tmp/app.tar.gz
sshx -h=prod-web --list=/tmp
```

删除前后都应该可见。高风险路径优先把文件移动到带日期的隔离目录，而不是直接永久删除。

## 场景 24：让 CI 失败时默认关闭

```bash
result="$(sshx -h=prod-web --timeout=20s --json "systemctl is-active nginx")"
printf '%s\n' "$result" | jq .
printf '%s\n' "$result" | jq -e '.success == true and .stdout == "active\n"'
```

当结构化结果缺失、命令失败或服务状态不符合 runbook 预期时，CI 会直接失败。
