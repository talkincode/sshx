# 主机管理

命名主机把重复的 SSH 信息变成短名称。它适合管理多台服务器、每台服务器使用不同 SSH key、或者 agent 需要稳定主机清单的场景。

## 添加主机

交互式添加：

```bash
sshx --host-add
```

命令行添加：

```bash
sshx --host-add \
  --host-name=prod-web \
  -h=192.168.1.100 \
  -p=22 \
  -u=deploy \
  -i=~/.ssh/prod-web.pem \
  -pk=prod-web-sudo \
  --host-desc="Production web node" \
  --host-type=linux
```

之后用别名执行命令：

```bash
sshx -h=prod-web "hostname && uptime"
```

## 配置文件

主机定义保存在 `~/.sshx/settings.json`。

```json
{
  "key": "/Users/alice/.ssh/id_rsa",
  "hosts": [
    {
      "name": "prod-web",
      "description": "Production web node",
      "host": "192.168.1.100",
      "port": "22",
      "user": "deploy",
      "key": "/Users/alice/.ssh/prod-web.pem",
      "password_key": "prod-web-sudo",
      "type": "linux"
    }
  ]
}
```

顶层 `key` 是默认 SSH 私钥。单个 host 的 `key` 只覆盖这一台主机。

## 日常主机命令

```bash
# 列出已配置主机
sshx --host-list

# 测试单台主机
sshx --host-test=prod-web

# 测试所有主机，每台使用独立拨号超时
sshx --host-test-all

# 更新主机
sshx --host-update --host-name=prod-web -u=deploy -i=~/.ssh/prod-web-2026.pem

# 删除主机
sshx --host-remove=old-lab
```

## 实用命名方式

主机名最好同时说明环境和角色：

```text
prod-web-1
prod-db-primary
staging-api
lab-router
customer-a-jump
```

password key 不要暴露敏感拓扑。共享 runbook 中尽量使用占位符：

```bash
sshx -h=prod-web -pk=<sudo-key> "sudo systemctl reload nginx"
```

## 团队和 agent 使用

对人类来说，命名主机减少输入错误。对自动化 agent 来说，它提供稳定边界：

- agent 收到的是 `prod-web`，不是裸 IP 和 key 路径。
- 操作者可以审阅 `~/.sshx/settings.json`。
- `--dry-run --json` 可以确认真实会使用哪个地址、端口、用户、key 和 sudo key。
- 审计事件可以记录解析后的主机，但不保存 secret。
