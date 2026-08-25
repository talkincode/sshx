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
  --host-type=linux \
  --bind=en0
```

之后用别名执行命令：

```bash
sshx -h=prod-web "hostname && uptime"
```

## 从 ~/.ssh/config 导入

如果你已经在 OpenSSH 客户端配置里维护主机，可以选择性导入，而不是重新输入。导入默认不会"一键全导"——写入 `~/.sshx/settings.json` 的内容由你决定。

交互式选择：

```bash
sshx --host-import
```

sshx 会列出可导入条目（含解析后的 `user@host:port` 与 key）以及所有被跳过的条目和原因，然后由你按编号、名称或 `all` 选择。

按名称非交互导入（适合脚本 / agent，全部成功或全部失败）：

```bash
sshx --host-import=web1,db1
```

从其他配置文件导入：

```bash
sshx --host-import --ssh-config=~/work/ssh_config
```

预览而不写入：

```bash
sshx --host-import=web1 --dry-run --json
```

每个条目导入的字段：`HostName`（缺省时使用别名本身）、`Port`、`User`、`IdentityFile`（作为该主机的 `key`）、以及 `BindAddress` / `BindInterface`（作为 `bind`；先出现的值生效）。

防污染规则——导入器始终跳过：

- 通配或否定模式（`Host *`、`web-?`、`!pattern`）——它们是规则，不是主机；
- 与 settings 中已有主机同名的条目；
- `host:port` 已存在于 settings（或与同文件中更早条目重复）的条目；
- sshx 不支持的选项（`ProxyJump`、`ForwardAgent` 等）——以 `ignored:` 显示，不会静默丢失；
- 其他块的选项：`Host *` 的默认值绝不会合并进导入条目；
- 含 `%` 令牌的 `IdentityFile`（在提示中说明）。

`Match` 块会被忽略，`Include` 指令不会被跟随；被包含的文件请用 `--ssh-config=<path>` 直接导入。

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
      "type": "linux",
      "bind": "en0"
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

# 修改或清空持久化源地址绑定
sshx --host-update --host-name=prod-web --bind=192.0.2.10
sshx --host-update --host-name=prod-web --bind=

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
