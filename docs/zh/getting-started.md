# 快速开始

这份指南走一遍安全的首次配置。示例里使用 `prod-web` 作为主机名，请替换成你自己的服务器名称或 IP。

## 安装

如果已经安装 Go：

```bash
go install github.com/talkincode/sshx/cmd/sshx@latest
sshx --version
```

也可以不安装，直接运行指定版本：

```bash
go run github.com/talkincode/sshx/cmd/sshx@latest --help
```

## 先确认 SSH 信任

`sshx` 默认校验 host key。首次连接前建议先把服务器写入 `known_hosts`：

```bash
ssh-keyscan -H prod-web >> ~/.ssh/known_hosts
```

如果你明确接受首次连接信任，可以使用：

```bash
sshx --accept-unknown-host -h=prod-web "uptime"
```

除短期受控实验环境外，不要使用 `--insecure-hostkey`。它会关闭防中间人攻击的主机信任校验。

## 执行第一条命令

```bash
sshx -h=prod-web -u=deploy "uptime"
```

常见变体：

```bash
# 非标准 SSH 端口
sshx -h=prod-web -p=2222 -u=deploy "uptime"

# 指定 SSH key
sshx -h=prod-web -u=deploy -i=~/.ssh/prod-web.pem "uptime"

# 给慢命令设置上限
sshx -h=prod-web --timeout=30s "apt-get update"
```

## 添加命名主机

命名主机把连接信息集中保存在一个本地文件里：

```bash
sshx --host-add --host-name=prod-web -h=192.168.1.100 -u=deploy -i=~/.ssh/prod-web.pem --host-desc="Production web node"
```

之后可以这样使用：

```bash
sshx --host-list
sshx --host-test=prod-web
sshx -h=prod-web "uname -a"
```

配置文件是 `~/.sshx/settings.json`，写入权限为 `0600`。

## 保存 sudo 密码

对于以 `sudo` 开头的命令，`sshx` 可以从 OS keyring 读取密码，并通过 stdin 传给 sudo。

```bash
sshx --password-set=prod-web-sudo
sshx -h=prod-web -pk=prod-web-sudo "sudo systemctl status nginx"
```

建议使用交互式输入。不要使用 `--password-set=key:password` 这种内联值，它可能泄露到 shell history 或进程列表。

## 执行前预览

`--dry-run` 会说明 `sshx` 如何解释这条命令，但不会连接、执行、读取 keyring secret、修改 `known_hosts` 或写主机配置。

```bash
sshx -h=prod-web --dry-run --json "sudo systemctl restart nginx"
```

dry-run 证明本地执行计划，不证明远程命令一定会成功。
