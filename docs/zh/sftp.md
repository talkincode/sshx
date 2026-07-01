# SFTP 工作流

`sshx` 支持常见的一次性 SFTP 操作。它不是交互式文件管理器；每次调用只做一个明确的上传、下载、列目录、创建目录或删除操作。

## 上传文件

```bash
sshx -h=prod-web --upload=./deploy/nginx.conf --to=/tmp/nginx.conf
```

生产环境更安全的模式：

```bash
# 先上传到临时路径
sshx -h=prod-web --upload=./deploy/nginx.conf --to=/tmp/nginx.conf

# 检查后再移动到正式位置
sshx -h=prod-web "sudo install -m 0644 /tmp/nginx.conf /etc/nginx/nginx.conf"
sshx -h=prod-web "sudo nginx -t"
sshx -h=prod-web "sudo systemctl reload nginx"
```

## 下载文件

```bash
sshx -h=prod-web --download=/var/log/nginx/error.log --to=./error.log
```

事故材料采集示例：

```bash
mkdir -p incident-2026-07-01/prod-web
sshx -h=prod-web --download=/var/log/nginx/error.log --to=incident-2026-07-01/prod-web/error.log
sshx -h=prod-web --download=/etc/os-release --to=incident-2026-07-01/prod-web/os-release
```

## 列目录与创建目录

```bash
sshx -h=prod-web --list=/var/log
sshx -h=prod-web --mkdir=/tmp/sshx-upload
```

## 删除远程文件

```bash
sshx -h=prod-web --rm=/tmp/old-upload.txt
```

把远程删除当成生产变更。建议先列出父目录：

```bash
sshx -h=prod-web --list=/tmp
sshx -h=prod-web --rm=/tmp/old-upload.txt
```

## 路径边界

本地路径遵循本地操作系统规则。远程路径是 SFTP 路径，应使用斜杠分隔；即使 `sshx` 在 Windows 上运行也一样。

```bash
# 本地 Windows 路径，远程 POSIX 路径
sshx -h=prod-web --upload=C:\Users\alice\release.zip --to=/tmp/release.zip
```

## 什么时候改用 SSH 命令

当操作需要远程校验或权限变更时，使用 SSH 命令：

```bash
sshx -h=prod-web "sudo ls -l /etc/nginx"
sshx -h=prod-web "sudo install -m 0644 /tmp/nginx.conf /etc/nginx/nginx.conf"
```

SFTP 负责文件移动。远程命令负责检查、改属主、reload 服务和需要 sudo 的清理。
