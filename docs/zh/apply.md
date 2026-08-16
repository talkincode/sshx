# 受控文件 Apply

`sshx apply` 替换一个远程正则文件。它是文件版的 `sshx sql`：判断目标、检查哈希前置条件、写备份，然后原子替换。服务校验和 reload 不属于这条命令。

```bash
sshx apply -h=prod-web --path=/etc/nginx/nginx.conf --from=./nginx.conf \
    --expect-sha256=<current> --sudo --json
```

## Apply 做什么

1. 拒绝非干净绝对路径、目录、符号链接和设备节点。
2. 默认阻断 `/etc/passwd`、`/etc/shadow`、`/etc/sudoers`，除非显式 `--force --bypass-reason=`。
3. 读取现有文件，并在提供 `--expect-sha256` 时做前置校验。
4. 除非 `--no-backup --force`，否则把原文复制到 `~/.sshx/file-backups/`。
5. 在同目录写临时文件，保留权限和所有者，再 rename 覆盖目标。
6. 返回 `changed`、`before_sha256`、`after_sha256`、`backup.path` 和 `completion`。

如果远程内容已经与 payload 一致，apply 以 `changed=false` 成功，且不写备份。

## 特权路径

SFTP 以 SSH 用户身份运行。目标对该用户不可写时使用 `--sudo`。sshx 先把 payload 暂存到远端 home，再通过 stdin 执行特权安装脚本；脚本不会留在主机上。

校验和 reload 用另一次 `sshx run`：

```bash
sshx run --target=prod-web --json -- "sudo nginx -t"
sshx run --target=prod-web --json -- "sudo systemctl reload nginx"
```

## 预览

```bash
sshx apply -h=prod-web --path=/etc/nginx/nginx.conf --from=./nginx.conf --dry-run --json
```

dry-run 只哈希本地文件并打印本地计划，不连接、不改远程文件。

## 什么时候继续用 SFTP

只搬字节、不需要备份合同时用 `--upload` / `--download`。会覆盖已有远程文件、需要哈希、备份和可判定的 `changed` 时用 `apply`。
