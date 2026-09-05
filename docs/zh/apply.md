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
6. 返回哈希/备份证据、`change_state`、可空 `executed`、`verified`、
   `verification`、条件与 `completion`，同时兼容原 `changed` / `created`。

如果远程内容已经与 payload 一致，apply 以 `changed=false` 成功，且不写备份。

## 验证与并发边界

失败时使用共享 `change_state`（`changed|unchanged|unknown`），不能把原布尔值
`changed=false` 当作无写入证明。no-op 可以未写入而已验证、未变更。
写后 `verification_failed` 可能表示替换已经发生，但回读失败或摘要不同：
重试前检查 before/after/payload 哈希与已知 `backup.path`。备份不是自动回滚。
`backup.verified` 表示备份回读/哈希验证；`rollback_available` 要求该验证，
而非仅有路径。它仍不是已测试恢复或自动回滚。
自有暂存文件尽力清理；`cleanup_pending` 列出中断/清理失败后可能残留的路径，
任何删除前应先检查。

| 观测 | 执行/变更证据 |
| --- | --- |
| 内容已一致 | `executed=false`、`change_state=unchanged`、`verified=true` |
| 发布已确认，必需回读失败 | `executed=true`、`completion=completed`、`change_state=changed`；操作验证失败 |
| rename 确认丢失 | `executed=null`、`completion=unknown`、`change_state=unknown`；先检查再重试 |

尝试发布时，`replace_method` 标明 `posix_rename`、`sftp_rename` 或特权
`same_directory_mv`；不能推断比报告方法更强的原语保证。

临近替换时复查哈希，但 SFTP 不提供针对任意并发写入者的通用原子
compare-and-swap。原子 rename 依赖服务端原语，SSH 成功不能证明
delete-then-create 安全或文件系统持久化。特权 apply 同样需要有效回读报告，
不能只依靠退出码 0。
POSIX-rename 扩展返回 `SSH_FX_OP_UNSUPPORTED` 时可尝试普通 rename，
但目标已存在时可能失败；不会以 delete-then-create 绕过该失败。

`--force` 保留原哈希前置条件绕过、备份/关键路径批准含义，不能绕过 `--expect-plan`。

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
需严格绑定本地审核与执行时，检查嵌套 `sshx.plan.v1` / `plan_hash`，再以
`--expect-plan="$reviewed_hash"` 执行。payload 字节与公开身份/信任必须一致；
远端内容由明确前置条件约束，不由计划隐式冻结。
详见[计划、结果与安全重试](execution-contract.md)。

## 什么时候继续用 SFTP

只搬字节、不需要备份合同时用 `--upload` / `--download`。需要哈希、备份和明确
变更/验证证据（包括失败后的不确定性）时用 `apply`。
