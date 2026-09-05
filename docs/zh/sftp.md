# SFTP 工作流

## 计划与副作用证据

SFTP 与主机间传输支持 `--dry-run --json`、`--expect-plan`、
`--host-timeout`、`--global-timeout`。dry-run 离线且不写状态；
绑定公开端点/操作与本地上传 payload，不绑定尚未读取的远端内容或递归目录成员。

使用 `--json` 消费真实 CLI 操作结果、共享执行身份、`effects`、`change_state`、
可空 `executed` 和验证状态。大小/元数据证据不是内容摘要保证。
下载即使远端为 `risk=read` 也标记本地写入；中转读取源端、写入目的端。

操作结果包含 `entries`、`bytes_transferred`、`partial` 和恒为 false 的
`directory_atomic`。条目记录路径/类型/大小/mode、复制字节数、开始/发布状态
与验证；内容校验过的文件复制另有 `source_sha256` / `sha256`。
错误以 `staging_path` / `cleanup_error` 保留已知暂存/清理证据；
应读取条目实际验证，不能假定列目录等操作也有内容哈希。

上传/中转逐文件暂存后发布；覆盖已有远端目的地需要受支持的原子替换，
不可用时失败而不删除原目的地。新目的地可用普通 SFTP rename 发布。
下载在本地目的地同目录暂存，并使用本地 OS 的 rename 语义；不把 POSIX 保证套用到
Windows。断连后可能无法清理远端暂存，结果会报告。
发布方法为 `posix_rename`、新文件 `sftp_rename_no_replace` 和下载
`local_rename`。文件成功验证包含复制后回读 SHA-256 与元数据；mkdir 验证类型/
存在，remove 验证不存在，list 只提供元数据。目录后续条目失败时，部分结果仍保留
此前已发布条目的证据。

受支持的单文件暂存也不提供目录整体原子性、任意写入者 CAS 或自动回滚。
失败/中断的递归传输可能已经产生部分目的地副作用，重试前应检查状态。
详见[计划、结果与安全重试](execution-contract.md)。

`sshx` 支持常见的一次性 SFTP 操作。它不是交互式文件管理器；每次调用只做一个明确的上传、下载、列目录、创建目录或删除操作。

## 上传文件

```bash
sshx -h=prod-web --upload=./deploy/nginx.conf --to=/tmp/nginx.conf
```

覆盖已有远程文件并需要备份/哈希前置条件时，用 [受控文件 Apply](apply.md)，不要自己拼 upload + `install`：

```bash
sshx apply -h=prod-web --path=/etc/nginx/nginx.conf --from=./deploy/nginx.conf --sudo --json
sshx run --target=prod-web --json -- "sudo nginx -t"
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
