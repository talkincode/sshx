# 安全准则

远程执行影响很大。这些规则必须严格执行，因为一个小错误就可能修改生产系统、泄露凭据，或掩盖事故的真实原因。

## 不可妥协的规则

1. 保持严格 host-key 校验。
2. 密码保存到 OS keyring，或显式启用的加密本地保险库，不放进明文文件、shell history、工单或聊天记录。
3. sudo 密码只通过 stdin 传入，绝不拼进命令字符串。
4. `--force`、`--no-safety-check`、`--insecure-hostkey` 都是例外的 break-glass 选择。
5. 对特权或破坏性操作先跑 `--dry-run`。
6. 自动化使用 `--json` 和明确的退出码判断。
7. 记住命令安全检查不是沙箱。

## 生产环境策略

对生产环境、共享 runbook、CI 作业和 agent 驱动操作，把下面这些当成策略，而不是建议：

- 使用命名主机，让审阅者能看清目标。
- 每个无人值守命令都设置 `--timeout`。
- 项目、迁移、发布和事故操作使用 `--audit-output`。
- 特权变更前必须先跑 `--dry-run --json`。
- 可绑定时用 `--expect-plan` 固定已审核输入，不为使预览可绑定而放松身份/信任。
- 重试超时/取消或失败变更前，检查 `change_state`、可空 `executed`、验证与备份
  证据。本地连接停止或进程退出成功，都不能单独证明远端状态。
- 不要把 `--force` 和 `--no-safety-check` 写进可复用脚本。
- 不要把 `--insecure-hostkey` 写进可复用脚本或 CI。
- 从聊天、工单或网页复制来的命令，必须先结合目标主机和回滚方案审阅。
- 优先使用分阶段写入：上传到 `/tmp`，验证后再用明确权限和属主安装。
- 不可逆动作尽量一条命令一个可见步骤，避免用 `&&` 串起大量特权变更。
- 影响生产时，在自己的 runbook 中记录维护窗口、操作者、命令、结果和回滚判断。

不要通过 shell profile、CI 变量或共享 `.env` 把弱安全参数变成全局默认值。break-glass 绕过必须只作用于单次命令，并且容易移除。
风险是描述而非授权：未知命令/脚本即使声明 `--intent=read` 也默认为 mutation。
普通 dry-run 不读取秘密或写状态；计划哈希不是远端锁，指纹不是审计签名。
详见[计划、结果与安全重试](execution-contract.md)。

## Host-Key 信任

默认行为会防止未知或变更的 host key。使用下面的安全路径：

```bash
# 推荐：审阅目标后显式加入 host key
ssh-keyscan -H prod-web >> ~/.ssh/known_hosts

# 对受控主机接受首次信任
sshx --accept-unknown-host -h=prod-web "uptime"
```

避免：

```bash
sshx --insecure-hostkey -h=prod-web "uptime"
```

不安全 host-key 模式只适合短期受控实验环境，并且要明确记录风险。不要把它写进默认脚本或共享 runbook。

## Secret 处理

使用交互式 keyring 存储：

```bash
sshx --password-set=prod-web-sudo
```

避免内联 secret：

```bash
sshx --password-set=prod-web-sudo:plain-text-password
```

内联值可能泄露到 shell history、终端滚屏、进程列表、日志或复制出去的命令里。

Keyring password key 用于 sudo 自动填充。`SSH_PASSWORD` 是 SSH 登录密码，应视为高风险 fallback，而不是正常操作模式。

无桌面、没有可用钥匙链的主机必须显式选择保险库：

```bash
export SSHX_SECRET_BACKEND=local-vault
export SSHX_VAULT_PASSPHRASE='…'
sshx --password-set=prod-web-sudo
```

本地保险库不会展示秘密值（`--password-get` 被拒绝）。sshx 经 stdin 注入。不要静默把秘密写成 JSON 文件。

## Sudo 规则

只有远程命令以 `sudo` 开头时，`sshx` 才会自动填充 sudo：

```bash
sshx -h=prod-web -pk=prod-web-sudo "sudo systemctl reload nginx"
```

下面这些不会触发自动填充：

```bash
sshx -h=prod-web "sh -c 'sudo whoami'"
sshx -h=prod-web "echo sudo"
```

这个边界让密码查询、stdin 注入和审计字段都遵循同一条清晰规则。

## 安全检查只是护栏

`sshx` 会拦截常见破坏性操作，例如删除根目录、格式化磁盘、关机重启、修改关键系统文件、fork bomb 和 `curl | sh` 这类管道。

判定对象是**真正要执行的命令**，而不是命令串里出现的危险词。sshx 先做 shell 分段，只判断处于命令位的 token，因此只读诊断不会被误拦：

```bash
sshx -h=prod-web "last reboot -F | head -10"                  # 放行：reboot 是参数
sshx -h=prod-web "journalctl -u app | grep -iE 'fail|halt'"   # 放行：halt 是 grep 模式
sshx -h=prod-web "sudo iptables-save | grep -F 10.0.0.0/24"   # 放行：是另一个程序
sshx -h=prod-web "sudo iptables -F"                           # 拦截：清空规则链
```

包装器会被穿透解析：`sudo`、`env`、`nohup`、`timeout`、`sh -c '...'` 以及 `docker exec <容器> ...` 都会一路解析到最终执行的命令。

这并不代表不可信命令就安全了。命令校验器不可能理解所有脚本、shell 展开、应用迁移和业务数据删除路径。

绕过检查前：

```bash
sshx -h=prod-web --dry-run --json "sudo systemctl reboot"
sshx -h=prod-web --force "sudo systemctl reboot"
```

先确认：

- 目标主机是否正确？
- 命令是否被审阅？
- 是否有维护窗口？
- 是否有回滚方案？
- 绕过原因是否被记录？

只要有一个答案是“否”，就先停下来修 runbook。`--force` 的含义应该是“我已经为这个目标审阅过这条命令”，而不是“让工具别再提醒我”。

## Agent 和自动化规则

自动化应该比人类终端更保守：

- 总是设置 `--timeout`。
- 优先使用 `--json`。
- 解析 `success`、`exit_code` 和 `error_kind`。
- 特权变更前先跑 `--dry-run --json`。
- 不要全局设置 `SSH_INSECURE_HOST_KEY=1`。
- 除非没有更安全路径且生命周期严格受控，否则不要通过环境变量传明文密码。
- 对项目、迁移或事故运行，使用 `--audit-output` 保存审计事件。

## 审计边界

审计事件是本地 JSONL 溯源记录。它记录模式、动作、主机解析、sudo/keyring 决策、安全状态、认证方式、退出码、错误类型和耗时等元数据。

它刻意不记录：

- 明文密码。
- 私钥内容。
- stdout。
- stderr。

命令文本会作为溯源材料写入，并对常见 password/token 类参数做脱敏，但不要因此把 secret 放进命令。

## 探测插件信任与缓存安全

自定义探测插件是 sshx 本地运行目录（通常为 `~/.sshx/plugins/`）拥有的可执行
代码。Agent skill 可以说明如何调用，但不能嵌入或维护采集脚本。

- 新建或修改后的插件默认不可信。先审阅并执行 `plugin validate`、`plugin test`，
  再用 `plugin trust` 准入当前准确摘要。
- 摘要信任不是沙箱。可信采集器会以所选远端用户或 sudo 身份运行，应按已审阅
  脚本对待。
- 插件代码和 sshx 凭据不会持久化到远端；采集器只通过单次 SSH 会话流式执行。
- `--cache=remote-prefer` 必须显式开启，远端只在当前认证用户的
  `~/.sshx/observations/v1/` 保存规范化、已脱敏 JSON。
- 缓存属于不可信输入。格式错误、超限、符号链接、权限过宽、属主不符、身份不符
  或过期的记录都会被拒绝；只有在硬上限内显式请求时才允许复用陈旧记录。
- 不要把环境变量转储、原始 Compose/Nginx 配置、镜像仓库认证、cookie、token、
  私钥或 secret 值放入 facts/evidence。脱敏是纵深防御，不是采集 secret 的许可。

## SFTP 安全

上传到特权路径时，先暂存文件：

```bash
sshx -h=prod-web --upload=./service.conf --to=/tmp/service.conf
sshx -h=prod-web "sudo install -m 0644 /tmp/service.conf /etc/service/service.conf"
```

删除前先列目录：

```bash
sshx -h=prod-web --list=/tmp
sshx -h=prod-web --rm=/tmp/old-file
```

远程 SFTP 路径就是远程路径，不要套用本地操作系统路径规则。

## 事故响应检查表

当情况不对时：

1. 停止用更弱的安全参数反复重试。
2. 记录准确命令、退出码和 `error_kind`。
3. 检查 `~/.sshx/audit` 或指定 `--audit-output` 里的审计事件。
4. 用 `ssh-keygen -F <host>` 验证 host-key 状态。
5. 判断失败发生在 SSH 前、认证阶段、安全校验阶段、命令执行阶段，还是输出收集阶段。
6. 如果 secret 可能进入 shell history、CI 日志、issue 文本或聊天记录，立即轮换相关凭据。

## 共享 Runbook 的好默认值

```bash
sshx -h=<named-host> \
  --timeout=30s \
  --audit-output=./.sshx-audit \
  --dry-run \
  --json \
  "sudo systemctl reload <service>"
```

计划审阅后，再执行真实命令：

```bash
sshx -h=<named-host> \
  --timeout=30s \
  --audit-output=./.sshx-audit \
  -pk=<sudo-key> \
  "sudo systemctl reload <service>"
```
