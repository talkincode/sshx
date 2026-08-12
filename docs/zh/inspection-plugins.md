# 主机探测能力与本地插件

Agent 初次接触服务器时，往往需要反复检查 Docker、Compose、路由、DNS、
网卡、防火墙和资源状态，还需要判断“没有结果”究竟是服务不存在，还是权限
不足。`sshx inspect` 将这些探索收敛为一次有版本、可校验的结构化调用。

## 内置系统能力

稳定的操作系统能力直接内置在 sshx 中：

- `system.identity`
- `system.resources`
- `system.baseline`
- `network.interfaces`
- `network.routes`
- `network.dns`
- `network.listeners`
- `network.firewall`

一次采集完整基线：

```bash
sshx inspect -h=prod-web system.baseline --json
```

结果是 `sshx.observation/v1` JSON 文档。`status` 明确区分 `complete`、
`partial`、`unsupported` 和 `failed`；权限不足不会被误报成服务不存在。

## 插件属于 sshx 运行目录

应用级采集器是 sshx 的本地运行资产，不放在 Agent skill 中，也不会安装到
远端服务器：

```text
~/.sshx/
├── settings.json
├── audit/
├── plugins/
│   └── <plugin-id>/
│       ├── manifest.json
│       ├── collectors/
│       ├── result.schema.json
│       ├── README.md
│       └── fixtures/
├── plugin-lock.json
└── observations/
```

可通过 `SSHX_HOME` 替换默认的 `~/.sshx`，用于项目、Agent 或 CI 隔离；
settings、audit、plugins 和 lock 都跟随同一个运行根目录。

## 创建自定义插件

`plugin create` 会生成可直接编辑和验证的完整骨架：

```bash
sshx plugin create private.environment \
  --runner=sh \
  --platform=linux \
  --privilege=optional \
  --template=generic \
  --json
```

模板包括 `generic`、`docker` 和 `nginx`。Docker 模板采集安装与 daemon
状态、版本、Docker 根目录、存储/cgroup 驱动、容器、镜像、端口、网络、
挂载以及 Compose project/工作目录/配置路径。默认不采集容器环境变量、
registry auth、`.env` 内容、Secret 值或 Compose 文件正文。

插件 API v1 使用面向 Linux 或 Darwin 目标的 `sh` runner。sshx 控制端仍保持
跨平台；未来的 Windows 目标 runner 必须先补充明确执行与测试契约，不能把
PowerShell 静默当成 POSIX shell。

`--replace` 会先把旧插件移动到 `~/.sshx/plugin-backups/`；`plugin remove`
同样采用可恢复移动，而不是直接永久删除。

## 校验、测试与信任

```bash
sshx plugin validate private.environment --json
sshx plugin test private.environment --fixture=complete --json
sshx plugin test private.environment --json
sshx plugin trust private.environment --json
sshx plugin show private.environment --json
sshx plugin list --json
```

`validate` 检查 manifest、路径、文件类型与权限、入口、JSON Schema、超时、
权限声明、缓存策略和副作用声明。`test` 可以校验 fixture，也可以显式在本地
最小环境中执行采集器，并限制 stdout/stderr 大小。

新建或修改后的本地插件默认不可信。`plugin trust` 将 manifest、入口和 schema
摘要写入 `plugin-lock.json`；以后任何修改都会改变摘要，`inspect` 会在建立 SSH
连接前拒绝执行，直到新摘要再次得到显式信任。信任不是沙箱：可信插件仍拥有
SSH 身份允许的权限，因此信任前必须审查内容。

## 远端临时执行，不安装脚本

```bash
sshx inspect -h=prod-web private.environment --json
```

sshx 在本地解析并校验插件，然后通过固定的 `sh -s --` SSH 会话把采集器送入
stdin。stdout 必须是唯一一份符合 schema 的 JSON；sshx 随后脱敏并补充目标、
来源和新鲜度信息。采集器不会持久安装到远端，也不会获得 SSH 或 keyring 密钥。

manifest 的权限策略为：

- `never`：禁止 `--sudo`。
- `optional`：默认普通用户，确有需要时显式增加 `--sudo`。
- `required`：sshx 解析对应 sudo key，并把密码和采集器内容分离送入 stdin。

执行前可以预览完整边界：

```bash
sshx inspect -h=prod-web private.environment \
  --cache=remote-prefer \
  --dry-run \
  --json
```

预览包含插件路径、摘要、信任状态、目标解析、权限、是否读取 secret、是否执行、
known_hosts 影响以及是否写观察快照，全程不连接远端。

## 有有效期的远端观察快照

缓存必须显式启用：

```bash
sshx inspect -h=prod-web private.environment \
  --cache=remote-prefer \
  --max-age=10m \
  --json
```

远端只在当前用户的 `~/.sshx/observations/v1/` 保存规范化、已脱敏 JSON，
插件代码仍然只在本地。目录和文件仅属主可访问，并使用原子替换。

只有 capability ID/版本/摘要、schema、参数、host-key 指纹、平台、认证 UID、
boot ID 和权限范围全部一致时，快照才可复用。TTL 到期或 `--refresh` 会重新采集；
`--allow-stale` 只是显式允许返回匹配但过期的快照，不会伪装成新鲜数据。

缓存始终按不可信输入处理：路径中的软链接、宽松权限、属主不符、超大文件、
畸形 JSON、schema 不匹配和身份漂移都会失败关闭，而不是被当成当前事实。

这只是观察缓存，不是 CMDB：不提供跨主机搜索、资产归属、期望状态、持续
收敛，也不声称它是权威资产库。
