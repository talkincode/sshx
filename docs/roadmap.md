# sshx 项目画像与方向

## 项目概述

`sshx` 是一个单二进制、跨平台的 SSH/SFTP 命令行工具，面向需要频繁操作多台远程服务器的人和自动化 agent。它的核心价值是：一次命令完成远程执行或文件操作，密码和 sudo 凭据交给系统密钥链保管，常用服务器可用短名称访问。

项目的运行方式保持简单：每次调用读取 CLI 参数、环境变量和可选的主机配置，建立一条直连 SSH 会话，完成命令或 SFTP 操作后退出。它不是后台服务，也不维护长期连接。

```text
用户 / 脚本 / AI agent
        |
        v
cmd/sshx/main.go
        |
        v
internal/app
  - 参数解析、命令分发
  - 主机配置管理 ~/.sshx/settings.json
  - 密码管理与 keyring 交互
        |
        v
internal/sshclient
  - SSH 连接与认证
  - host-key 校验
  - 远程命令执行 / SFTP
  - sudo stdin 注入与危险命令拦截
        |
        +--------------------+
        |                    |
        v                    v
远程 SSH/SFTP 服务        OS keyring / known_hosts
```

## 项目画像（目标状态）

`sshx` 做好之后，应当是一个可以被人类终端和自动化系统共同信任的远程操作工具：人类使用时命令短、反馈清楚、默认安全；agent 使用时输出稳定、退出码可判断、失败原因可机读；事后排查时能追溯关键操作的来源、目标、结果和安全上下文。

项目优先级是：安全默认值、数据正确性和可审计溯源优先于便利性；清晰的单次调用语义优先于复杂的长期会话能力；跨平台一致性优先于某个平台的深度特性。任何新能力都应服务于“一次调用、明确结果、低认知负担、事后可解释”的体验。

安全设计不是附加功能，而是产品边界。默认行为应保护 host-key、凭据和 sudo 密码路径；绕过安全检查必须显式、可见，并且不应让用户误以为 `sshx` 是不可信命令的沙箱。审计溯源也应遵守同一边界：记录足够解释操作链路的元数据，但不把 secret、sudo 密码、私钥内容或高敏 stdout/stderr 写进日志。

## 当前能力清单

- SSH 命令执行

  支持 `sshx -h=<host> [options] <command>`，默认直连远程主机并执行一次命令；远程命令退出码会透传为 `sshx` 自身退出码。证据：`cmd/sshx/main.go`、`internal/app/app.go`、`internal/sshclient/client.go`、`internal/app/usage.go`。

- Agent / 脚本模式

  `--json` 会在 stdout 输出单个结构化 JSON 对象，包含 `exit_code`、`success`、`stdout`、`stderr`、`duration_ms`、`auth_method`、`error_kind` 等字段；stderr 仍用于诊断信息。证据：`internal/app/app.go`、`internal/app/usage.go`、`skills/sshx/SKILL.md`。

- 命令超时与 PTY 选择

  `--timeout` 可限制远程命令运行时间；默认不使用 PTY，以保持 stdout/stderr 分离，`--pty` 仅在需要终端语义时显式启用，且不能与 `--json` 组合。证据：`internal/app/config.go`、`internal/app/app.go`、`internal/sshclient/client.go`。

- SFTP 文件操作

  支持上传、下载、列目录、创建目录、删除远程路径等单次 SFTP 操作。证据：`internal/app/config.go`、`internal/sshclient/client.go`、`internal/app/usage.go`。

- 系统密钥链密码管理

  密码存储在系统 keyring 服务 `sshx` 下，支持设置、检查、获取、删除和常见 key 探测；交互式终端上 `--password-get` 不直接打印明文密码，只有管道或重定向时输出原始值。证据：`internal/app/password.go`、`internal/sshclient/validate.go`、`CHANGELOG.md`。

- 命名主机配置

  `~/.sshx/settings.json` 保存主机短名称、地址、端口、用户、描述、系统类型、每主机 SSH key 和密码 key；支持添加、更新、列表、连接测试、全量连接测试和删除。配置写入采用临时文件加 rename 的方式，并设置为 `0600`。证据：`internal/app/settings.go`、`internal/app/host_manager.go`、`internal/app/usage.go`。

- 认证路径

  默认先尝试 SSH key，服务端拒绝 key 后可回退到密码；也支持 `--no-key` / `--password-only` 强制密码模式。每个命名主机可有自己的 SSH key 和 password key。证据：`internal/sshclient/client.go`、`internal/app/host_manager.go`、`skills/sshx/SKILL.md`。

- host-key 校验

  默认使用 `known_hosts` 严格校验主机 key；未知主机或变更 key 会阻止连接。`--accept-unknown-host` 和 `--insecure-hostkey` 是显式 opt-in。证据：`internal/sshclient/client.go`、`AGENT.md`。

- sudo 密码自动填充

  识别以 `sudo` 开始的命令后，从 keyring 读取密码，并通过 stdin 传入 `sudo -S -p ''`，不把密码拼进命令字符串。证据：`internal/sshclient/client.go`、`internal/sshclient/validate.go`。

- 危险命令防护

  默认拦截一组明显破坏性命令，例如删除根目录、格式化磁盘、fork bomb、`curl | sh`、关机重启和关键系统文件覆盖；`--force` 或 `--no-safety-check` 可显式绕过。证据：`internal/sshclient/validate.go`、`internal/app/app.go`、`internal/app/usage.go`。

- 构建、发布和质量守护

  Makefile 提供构建、测试、覆盖率、lint、跨平台编译和安装目标；CI 在 Ubuntu 和 macOS 上使用 Go 1.24 运行测试、race、覆盖率、lint 和安全扫描；release workflow 在 tag push 时构建 Linux、macOS、Windows 产物并生成 checksums。证据：`Makefile`、`.github/workflows/ci.yml`、`.github/workflows/release.yml`、`RELEASE.md`。

## 非目标（铁律）

- 不重新引入 MCP server、`mcp-stdio` 模式或 MCP tools。`sshx` 的产品形态是 CLI。

- 不引入守护进程、后台服务、连接池或长期会话管理。每次命令都应建立连接、执行、退出。

- 不做 GUI 或 TUI。交互面保持在 flags、stdout、stderr 和机器可读 JSON。

- 不做完整 OpenSSH 替代品。不覆盖交互式登录 shell 复用、端口转发、隧道、SOCKS proxy、X11 forwarding 或 agent forwarding。

- 不提供明文 secret 存储。凭据默认只进入 OS keyring；inline password 只能作为高风险便利入口存在，并应持续被明确提示。

- 不扩展出新的私有配置格式。配置边界是 CLI flags、环境变量、`.env` 和 `~/.sshx/settings.json`。

- 不把危险命令防护宣传成安全沙箱。它只能拦截常见误操作，不能承诺执行不可信命令是安全的。

- 不把审计能力做成企业 SIEM、集中式合规平台或不可篡改账本。`sshx` 可以提供结构化溯源材料，但不承担组织级审计系统的全部职责。

- 不为了局部平台特性牺牲 Linux、macOS、Windows 的一等支持。

## 方向与意图

- 提升核心路径可信度

  命令执行、认证回退、host-key 校验、sudo stdin、settings 原子写入、JSON 契约和 SFTP 操作是项目的负重路径。未来改动应让这些路径更容易被测试守护、更容易定位失败，而不是扩大不受控行为面。

- 改善命名主机的规模化体验

  当用户管理的主机数量增加时，`--host-list`、连接测试和配置编辑需要更易扫描、更少出错。标签、分组、丰富列表输出或更顺手的编辑体验都属于这个方向，但必须保持 `settings.json` 简单、可审阅、可迁移。

- 让密码 key 发现和命名更一致

  现有 keyring API 限制导致 `--password-list` 只能探测常见 key。未来方向是减少“密码存在但用户不知道 key 名”的摩擦，同时不引入明文索引、不泄露基础设施命名、不破坏系统 keyring 作为信任根的边界。

- 强化 agent 友好契约

  `--json`、退出码、`error_kind`、stdout/stderr 分离和 timeout 是 agent 使用的核心契约。后续能力应尽量让程序可以分支处理失败，而不是解析自然语言日志。

- 扩展 SFTP 的实用范围

  递归上传/下载、glob 等能力可以提升文件操作效率。扩展时应保持“一次调用完成一个明确操作”的语义，不把 SFTP 做成长期交互式文件管理器。

- 支持多主机 fan-out 操作

  在不引入 daemon 或连接池的前提下，允许对多个命名主机执行同一类检查或命令，并输出聚合报告。这是 `--host-test-all` 思路的自然延伸，目标是 fleet 级可观察结果，而不是长期编排系统。

- 支持受控的跳板访问

  对私有网络主机，ProxyJump 风格能力可以降低运维摩擦。该方向必须保持 host-key 校验、认证路径和错误报告清晰，不能演变成通用隧道或代理产品。

- 建立可审计溯源能力

  对执行过的操作形成结构化溯源材料，应成为重点方向。记录对象应优先覆盖时间、调用入口、人类/脚本/agent 可识别来源、目标主机、解析后的命名主机、远程用户、认证方式、host-key 决策、命令或 SFTP 意图、是否使用 sudo、是否绕过安全检查、退出状态、错误类别和耗时。审计应默认不记录 secret，不捕获敏感 stdout/stderr，且不改变一次调用即退出的模型。

- 让审计材料可被本地排查和自动化系统消费

  审计结果应兼顾人读和机器处理，能够与 `--json` 契约、退出码和 `error_kind` 对齐。未来能力应让用户可以回答“这次操作从哪里来、实际打到了哪台机器、用了什么凭据路径、为什么失败或成功”，而不是只能翻自然语言终端输出。

- 允许 secret backend 演进但不放松信任边界

  如果未来支持可插拔 secret backend，默认仍应是 OS keyring，并且所有 backend 都必须遵守“不落明文、不经命令字符串传 sudo 密码、不静默降级”的原则。

## 完成的样子

`sshx` 的路线图不是以功能数量衡量，而是以远程操作是否更可靠、更可判断、更不容易误伤来衡量。当人和 agent 都能在多数日常服务器操作中用一次命令得到明确结果，并且安全边界没有被便利性侵蚀，项目方向才算成立。

- 核心执行契约稳定

  人类模式下输出清楚，agent 模式下 stdout 可直接解析；远程命令失败和 `sshx` 自身失败可以稳定区分；timeout、认证失败、host-key 失败、危险命令阻断都有可观察、可分支的结果。

- 凭据和 host-key 路径没有绕路

  密码仍由系统 keyring 管理，sudo 密码仍只通过 stdin 传递，host-key 默认严格校验；任何绕过都必须是显式选择，且用户能从命令或输出上看出来。

- 主机配置适合小团队和个人长期维护

  `settings.json` 可读、权限正确、写入安全；主机越多时，用户仍能快速知道每个主机使用的地址、用户、key、password key 和连接状态。

- 自动化使用不会依赖脆弱文本解析

  重要状态应通过退出码、JSON 字段或稳定结构表达。自由文本日志可以辅助人读，但不能成为 agent 判断成败的唯一依据。

- 关键操作可审计、可回看、可解释

  对远程命令、SFTP 操作、host-key 信任变更、安全检查绕过和配置变更，应能形成结构化记录或等价的溯源材料。记录能支持本地排查和自动化汇总，同时不泄露 secret，不默认持久化高敏命令输出。

- 新能力没有突破 CLI-only 边界

  即使支持更多主机、更强 SFTP 或跳板访问，项目仍保持单二进制、单次调用、无后台服务、无 GUI/TUI、无 MCP 的形态。

- 质量守护跟得上风险

  安全相关逻辑、认证分支、配置写入、JSON 契约、SFTP 行为和跨平台差异应有自动化检查守护。具体测试形式可按代码实际选择，但关键回归应能在本地 `make check` 或 CI 中被挡下。
