# sshx 项目画像与方向

> **SSH is the channel. X is execution.**
>
> **SSH 是通道，X 代表执行。**

## 项目定位

`sshx` 是一个**面向 Agent 的远程主机执行工具**。它以 SSH/SFTP 作为已有、成熟、普遍可达的可信通道，把 Agent 的执行意图转换为一次边界清楚、结果可判断、过程可审计的远程主机操作。

这一定义刻意把产品重心从“SSH 客户端”移到“远程执行”上：

- **SSH 是通道**：负责连接、认证、加密、主机身份校验和文件传输，但不是 sshx 的全部产品价值。
- **X 是执行**：负责目标解析、执行预览、安全检查、命令或文件动作、结果结构化、失败分类和审计留痕。
- **Agent 是首要调用者**：CLI 不是纯人类交互界面，而是一份稳定的进程级工具契约；人类运维者与 Agent 共用同一套目标、安全和审计语义。

一句话定位：

> **让 Agent 通过 SSH，高效、安全、可审计地在远程主机上完成任务。**

英文定位：

> **Agent-native remote execution over SSH.**

## 项目概述

Agent 操作远程主机时，真正的困难通常不在“能否建立 SSH 连接”，而在于如何稳定地回答以下问题：目标是哪台主机、使用什么身份、将执行什么、是否越过安全边界、执行是否成功、失败发生在哪一层、事后能否解释这次操作。`sshx` 应把这些重复且高风险的细节收敛为一个短命令和一份稳定结果。

项目保持单二进制、跨平台、无远端驻留组件的形态。每次调用解析目标和约束，建立 SSH/SFTP 连接，执行一个明确动作，返回结果并退出；本地配置、系统 keyring、`known_hosts` 和审计记录共同构成执行所需的最小信任环境。

```text
Agent / 自动化 / 人类运维者
           |
           v
    Agent 契约层
    - CLI / JSON / 退出码 / error_kind
    - dry-run / timeout / audit context
           |
           v
      X 执行层
    - 目标发现与解析
    - 动作分类与安全检查
    - 命令、SFTP、主机间传输
    - 结果归一化与审计留痕
           |
           v
     SSH 通道层
    - 加密连接与认证
    - host-key 信任
    - SSH exec / SFTP
           |
           v
        远程主机

本地信任边界：settings.json / OS keyring / known_hosts / audit JSONL
```

## 项目画像（目标状态）

`sshx` 做好之后，应成为 Agent 工具箱里的“远程执行基本件”：像调用本地进程一样容易组合，又明确承认远程操作具有凭据、权限、网络和破坏性副作用。Agent 不需要模拟交互式终端，不需要从自然语言日志猜测结果，也不需要在每个任务中重新拼装 SSH 参数、sudo 注入、安全检查和审计逻辑。

### 效率画像

效率不是单纯缩短 SSH 握手时间，而是减少 Agent 完成一次可靠远程操作所需的决策、调用和返工：

- **意图表达短**：命名主机和可复用配置把地址、端口、用户、key 与 sudo key 收敛到稳定目标名。
- **一次调用闭环**：发现或解析目标、执行动作、返回结构化结果、形成审计记录，不要求 Agent 维持交互会话。
- **机器判断直接**：stdout、stderr、退出码、`success` 与 `error_kind` 各自职责稳定，Agent 不依赖脆弱文本匹配。
- **执行前少返工**：dry-run 能在连接、读取 secret 或修改状态前暴露目标解析、sudo、安全绕过和副作用意图。
- **失败后快恢复**：错误能区分配置、连接、认证、host-key、超时、命令退出和安全阻断，避免盲目重试。
- **数据移动少落地**：远端到远端传输可以流式中转，不要求先写入本地磁盘。

### 安全画像

安全不是一句“危险命令检测”，而是一组贯穿执行生命周期的边界：

- **凭据边界**：secret 默认进入 OS keyring，不进入配置、命令字符串、审计记录或普通终端回显。
- **通道边界**：默认严格校验 host key，未知或变更的远端身份不会被静默接受。
- **权限边界**：SSH 登录身份与 sudo secret 语义分离；特权执行必须可识别、可预览、可追溯。
- **动作边界**：明显破坏性操作默认阻断；绕过必须显式且进入结果与审计上下文。
- **副作用边界**：Agent 在执行前能知道动作是否会连接、读取 secret、修改本地状态或修改远端状态。
- **责任边界**：记录足够解释“谁通过什么入口，对哪台主机，以何种安全上下文做了什么，结果如何”，同时默认不持久化敏感输出。

安全、正确性与可审计性高于便利和吞吐；在发生冲突时，宁可要求调用者显式表达意图，也不静默降级信任边界。效率优化必须减少无意义摩擦，但不能用模糊目标、隐式凭据选择或不可解释的并发换速度。

### 产品边界画像

`sshx` 是执行工具，不是远程主机上的 Agent，也不是持续运行的控制平面。它应在现有 SSH 基础设施上提供一个清晰的 Agent 执行契约，而不是要求每台服务器安装新服务。它可以支持受控的批量执行和更强的执行描述，但不承担期望状态管理、工作流编排、资产治理或组织级审批系统的全部职责。

## 当前能力清单

- **单次远程命令执行**

  支持 `sshx -h=<host> [options] <command>`，默认不启用 PTY，保持 stdout/stderr 分离，并透传远程命令退出码。支持 timeout、显式 PTY 和 sudo stdin 注入。证据：`internal/app/app.go`、`internal/app/config.go`、`internal/sshclient/client.go`、`internal/sshclient/runcommand_test.go`。

- **Agent 结构化结果契约**

  `--json` 输出单个 JSON 对象，包含成功状态、退出码、输出、耗时、认证方式和 `error_kind`；sshx 自身失败与远程命令失败可以区分。证据：`internal/app/app.go`、`internal/app/agentmode_test.go`、`internal/app/usage.go`。

- **执行计划预览**

  `--dry-run` 在建立连接、执行动作、读取 keyring secret、更新 `known_hosts` 或写配置前生成本地执行计划；可与 `--json` 组合供 Agent 判断。证据：`internal/app/dryrun.go`、`internal/app/agentmode_test.go`、`internal/app/transfer_test.go`。

- **命名主机发现与管理**

  `~/.sshx/settings.json` 保存命名主机、地址、端口、用户、key 和 password key；支持增删改查、单台或全量连接测试，并可从 `~/.ssh/config` 选择性、全有或全无地导入合格主机。配置写入使用私有权限和原子替换。证据：`internal/app/settings.go`、`internal/app/host_manager.go`、`internal/app/sshconfig.go`、`internal/app/settings_test.go`、`internal/app/sshconfig_test.go`。

- **SFTP 与主机间文件执行动作**

  支持上传、下载、列表、建目录、删除，以及两台远端主机之间经本机流式中转的文件或目录传输。证据：`internal/sshclient/client.go`、`internal/sshclient/transfer.go`、`internal/app/transfer.go`、`internal/app/transfer_test.go`。

- **凭据与认证边界**

  密码存放在系统 keyring；默认优先 SSH key，只有显式提供 SSH 登录密码时才回退密码认证；命名主机可独立选择 SSH key 和 sudo password key。证据：`internal/app/password.go`、`internal/sshclient/client.go`、`internal/sshclient/client_test.go`。

- **通道信任与动作护栏**

  默认通过 `known_hosts` 严格校验 host key；未知主机接受和不安全校验必须显式开启。明显破坏性命令默认被拦截，`--force` / `--no-safety-check` 是显式绕过。命令位上的 `psql`/`pgcli`/`sqlite3` 被导向 `sshx sql`。证据：`internal/sshclient/client.go`、`internal/sshclient/validate.go`、`internal/sshclient/client_test.go`、`internal/sshclient/validate_test.go`。

- **受控 SQL 执行**

  `sshx sql` 通过远端已有的 `psql` 或 `sqlite3` 执行恰好一条语句：本地 fail-closed 分类、策略门闩、变更前备份、结构化 JSON 与审计。PostgreSQL 另有 EXPLAIN 行数估计、表锁事务备份和容器凭据发现；SQLite 以绝对文件路径为身份，只读走 `file:?mode=ro`，变更在 `BEGIN IMMEDIATE` 下做表 CSV 或整文件 `.backup`。证据：`internal/app/sql.go`、`internal/sqlsafe/`、`tests/e2e/sql_sqlite_e2e_test.go`。

- **本地结构化审计**

  非 dry-run 调用默认写入本地 JSONL 审计事件，记录目标、动作、安全上下文、结果和耗时，排除 stdout/stderr，并对命令中的 secret-like 参数做尽力脱敏。证据：`internal/app/audit.go`、`internal/app/audit_test.go`。

- **内置主机环境探测**

  `sshx inspect` 用一次 SSH 连接返回带来源、权限、目标身份和新鲜度的观察结果；内置系统身份、资源、网卡、路由、DNS、监听端口、防火墙和组合基线能力。证据：`internal/app/inspect.go`、`internal/plugin/builtin.go`、`tests/e2e/inspect_plugin_e2e_test.go`。

- **sshx 本地插件生命周期**

  Agent 可通过 `sshx plugin create` 在 `~/.sshx/plugins/`（或 `$SSHX_HOME/plugins/`）创建 Docker、Nginx 或自定义应用探测插件，并完成 list/show/validate/test/trust/remove。插件脚本不由 Agent skill 维护；摘要变化会使信任失效。证据：`internal/app/plugin.go`、`internal/plugin/`、`tests/e2e/inspect_plugin_e2e_test.go`。

- **有界远端观察快照**

  显式启用 `--cache=remote-prefer` 后，仅把规范化、已脱敏 JSON 保存到远端用户 `~/.sshx/observations/v1/`。复用绑定插件版本/摘要、host key、平台、UID、boot ID、权限、参数与 TTL；缓存作为不可信输入校验，使用私有权限和原子替换。证据：`internal/app/inspect.go`、`internal/plugin/observation.go`、`internal/sshclient/remote_state.go`、`tests/e2e/inspect_plugin_e2e_test.go`。

- **跨平台交付**

  项目以单二进制形式面向 Linux、macOS 和 Windows，支持 Go 安装、安装脚本、Release 产物和 Homebrew tap。证据：`Makefile`、`.github/workflows/ci.yml`、`.github/workflows/release.yml`、`install.sh`、`install.ps1`。

## 非目标（铁律）

- **不把 SSH 本身重新实现一遍。** 不追求交互式 shell 复用、通用端口转发、SOCKS、X11 或 agent forwarding；SSH 是底层通道，不是功能竞赛对象。

- **不在远端安装驻留 Agent 或插件运行时。** 不引入守护进程、后台服务、连接池或常驻控制面；采集器只在单次 SSH 会话中流式执行。远端可显式保存有版本、有时效的被动 JSON 观察结果，但不保存插件代码或可执行运行时。

- **不成为 Ansible、Salt 或工作流引擎。** 可以提供有界的多主机执行，但不引入期望状态语言、playbook 生态、调度系统或长期任务编排。

- **不在核心二进制内重新引入 MCP server。** CLI 和进程级结构化契约是稳定集成面；需要 MCP 或其他协议时，应由外部适配层调用 sshx，而不是扩张核心运行模型。

- **不把危险命令防护宣传成沙箱。** sshx 降低误操作和凭据泄露风险，但不承诺安全执行恶意或不可信命令。

- **不成为 CMDB、企业 secret vault 或 SIEM。** sshx 可消费主机配置、使用本地 secret backend、生成审计证据，但不替代组织级资产、密钥和合规平台。

- **不提供明文 secret 存储，也不静默放松 host-key 校验。** 便利性不能突破凭据与通道信任边界。

- **不做 GUI/TUI。** 核心交互面保持为 flags、stdin、stdout、stderr、退出码和结构化文件；图形化体验属于外部工具。

- **不为了局部平台能力牺牲跨平台一等支持。** Linux、macOS 和 Windows 的核心执行契约必须保持一致。

## 方向与意图

- **把“执行单元”变成稳定产品契约**

  每次执行都应能明确表达目标、动作、约束、副作用、安全上下文和结果。无论动作是命令、文件操作还是未来的批量执行，Agent 都能用同一套心智模型预览、执行、判断和审计，而不需要理解内部 SSH 细节。

- **降低复杂命令与脚本的传递损耗**

  远程命令经本地 shell、参数解析和远端 shell 多层解释时容易发生引用、通配和变量展开损坏。sshx 应让 Agent 能可靠传递复杂执行内容，并保持“实际执行内容”在 dry-run、审计和结果中的语义一致；具体输入形态由实现阶段选择。

- **建立有界的多主机执行能力**

  Agent 应能对主机集合执行同一检查或动作，并得到逐主机、可聚合、可部分失败的结构化结果。并发必须有界，目标集合必须可预览，失败不能被总成功状态吞掉；该方向服务于执行效率，但不演变成持续编排平台。

- **从命令黑名单走向可解释的执行治理**

  在现有危险命令防护之外，逐步增强动作分类、只读与变更意图表达、安全绕过原因、调用来源或 run ID 等上下文，使人类审批层或上层 Agent 能基于明确证据决策。治理信息不得伪装成绝对安全保证。

- **强化目标与身份的可发现性**

  主机导入、列表、分组、标签、连接健康和凭据引用应让 Agent 快速找到正确目标，同时避免把基础设施秘密复制到更多位置。规模化体验仍以简单、可审阅、可迁移的本地配置为底线。

- **把重复探索收敛为可复用探测能力**

  固定的操作系统与网络事实由二进制内置，Docker、Nginx 和私有应用由 sshx 运行目录中的本地插件表达。每个能力都应有严格 manifest、结果 schema、摘要信任、权限策略、脱敏与有效期，让 Agent 先读可信的新鲜观察，再决定是否重新探测，而不是跨任务重复拼装命令。

- **提升失败恢复效率**

  连接、认证、host-key、权限、超时、远程退出、部分传输和本地持久化失败应拥有稳定分类与足够上下文。对于会修改状态的动作，结果需要帮助调用者判断“未开始、部分完成、已完成但回执异常”，减少危险重试。

- **扩展文件与受控网络边界执行**

  继续完善递归文件操作、传输完整性和失败恢复；在需要进入私有网络时，可考虑受控的 jump-host 能力，但不得扩展成通用隧道产品，也不得模糊每一跳的 host-key 与认证决策。

- **保持 secret backend 可演进**

  默认信任根仍是 OS keyring。未来若接入其他 secret backend，必须保持 secret 不落明文、不进入命令字符串、不静默降级、用途可区分，并让 Agent 只引用凭据而非读取凭据。

## 完成的样子

`sshx` 的成功不以支持多少 SSH flag 衡量，而以 Agent 能否用更少步骤完成一次可信远程执行衡量。

- Agent 用一个稳定目标名和一个明确动作即可发起执行，不需要重复处理地址、端口、用户、key、sudo secret 与 host-key 细节。
- dry-run 所展示的目标、动作、安全绕过和副作用，与真实执行及审计记录保持同一语义。
- 人类输出清楚，机器输出稳定；所有一级失败都有可分支的类别，远程命令失败不会与 sshx 自身失败混淆。
- 明显危险动作默认受阻，特权执行与安全绕过显式可见；secret 不出现在普通配置、命令拼接、审计记录或默认终端回显中。
- 多主机执行即使部分失败，也能逐主机说明状态，并避免不受控并发和盲目重试。
- 会修改远端状态的操作能够说明是否执行、是否部分完成以及下一步如何安全判断，而不是只返回一个模糊 EOF 或通用错误。
- 项目继续保持单二进制、无远端驻留组件、无核心 MCP server、无长期控制面的轻量边界。
- Agent 能在 sshx 运行目录快速创建、测试和信任应用探测插件；skill 只维护调用方法，不维护插件脚本。
- 常见系统/网络或应用部署探索可在一次调用中形成可复用观察，且陈旧、身份漂移或不可信缓存不会被静默采用。
- 每项一级能力都有覆盖真实 CLI 与真实 SSH/SFTP 边界的验收证据；安全与状态修改路径同时覆盖失败和恢复语义。

## 验收矩阵（业务能力覆盖矩阵）

> 覆盖底线（硬性规定）：
>
> 1. 每个一级功能至少有一条 Happy Path E2E。
> 2. 每个高风险功能至少覆盖一条失败路径。
> 3. 每个涉及权限的功能至少验证两种角色或权限状态。
> 4. 每个会修改系统状态的操作至少验证一次失败后的恢复或回滚。
> 5. 每次新增一级业务功能，必须同步新增对应 E2E 并更新本矩阵。

当前仓库已建立 `tests/e2e` 编译后二进制验收套件：测试进程通过真实 TCP SSH/SFTP 协议连接隔离服务端，并从进程退出码、stdout/stderr、JSON、远端文件/状态、`known_hosts`、settings、keyring 和审计 JSONL 观察结果。默认 keyring 场景使用仅在 `sshx_e2e` 构建标签下启用的隔离后端；macOS CI 还会创建临时系统 Keychain，验证生产二进制跨真实 OS keyring 的完整生命周期。组件测试不计作 CLI E2E，表内证据按实际边界标注。

| 一级功能 | 风险 | 权限 | 修改状态 | Happy Path E2E | 失败路径 | 权限状态覆盖 | 失败恢复/回滚 | 现有证据 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 单次远程命令执行 | 高 | 是 | 可能 | ✅ | ✅ 远端非零/超时/异常断连 | ✅ operator/reader | ✅ 部分完成后重读状态 | `tests/e2e/cli_e2e_test.go` |
| Agent JSON / 退出码契约 | 高 | 否 | 否 | ✅ | ✅ stdout/stderr、远端非零与分类失败 | 不适用：只描述结果 | 不适用：不修改状态 | `tests/e2e/cli_e2e_test.go` |
| dry-run 执行预览 | 中 | 否 | 否 | ✅ | ✅ 组件级无效计划 | 不适用：不获取远端权限 | ✅ 证明零连接、零信任/审计写入 | `tests/e2e/cli_e2e_test.go`、`internal/app/agentmode_test.go` |
| 命名主机管理与 SSH config 导入 | 中 | 否 | 是，本地 | ✅ 导入后按别名执行 | ✅ 选择项缺失 | 不适用：单用户本地配置 | ✅ 失败选择不部分写入 | `tests/e2e/host_audit_e2e_test.go` |
| SFTP 上传/下载/目录操作 | 高 | 是 | 是，远端 | ✅ | ✅ 只读端拒绝写入 | ✅ operator/reader | ✅ 失败上传无目标残留 | `tests/e2e/sftp_e2e_test.go` |
| 远端到远端传输 | 高 | 是，两端 | 是，两端 | ✅ | ✅ 目标端只读 | ✅ 可写/只读目标 | ✅ 失败无残留，改用可写端重试 | `tests/e2e/sftp_e2e_test.go` |
| keyring 凭据管理与认证回退 | 高 | 是 | 是，本地 secret | ✅ | ✅ 缺失 secret/公钥被拒 | ✅ key/password-fallback、stored/missing | ✅ 删除后缺失；可重新设置 | `tests/e2e/keyring_e2e_test.go`、`tests/e2e/cli_e2e_test.go` |
| host-key 校验 | 高 | 是，信任状态 | 可能修改 `known_hosts` | ✅ 显式信任后严格复用 | ✅ 未知/变更 key | ✅ strict/accept-unknown | ✅ 首次写入后重新严格连接 | `tests/e2e/cli_e2e_test.go` |
| 危险动作阻断与显式绕过 | 高 | 是 | 否，仅控制执行准入 | ✅ 显式 `--force` | ✅ 默认阻断且零连接 | ✅ 默认阻断/显式绕过 | 不适用：策略门本身不修改状态 | `tests/e2e/cli_e2e_test.go` |
| 本地结构化审计 | 高 | 否 | 是，本地 | ✅ | ✅ 不可写目标可观测 | 不适用：本地调用者同权 | ✅ 修复目标后单事件写入 | `tests/e2e/host_audit_e2e_test.go` |
| 本地探测插件生命周期 | 高 | 本地调用者权限 | 是，本地 | ✅ create/list/show/validate/test/trust/remove | ✅ 路径逃逸、重复创建、manifest/entrypoint/schema/fixture 分类失败 | ✅ 私有目录/文件权限 | ✅ replace/remove 保留可恢复备份 | `tests/e2e/inspect_plugin_e2e_test.go` |
| Agent Skill 安装 | 高 | 本地调用者权限 | 是，本地 Agent 信任目录 | ✅ 编译后二进制离线安装/幂等复用 | ✅ 内容冲突与 symlink 目标拒绝 | ✅ 默认目录/显式目录 | ✅ 冲突不覆盖，显式 force 后恢复官方版本 | `tests/e2e/skill_e2e_test.go` |
| 单主机探测与内置基线 | 高 | 是 | 否，cache off | ✅ 自定义插件与 `system.baseline` | ✅ 未信任、污染/超限输出、超时、非零退出、不支持平台 | ✅ operator/reader/sudo-required | 不适用：不修改远端状态 | `tests/e2e/inspect_plugin_e2e_test.go`、`tests/e2e/keyring_e2e_test.go` |
| 远端观察缓存 | 高 | 是 | 是，远端 JSON | ✅ 冷写入/热复用/并发原子替换 | ✅ TTL/boot ID、格式、大小、属主、权限、symlink、只读端 | ✅ 可写/只读 SFTP | ✅ 失败写入保留原有效快照 | `tests/e2e/inspect_plugin_e2e_test.go` |
| 有界多主机执行 | 高 | 是 | 可能，多主机 | ✅ `sshx run` 组/标签选择 + concurrency 1/4/8/32 | ✅ fail_fast、部分失败、零匹配 | ✅ operator 密码角色 | ✅ 每个选中目标都有终态事件 | `tests/e2e/run_e2e_test.go`、`internal/execution/*_test.go` |
| 可解释执行治理 | 高 | 是 | 可能 | ✅ run 契约 dry-run/digest/intent/bypass_reason | ✅ blocked、uncertain completion、typed error.kind | ✅ SSH login vs sudo key 分离 | ✅ completion 指导 verify_first/unsafe | `tests/e2e/run_e2e_test.go`、`internal/app/run.go`、`internal/execution` |
| 受控 SQL 执行（PostgreSQL / SQLite） | 高 | 是 | 是，远端库 | ✅ sqlite 只读查询与带备份 UPDATE | ✅ 直连客户端阻断、ATTACH 分类拒绝、缺路径 | ✅ operator 密码角色 | ✅ UPDATE 前 CSV 可还原旧值 | `tests/e2e/sql_sqlite_e2e_test.go`、`internal/sqlsafe/*_test.go`、`internal/app/sql_test.go` |

当前已达到已实现一级能力的覆盖底线。表中的剩余红项属于尚未实现的方向能力，而不是用组件测试掩盖的既有质量债。未来任何一级能力不得只以参数解析或组件测试作为完成依据；必须沿用编译后二进制边界补充 E2E，并同步更新本矩阵。
