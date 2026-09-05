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

本地信任边界：settings.json / OS keyring 或显式 local vault / known_hosts / audit JSONL
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

- **人类交互登录**

  `sshx login <name> [--sudo]` 把本地 TTY 接到已解析主机上的交互会话；`--sudo` 经 stdin 注入 keyring sudo 秘密后进入特权 login shell。`--json` 仅配合 `--dry-run`。不进入 MCP，不支持多主机。POSIX only。证据：`internal/app/login.go`、`internal/sshclient/login.go`。

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

  密码默认存放在系统 keyring；无桌面环境可显式启用加密本地保险库（`SSHX_SECRET_BACKEND=local-vault`，文件 `$SSHX_HOME/vault`）。保险库只写不读，执行时经 stdin 注入。默认优先 SSH key，只有显式提供 SSH 登录密码时才回退密码认证；命名主机可独立选择 SSH key 和 sudo password key。没有从钥匙链到文件的静默降级。证据：`internal/keyringstore/`、`internal/app/password.go`、`internal/sshclient/client.go`、`tests/e2e/keyring_e2e_test.go`、`tests/e2e/vault_e2e_test.go`。

- **通道信任与动作护栏**

  默认通过 `known_hosts` 严格校验 host key；未知主机接受和不安全校验必须显式开启。明显破坏性命令默认被拦截，`--force` / `--no-safety-check` 是显式绕过。命令位上的 `psql`/`pgcli`/`sqlite3` 被导向 `sshx sql`。证据：`internal/sshclient/client.go`、`internal/sshclient/validate.go`、`internal/sshclient/client_test.go`、`internal/sshclient/validate_test.go`。

- **受控 SQL 执行**

  `sshx sql` 通过远端已有的 `psql` 或 `sqlite3` 执行恰好一条语句：本地 fail-closed 分类、策略门闩、变更前备份、结构化 JSON 与审计。PostgreSQL 另有 EXPLAIN 行数估计、表锁事务备份和容器凭据发现；SQLite 以绝对文件路径为身份，只读走 `file:?mode=ro`，变更在 `BEGIN IMMEDIATE` 下做表 CSV 或整文件 `.backup`。证据：`internal/app/sql.go`、`internal/sqlsafe/`、`tests/e2e/sql_sqlite_e2e_test.go`。

- **受控文件 Apply**

  `sshx apply` 替换一个远程正则文件：绝对路径门闩、可选 `--expect-sha256` 前置条件、默认 owner-only 备份、同目录临时文件 + rename、保留权限/所有者。`--sudo` 先经 SFTP 暂存再特权安装。不包含 nginx -t 或 reload。证据：`internal/app/apply.go`、`internal/sshclient/apply.go`、`tests/e2e/apply_e2e_test.go`。

- **stdio MCP server**

  `sshx mcp` 通过 stdio 提供 Model Context Protocol 工具面：`sshx_run`、`sshx_sql`、`sshx_apply`、`sshx_inspect`、`sshx_sftp`、`sshx_transfer`、`sshx_host_list` 与 CLI 契约 1:1 映射，每次 tool call 以一次性子进程重新进入 sshx，结果就是 CLI 的版本化 JSON；force/bypass_reason 必须显式传参，密码管理不暴露，审计事件带 `entry=mcp` 标记。证据：`internal/app/mcp.go`、`internal/app/mcp_test.go`、`tests/e2e/mcp_e2e_test.go`。

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

- **不做 HTTP/SSE MCP server、守护进程或常驻协议服务。** stdio MCP server（`sshx mcp`）在范围内：它由 MCP 客户端拉起并随会话生灭，每个 tool call 都以一次性子进程重新进入 sshx，复用同一套契约、安全门禁与审计。不得添加 HTTP/SSE 传输、监听端口或任何寿命超过其客户端的服务。

- **不把危险命令防护宣传成沙箱。** sshx 降低误操作和凭据泄露风险，但不承诺安全执行恶意或不可信命令。

- **不成为 CMDB、企业 secret vault 或 SIEM。** sshx 可消费主机配置、使用本地 secret backend、生成审计证据，但不替代组织级资产、密钥和合规平台。

- **不提供明文 secret 存储，也不静默放松 host-key 校验。** 便利性不能突破凭据与通道信任边界。本地保险库必须加密、显式选择，且不得从钥匙链失败自动掉进文件。

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

  默认信任根仍是 OS keyring。无桌面主机的加密本地保险库已在范围内：secret 不落明文、不进入命令字符串、不静默降级、用途可区分，Agent 只引用凭据而非读取凭据。未来若再接入其他 backend，必须保持同一契约，且不得变成组织级 secret 平台。

## 完成的样子

`sshx` 的成功不以支持多少 SSH flag 衡量，而以 Agent 能否用更少步骤完成一次可信远程执行衡量。

- Agent 用一个稳定目标名和一个明确动作即可发起执行，不需要重复处理地址、端口、用户、key、sudo secret 与 host-key 细节。
- dry-run 所展示的目标、动作、安全绕过和副作用，与真实执行及审计记录保持同一语义。
- 人类输出清楚，机器输出稳定；所有一级失败都有可分支的类别，远程命令失败不会与 sshx 自身失败混淆。
- 明显危险动作默认受阻，特权执行与安全绕过显式可见；secret 不出现在普通配置、命令拼接、审计记录或默认终端回显中。
- 多主机执行即使部分失败，也能逐主机说明状态，并避免不受控并发和盲目重试。
- 会修改远端状态的操作能够说明是否执行、是否部分完成以及下一步如何安全判断，而不是只返回一个模糊 EOF 或通用错误。
- 项目继续保持单二进制、无远端驻留组件、无常驻协议服务（stdio MCP 随客户端会话生灭）、无长期控制面的轻量边界。
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

下表记录既有测试覆盖位置，不代表本次工作已在所有 OS/SQL 引擎上执行通过。
特别是通过真实 SSH 调用模拟 SQL 客户端，仍不能证明真实数据库事务正确。
issue #71 的新增边界、验证状态及外部前提单列在后面的证据矩阵。

| 一级功能 | 风险 | 权限 | 修改状态 | Happy Path E2E | 失败路径 | 权限状态覆盖 | 失败恢复/回滚 | 现有证据 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 单次远程命令执行 | 高 | 是 | 可能 | ✅ | ✅ 远端非零/超时/异常断连 | ✅ operator/reader | ✅ 部分完成后重读状态 | `tests/e2e/cli_e2e_test.go` |
| Agent JSON / 退出码契约 | 高 | 否 | 否 | ✅ | ✅ stdout/stderr、远端非零与分类失败 | 不适用：只描述结果 | 不适用：不修改状态 | `tests/e2e/cli_e2e_test.go` |
| dry-run 执行预览 | 中 | 否 | 否 | ✅ | ✅ 组件级无效计划 | 不适用：不获取远端权限 | ✅ 证明零连接、零信任/审计写入 | `tests/e2e/cli_e2e_test.go`、`internal/app/agentmode_test.go` |
| 命名主机管理与 SSH config 导入 | 中 | 否 | 是，本地 | ✅ 导入后按别名执行 | ✅ 选择项缺失 | 不适用：单用户本地配置 | ✅ 失败选择不部分写入 | `tests/e2e/host_audit_e2e_test.go` |
| SFTP 上传/下载/目录操作 | 高 | 是 | 是，远端 | ✅ | ✅ 只读端拒绝写入 | ✅ operator/reader | ✅ 失败上传无目标残留 | `tests/e2e/sftp_e2e_test.go` |
| 远端到远端传输 | 高 | 是，两端 | 是，目的端；源端只读 | ✅ | ✅ 目标端只读 | ✅ 可写/只读目标 | ✅ 失败无残留，改用可写端重试；不证明目录整体回滚 | `tests/e2e/sftp_e2e_test.go` |
| keyring 凭据管理与认证回退 | 高 | 是 | 是，本地 secret | ✅ | ✅ 缺失 secret/公钥被拒 | ✅ key/password-fallback、stored/missing | ✅ 删除后缺失；可重新设置 | `tests/e2e/keyring_e2e_test.go`、`tests/e2e/cli_e2e_test.go` |
| 加密本地保险库 | 高 | 是 | 是，本地 secret | ✅ set/check/sudo 注入 | ✅ get 拒绝、错误口令、过宽权限 | ✅ 0600 可读 / 0644 拒绝 | ✅ 失败写入保留原 vault 字节 | `tests/e2e/vault_e2e_test.go`、`internal/keyringstore/vault_test.go` |
| host-key 校验 | 高 | 是，信任状态 | 可能修改 `known_hosts` | ✅ 显式信任后严格复用 | ✅ 未知/变更 key | ✅ strict/accept-unknown | ✅ 首次写入后重新严格连接 | `tests/e2e/cli_e2e_test.go` |
| 危险动作阻断与显式绕过 | 高 | 是 | 否，仅控制执行准入 | ✅ 显式 `--force` | ✅ 默认阻断且零连接 | ✅ 默认阻断/显式绕过 | 不适用：策略门本身不修改状态 | `tests/e2e/cli_e2e_test.go` |
| 本地结构化审计 | 高 | 否 | 是，本地 | ✅ | ✅ 不可写目标可观测 | 不适用：本地调用者同权 | ✅ 修复目标后单事件写入 | `tests/e2e/host_audit_e2e_test.go` |
| 本地探测插件生命周期 | 高 | 本地调用者权限 | 是，本地 | ✅ create/list/show/validate/test/trust/remove | ✅ 路径逃逸、重复创建、manifest/entrypoint/schema/fixture 分类失败 | ✅ 私有目录/文件权限 | ✅ replace/remove 保留可恢复备份 | `tests/e2e/inspect_plugin_e2e_test.go` |
| Agent Skill 安装 | 高 | 本地调用者权限 | 是，本地 Agent 信任目录 | ✅ 编译后二进制离线安装/幂等复用 | ✅ 内容冲突与 symlink 目标拒绝 | ✅ 默认目录/显式目录 | ✅ 冲突不覆盖，显式 force 后恢复官方版本 | `tests/e2e/skill_e2e_test.go` |
| 单主机探测与内置基线 | 高 | 是 | 否，cache off | ✅ 自定义插件与 `system.baseline` | ✅ 未信任、污染/超限输出、超时、非零退出、不支持平台 | ✅ operator/reader/sudo-required | 不适用：不修改远端状态 | `tests/e2e/inspect_plugin_e2e_test.go`、`tests/e2e/keyring_e2e_test.go` |
| 远端观察缓存 | 高 | 是 | 是，远端 JSON | ✅ 冷写入/热复用/并发原子替换 | ✅ TTL/boot ID、格式、大小、属主、权限、symlink、只读端 | ✅ 可写/只读 SFTP | ✅ 失败写入保留原有效快照 | `tests/e2e/inspect_plugin_e2e_test.go` |
| 有界多主机执行 | 高 | 是 | 可能，多主机 | ✅ `sshx run` 组/标签选择 + concurrency 1/4/8/32 | ✅ fail_fast、部分失败、零匹配 | ✅ operator 密码角色 | ✅ 每个选中目标都有终态事件 | `tests/e2e/run_e2e_test.go`、`internal/execution/*_test.go` |
| 可解释执行治理 | 高 | 是 | 可能 | ✅ run 契约 dry-run/digest/intent/bypass_reason | ✅ blocked、uncertain completion、typed error.kind | ✅ SSH login vs sudo key 分离 | ✅ completion 指导 verify_first/unsafe | `tests/e2e/run_e2e_test.go`、`internal/app/run.go`、`internal/execution` |
| 受控 SQL 执行（SQLite） | 高 | 是 | 是，远端库 | sqlite3 可用时：只读查询与带备份 UPDATE | 直连客户端阻断、ATTACH 分类拒绝、缺路径 | operator SSH 密码角色；非完整 DB 权限矩阵 | UPDATE 前 CSV 可还原旧值；不等于全部失败注入 | `tests/e2e/sql_sqlite_e2e_test.go`、`internal/sqlsafe/*_test.go`、`internal/app/sql_test.go` |
| 受控文件 Apply | 高 | 是 | 是，远端文件 | ✅ 创建/覆盖/幂等 | ✅ 哈希不匹配、符号链接、只读端 | ✅ operator/reader | ✅ 覆盖前备份可还原旧值 | `tests/e2e/apply_e2e_test.go`、`internal/app/apply_test.go`、`internal/sshclient/apply_test.go` |
| stdio MCP 工具面 | 高 | 是 | 可能，经子进程 | ✅ initialize/tools/list/tools/call 真实执行 | ✅ force 缺 bypass_reason 被拒、非法输入本地拒绝 | ✅ operator 密码角色 | ✅ dry-run 零连接；审计 `entry=mcp` 可追溯 | `tests/e2e/mcp_e2e_test.go`、`internal/app/mcp_test.go` |
| 审计查询/导出 | 中 | 否 | 查询无写入；导出写本地目标 | ✅ execute → query by run_id | ✅ 空结果 exit 0 | 不适用：本地调用者 | 不改写源审计文件 | `tests/e2e/host_audit_e2e_test.go`、`internal/app/audit_query_test.go` |
| 受控 SQL（MySQL） | 高 | 是 | 是，远端库 | 真实 SSH + 模拟 mysql 客户端；非真实引擎 | LOAD DATA / INTO OUTFILE 分类拒绝；run-mode mysql 阻断且零连接 | operator SSH 密码角色；非真实 DB 权限验证 | 模拟快照含旧值，不证明真实引擎回滚/原子性 | `tests/e2e/sql_mysql_e2e_test.go`、`tests/e2e/fake_mysql.py`、`internal/sqlsafe/mysql_test.go` |

不能据此声称完整平台/引擎验收已通过。任何一级能力不得只以参数解析或组件测试
作为完成依据；必须补充相应外部边界 E2E，并如实记录不可用环境与未证明的保证。

## Issue 71 execution hardening evidence

本轮是执行原语加固，不是产品扩张；上述非目标不变。公开契约见
[English](execution-contract.md) / [中文](zh/execution-contract.md)。
“测试已存在”与“本次已执行通过”分开，不把跨平台编译、mock 或跳过计为真实验收。

| Requirement / 要求 | In-tree evidence / 仓库证据 | Boundary / 验证边界与前提 |
| --- | --- | --- |
| Canonical plan/risk / 规范计划与风险 | `internal/execution/plan_test.go`、`risk_test.go`、`internal/app/plan_test.go` | 本地向量/准入测试；整个信任记录快照保守失效，不承诺仅相关记录失效 |
| Legacy contract fixtures / 既有契约 fixture | `tests/e2e/contract_golden_e2e_test.go`、`tests/e2e/testdata/contract/` | 7 份增量兼容规范化 v1 JSON/JSONL fixture；不证明真实数据库事务 |
| Bound CLI, offline rejection / 绑定与离线拒绝 | `tests/e2e/plan_e2e_test.go` | 编译后二进制、真实 SSH；DNS、缺公钥/信任、远端 SQL 身份应拒绝绑定；完整各动词矩阵仍需逐项证据 |
| Effect/verification evidence / 副作用验证 | apply / SQL / SFTP 的领域测试与共享元数据 | 未知不可当 false；任意程序副作用、远端状态锁不在保证内 |
| Invocation/target identity / 执行关联 | `internal/execution/lifecycle_test.go`、`tests/e2e/plan_e2e_test.go` | 身份/指纹为脱敏关联，不是签名、防重放或防篡改日志 |
| Deadline/fan-out admission / 期限与准入 | `internal/execution/executor_test.go`、`lifecycle_test.go`、`internal/sshclient/transport_reliability_test.go` | 本地并发/协议故障测试；阈值只停止准入，不保证远端终止 |
| Compiled-binary faults / 二进制故障路径 | `tests/e2e/reliability_e2e_test.go` | 缺失/损坏/加密 key、认证回退、信任损坏/变更/只读、损坏 settings、HOME/USERPROFILE 隔离；不自动证明所有传输阶段、原生 OS 或数据库故障 |
| Apply recovery / 文件恢复 | `tests/e2e/apply_e2e_test.go`、`internal/sshclient/apply_test.go` | 服务端 rename 与 sudo 工具前提；SFTP 不是任意写入者 CAS |
| File transfer effects / 传输副作用 | `tests/e2e/sftp_e2e_test.go` | 单文件/部分目录证据；不承诺目录整体原子回滚或大小即内容相同 |
| SQL CLI engine effects / SQL CLI 效果 | `tests/e2e/reliability_sql_native_e2e_test.go`、SQLite E2E；旧 MySQL 模拟测试另列 | PostgreSQL/MySQL read/update/no-op/zero、备份回读、reader 拒绝/恢复 fixture 已存在；编译后 CLI 原生 opt-in 缺主机 psql/mysql 而失败，仍待 CI/原生客户端 |
| SQL transaction engines / SQL 引擎事务 | `internal/sqlsafe/real_engine_integration_test.go` | 隔离 Docker 中真实 PostgreSQL 17.11 / MySQL 8.4.11：RollbackAndCommit、ConcurrentWriterExcludedFromPreimage 均通过；是生成 SQL/真实客户端/真实服务端组件集成，不是编译 CLI SSH E2E |
| Audit diagnostics / 审计诊断 | `internal/app/audit_query_test.go`、`audit_test.go`、`tests/e2e/host_audit_e2e_test.go` | best-effort 持久化独立于执行结果；损坏行与真实读写错误不可吞掉 |
| MCP parity / MCP 一致性 | `internal/app/mcp_test.go`、`tests/e2e/mcp_e2e_test.go` | stdio 子进程，受 watchdog/进度通道限制；中断流不能伪造完成 |
| Native platforms / 原生平台 | `.github/workflows/ci.yml` 与平台测试 | 原生 Windows 执行、可隔离 keyring、POSIX 权限/信号各自验证；交叉编译不能替代 |

2026-09-05 实现验证记录：macOS 执行器 `go test -race ./internal/execution`
通过，准入/期限/身份/投递选择器重复 20 次通过；后续 peer 身份投影测试验证各字段
变化影响目标及父指纹、执行 ID/计划关联保持稳定且 ToResult 保留同一元数据，
并再次通过 executor race。这些是确定性 barrier、fake/cancel-aware
dialer 与执行观测映射的组件证据，不涉及外部 SSH 认证、真实数据库或原生 Windows。
文档/帮助的 `go test ./internal/app -run '^TestPrintUsage' -count=1` 也已通过。
SQL 包 race、真实 SQLite 事务/证据测试与该范围 lint 已通过；
SQLite 的本地证据本身不证明 PostgreSQL/MySQL，后者证据另列。
传输范围 `go test -race ./internal/sshclient`、Transport/SFTPReliability/
TransferReliability race 选择器重复 5 次通过，范围 lint 为 0 issues。
`transport_reliability_test.go` 覆盖 loopback 协议取消、rekey、信任/签名 pin、
输出上限、权限、短复制恢复、缺原子原语、部分目录和双端中转取消；Windows 仅
测试交叉编译，不代表原生 Windows，也不证明引擎/审计/MCP 边界。
该记录不扩展为全部外部边界或所有平台已通过。
可靠性实现环境中 Windows 仅交叉编译与平台 lint，原生执行等待 CI。Windows CI
选择的 Portable/Reliability/ContractGolden/CLI 认证、streams、failures、safety、
dry-run、skill 子集已在 macOS 通过；不能算原生 Windows 通过。冻结 golden/认证/信任
也在未修改 HEAD 快照上通过；settings 测试与 plugin/skill/keyring race 测试通过。
MCP 范围的 app 定向测试与 `tests/e2e` 的全部 `TestMCP` 生产二进制测试已在
macOS 通过；Windows/Linux app-test 仅完成交叉编译，不能据此宣称原生 MCP 验证。
审计范围完整 race 测试已在集成代码上通过（无临时 overlay 替换），覆盖查询诊断、
部分有效记录、执行关联与 apply/SQL 证据保留。
编译后 CLI 的原生 PostgreSQL/MySQL opt-in 曾因缺少本地 `psql` / `mysql`
失败，没有回退到 fake；该 CLI SSH E2E 范围仍待 CI/原生客户端。
随后通过会话独占、无网络的 Docker fixture 和 `docker exec` 客户端适配器，
运行实际 PostgreSQL 17.11 / MySQL 8.4.11，两个引擎的
`TestSQLRealEngineRollbackAndCommit` 与
`TestSQLRealEngineConcurrentWriterExcludedFromPreimage` 均通过。
这是生成 SQL、真实客户端、真实服务器及隔离前镜像文件的组件集成，
不是 mock，也不是编译后 CLI 跨 SSH E2E。没有使用生产资源或源码挂载。
macOS 原生 keyring 只有明确隔离 fixture、且默认与唯一
搜索列表 keychain 同时匹配才允许测试，不触碰用户日常钥匙链。

可按需要运行现有选择器，而不是为文档修改启动全套测试：

```bash
go test ./internal/app -run '^TestPrintUsage' -count=1
go test ./internal/execution -run 'Test.*(Plan|Risk|Lifecycle|Failure)' -count=1
```

具体引擎/平台测试的命令、是否跳过和外部服务前提，应随实现验证记录更新；
MySQL 保证限于受支持策略与实际验证的 rollback/commit、并发写入案例，
不能推广为所有语句/引擎或整个 CLI 流程的通用原子性。

### Native SQL prerequisites

CI 的 `sql-native` job 提供 PostgreSQL 16、MySQL 8.4 和 native `psql` /
`mysql` / `sqlite3` 客户端。本地只能指向可销毁的 loopback 测试服务，不能使用生产库。

- Compiled CLI / 编译后 CLI：`SSHX_E2E_REAL_SQL=1`，明确设置测试专用
  `SSHX_E2E_PG_PASSWORD` / `SSHX_E2E_MYSQL_PASSWORD`；fixture 使用
  `127.0.0.1:5432`（用户 `sshx`）和 `127.0.0.1:3306`（用户 `root`），
  两者数据库均为 `sshx_e2e`。启用后缺客户端或服务应失败，不回退为模拟测试。
- Engine transactions / 引擎事务：`SSHX_SQL_INTEGRATION_POSTGRES=1` 或
  `SSHX_SQL_INTEGRATION_MYSQL=1`，并设置
  `SSHX_SQL_INTEGRATION_{DATABASE,USER,HOST,PORT,PASSWORD}` 指向独立测试数据库。
  SQLite 使用真实本地客户端；其他引擎未显式启用时跳过，不计为通过。

```bash
# Only after provisioning disposable services and explicit test credentials:
SSHX_E2E_REAL_SQL=1 go test ./tests/e2e -run '^TestSQLRealEngineReliability$' -count=1
go test ./internal/sqlsafe -run 'TestSQLRealEngine(RollbackAndCommit|ConcurrentWriterExcludedFromPreimage)' -count=1
```
