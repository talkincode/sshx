# 计划、结果与安全重试

本文描述 issue #71 的增量执行加固契约。既有参数、intent/force 含义、结果信封、
退出码和 JSONL 事件名称保持兼容。兼容政策见[契约冻结策略](contract.md)，
验证证据与外部前提见[验收矩阵](../roadmap.md#issue-71-execution-hardening-evidence)。

## 审核并绑定本地计划

非交互 command、`run`、`apply`、`sql`、SFTP、transfer、`inspect` 预览增加
嵌套 `plan`（`schema_version: "sshx.plan.v1"`）、`plan_hash` 和 `risk`。
run 预览仍保留外层 `sshx.request.v1`。

```bash
sshx run --target=prod-web --script-file=./deploy.sh --dry-run --json
# 审核 plan.bindable、plan.unresolved、risk、effects、targets、inputs。
# 原样传入已审核的 sha256:<64 位小写十六进制>：
sshx run --target=prod-web --script-file=./deploy.sh \
  --expect-plan="$reviewed_hash" --json
```

`--expect-plan` 是可选参数，在 secret 查询或网络操作前比对本次准备的计划。
它不是审批服务，调用方必须保护已审核哈希。格式错误为 `config`，哈希不同为
`plan_mismatch`，哈希相同但不可绑定为 `plan_unresolved`。`--force` 不能绕过
计划比对；拒绝时仍可写入正常的脱敏审计事件。

普通 `--dry-run` 始终**离线、不读取 secret、不写状态**：不写审计、信任、
缓存或 payload 暂存文件。它只读取公开配置、公钥/信任材料与本地 payload，
不读取私钥，也不向 secret backend 查询秘密值。

### 哈希绑定什么

哈希是规范化语义 JSON 投影的 `sha256:`，不是渲染后预览文本的哈希。
目标和 map 键排序；有语义的命令/脚本/SQL 字节保持原样；时长规范为整数纳秒。
schema 与执行语义版本属于投影的一部分。

纳入的输入包括端点角色、地址/用户/端口/源绑定、公有凭据身份与角色引用、
信任快照、payload 摘要/长度、解释器/PTY/权限、路径与写入目的地、
SQL 分类/身份/备份策略、插件摘要/缓存策略、安全绕过、条件以及有效执行/失败限制。
ID、时间、格式、审计目录、原始输出、密码和私钥不属于计划语义。
相同快照字节定义操作时，payload 本地来源路径不是身份；下载目的地则属于身份。
`selector_digest` 仍只描述选择结果，不能代替完整计划绑定。

**信任失效采取保守策略：**当前实现排序并哈希选定 `known_hosts` 文件中
**全部**非空、非注释记录，而非仅目标主机相关记录。因此修改无关信任记录也可能
使旧计划失效。绑定执行使用已准入的信任快照，不重新打开可变文件。

### 哪些预览不能绑定

- 仅有 DNS 名称的目标：离线预览不解析或冻结 DNS 答案，需使用明确的 IP。
- key 认证缺少可用的 `<私钥路径>.pub`：预览不会读取私钥来推导公钥。
  真正加载的 signer 必须与准入公钥指纹一致。
- 信任材料缺失/不可读、peer 不受信任，或使用放宽信任参数
  `--accept-unknown-host` / `--insecure-hostkey`。在线 peer-key 拒绝仍为 `host_key`。
- 依赖远端发现/客户端默认值的 SQL 身份：应明确数据库与角色；
  容器/`--db-cred-from` 发现无法离线固定，在绑定模式下拒绝。

纯密码认证绑定明确主体、backend 和引用，不绑定密码字节；秘密轮换或远端角色
策略变化不是本地哈希能冻结的事实。不使用绑定时保留原行为。

脚本/apply 字节与绑定上传使用本地快照执行。远端行、文件内容、递归目录成员、
程序版本、权限与观察缓存内容**不会**被计划隐式快照。远端前置检查发生在本地
准入之后；计划哈希不是远端锁。

## 风险不等于意图或授权

`risk` 是标量：`read < mutation < privileged < destructive`。
`effects` 同时保留 `unknown`、`remote_write`、`local_write`、`privileged`、
`destructive`，防止一个风险等级遮盖其他副作用。

不透明命令/脚本默认 `mutation` 且副作用未知；`--intent=read` 不能证明只读。
sudo 读取仍是 privileged，删除是 destructive，上传/apply/中转会远端写入。
下载可以是远端 `read`，同时明确标记本地目的地写入。带远端缓存的探测包含缓存写；
自定义采集器不假定为纯读取。既有安全门与绕过要求继续决定准入；分类不是授权或沙箱。

## 重试前先解释结果

以下共享字段增量加入各动词的原结果信封：

| 字段 | 含义 |
| --- | --- |
| `execution_id`、`parent_execution_id` | 调用/目标关联；调用方 request ID 和原 run ID 含义不变 |
| `plan_hash`、`risk`、`effects` | 已准入公开计划及预期副作用 |
| `execution_fingerprint` | 最终脱敏执行证据的摘要，不是签名或防重放令牌 |
| `peers`、`target_fingerprints` | 观测的公开 peer/auth 身份，以及 run 父级的最终目标指纹 |
| `change_state` | `changed`、`unchanged`、`unknown`；未知不能当作 false |
| `executed` | 可空执行观测；`null` 表示未知，不是“没执行” |
| `verified`、`verification` | 必需证据是否验证及其状态；进程成功不等于副作用已验证 |
| `preconditions`、`postconditions` | 可选条件数组，含 `kind`、`subject`、`expected`、`observed`、`status` |

指纹不包含原始 stdout/stderr、秘密值或显示格式。它用于对照可信参考关联证据，
不使审计存储防篡改。成功可以未验证副作用；失败也可能已经发生变更。
apply 原有 `changed` / `created` 布尔值继续兼容，失败时应读取 `change_state`。
指纹只覆盖最终共享投影，不能假设所有历史信封字段都纳入；
投影之外单独报告的 peer/auth 字段不会自动绑定。
共享 `peers` 投影现在绑定实际传输地址、host-key 指纹、认证方式、有效用户与
SSH/sudo 凭据引用。目标指纹包含这些观测事实；父级通过 `target_fingerprints`
间接绑定。采集发生在连接/认证成功之后，不能承诺此前失败保留观测 peer。
缺失的实际地址/key 不会用计划目标配置补造，凭据引用也不含秘密值。

run 的父执行 ID 同时是 run ID，目标执行 ID 由父 ID 与规范目标身份/索引确定生成。
单目标结果使用目标自身元数据，不是 run 父级元数据。父级 `run_finished` 元数据
保留排序后的最终目标指纹。调用方 `request_id` 仅用于关联。

JSONL writer 可写时，`seq` 从 1 连续递增，每个选中目标恰有一个终态事件；
未准入的 skipped 目标没有 `target_started`。最终计数满足：

```text
Selected = Succeeded + Failed + Skipped
Started  = 已准入 = Succeeded + Failed
Uncertain 是 Failed 的子集，不另加到总数
```

选择器拒绝的候选不计入 selected。`partial`、`completed_unconfirmed`、`unknown` 属于
不确定完成；建立连接本身不是执行确认。通用命令不验证副作用，不透明/高风险命令
执行后仍为未知变更、`verified=false` 和不支持副作用验证。

| 命令传输观测 | 结果确定性 |
| --- | --- |
| 尚未尝试 exec 请求（session/PTY/前置检查失败） | `completion=not_started`、`executed=false` |
| 已尝试 exec 请求，但确认丢失 | `completion=unknown`、`executed=null`、`change_state=unknown` |
| 收到明确 start 确认 | 已执行；是否完成仍需退出证据 |
| 观测到退出状态 | 独立于 start 确认报告，可确定命令完成 |

exec 请求尝试后的超时、取消或断连，不能仅因 start 确认丢失就降级成“未开始”。

| 观测 | 下一步 |
| --- | --- |
| `config`、`plan_mismatch`、`plan_unresolved` 或准入阻断 | 修正并重新审核输入，不为通过哈希而放松信任 |
| 提交前 `precondition` | 重新读取/审核远端状态，不丢弃原前置条件 |
| `verification_failed`、部分/未知完成或缺少确认 | 先检查状态与备份证据，再考虑重试 |
| 准入后 `timeout` / `cancelled` | 副作用可能部分完成/未知；传输可重试不等于变更可重试 |
| 成功执行后审计写入失败 | 单独恢复审计投递，不重复变更来补日志 |

## 变更保证依赖后端

**Apply：**验证过的 no-op 可以 `unchanged`，无需写入或备份。替换后须看回读/
哈希证据；失败仍保留前后/payload 哈希和已知备份。原子替换依赖服务端 rename
原语，不承诺 delete-then-create 降级。临近替换时复查哈希**不等于**针对任意
并发 SFTP 写入者的通用 compare-and-swap。`--force` 保留原哈希前置条件绕过，
不能绕过 `--expect-plan`。

**SFTP/transfer：**应读取操作/副作用元数据，而非将复制成功当作内容相同的证明。
仅大小验证不是摘要比对。单文件暂存替换不提供目录整体原子性或回滚；中断的递归
传输可能已经发布部分文件。中转读取源端，只写目的端。

**SQL：**执行确认、提交确认、行数、备份状态和副作用验证是不同事实。
PostgreSQL 匹配/处理行数、SQLite `changes()`、MySQL affected rows 语义不同。
正数不能普遍证明 UPDATE 改变了值，零也不能普遍证明没有副作用。
不支持的验证必须明确；丢失提交确认不能安全盲重试。

SQL 嵌套 `evidence` 区分：

| 字段 | 含义 |
| --- | --- |
| `affected_rows_semantics` | `postgres_command_tag`、`sqlite_changes` 或 `mysql_row_count`；原 `affected_rows` 保留引擎计数 |
| `state_change` | 当前所有变更均保持 `unknown`，包括零计数；读取为 `unchanged` |
| `commit` | `not_started`、`unknown` 或 `acknowledged` |
| `verification`、`verification_method` | nonce 绑定客户端协议校验，不是 postimage 检查 |
| `effect_verification` | 独立的副作用验证；通用变更后置条件仍不支持 |
| `backup_status`、`backup_consistency`、`backup_format` | 计划备份是否确认、锁定前镜像的一致性与实际格式 |
| `outcome_uncertain` | 变更缺少提交确认 |

`evidence.verification=protocol_verified` 不能当作值变化已 `verified=true`。
PostgreSQL/SQLite UPDATE 计数可能表示处理的行，即使赋值与原值相同。
必需证据畸形或缺失时报告 `protocol_error` 或 `verification_failed`；
二者都不能证明已准入的变更回滚了。

PostgreSQL（包括 Docker）在一个锁定事务中流式输出 CSV 前镜像。
volatile/带括号谓词使行备份升级为整表快照；整表快照支持多行 SQL。
SQLite 表 CSV 捕获整表，由变更客户端持有 `BEGIN IMMEDIATE`；
整文件 `.backup` 在持有写锁时通过**第二个只读客户端**执行，快照完成后才发送变更。
在同一活跃写事务连接上 `.backup` 可能报 `database is locked`，不是采用的策略。

MySQL 受控备份支持 InnoDB 简单单表 UPDATE/DELETE，使用一个变更会话与显式写锁
（`innodb_table_locks=1`、`autocommit=0`、`LOCK TABLES ... WRITE`）。
表名必须为简单、无 schema 限定的名称；别名、JOIN、子查询、RETURNING 和带受控
备份的 DDL 不支持。获得锁后检查 InnoDB/关联影响，拒绝触发器/级联和不支持的引擎。
数据前镜像流式输出并持久化后才发送变更，不创建服务端备份表或执行备份 DDL。
格式 `SSHX_MYSQL_HEX_ROWS_V1` 采用十六进制列名/类型头和可区分 NULL 的二进制安全
行值，保存为 `.mysql-hex`，`evidence.backup_format=mysql_hex_rows_v1`；
它**不是 CSV**、schema/整库 dump 或自动恢复脚本。

不能把受支持策略推广为通用 MySQL 原子性：无锁的分连接快照/变更与隐式提交 DDL
并不原子。宣称的策略必须有真实引擎并发写入/回滚证据。不支持的形式应拒绝，
或使用明确的独立备份绕过并展示降低的保证。真实引擎测试是否执行以验收矩阵为准。

## 超时与停止准入

- `--timeout` / `SSH_TIMEOUT` 保留原命令/会话语义与默认值：
  run 默认 60s，兼容命令模式默认不设置。
  拨号、握手与密码回退共享一个连接预算，回退不会重置预算；
  命令 timeout 仍只针对命令。
- 可选 `--host-timeout` 覆盖已准入目标的准备、执行和验证；
  `--global-timeout` 覆盖整个操作及排队。未设置新限制不会静默增加单目标期限；
  run 未显式覆盖全局期限时保留原推导总预算。
- `--fail-fast` 等价于 `--failure-mode=fail_fast`；`--max-failures=N` 达到阈值
  后停止准入，冲突策略属于配置错误。**已经准入的目标继续完成**，可能继续失败，
  因此阈值不限制最终失败总数：停止阈值记录后，最多还有 `concurrency-1`
  个已准入目标可能失败。
- 取消/期限独立取消活跃传输；`cancelled` 与 `timeout` 不同。
  关闭本地 SSH 连接或终止 MCP 子进程**不保证远端终止或回滚**。
  原生 secret API 可能不可中断，只能在调用前后检查上下文，不能靠无界后台线程
  假装可取消。

MCP 仍是 stdio 单次子进程适配器；进程 watchdog 和进度投递限制是适配层边界，
不是远端执行保证。最终 JSONL 缺失/截断不能解释成 fan-out 已完成。
fan-out 在发布事件前记录准入/失败阈值。首次事件 writer 失败后停止后续发布，
返回本地 I/O 失败，但内部保留已收集目标结果；输出通道损坏不能撤销或重新定义远端结果。
在该通道缺少目标终态事件，不代表目标从未执行。

## 平台与证据边界

本地路径遵循客户端 OS，远端 SFTP 路径使用斜杠。POSIX mode/owner/signal 保证
不等同于 Windows ACL/进程语义。原生 Windows、真实 SQL 引擎/客户端、可隔离原生
OS keyring 是独立前提；交叉编译、模拟 SQL 客户端、测试专用 secret backend
不能证明这些边界。审计是尽力写入的本地脱敏证据；
[查询诊断](audit.md) 区分损坏记录与空结果。本次不引入 daemon、工作流引擎、
调度器或远端驻留组件。

原生 SQL CI 提供 PostgreSQL 16 / MySQL 8.4。编译后 CLI 的
`TestSQLRealEngineReliability` 需显式 `SSHX_E2E_REAL_SQL=1` 和可销毁 loopback
测试库凭据；启用后缺客户端/服务应失败。`internal/sqlsafe/real_engine_integration_test.go`
独立验证 rollback/commit 与并发写入。这两个确切测试已通过会话独占的
`docker exec` 客户端适配器，在隔离、无网络 Docker 中对真实 PostgreSQL 17.11 /
MySQL 8.4.11 执行通过。它是生成 SQL/真实客户端/真实服务端的**组件集成**，
不是 mock，也不是编译 CLI 跨 SSH E2E。编译后 CLI 的原生 SQL opt-in 曾因主机缺少
`psql`/`mysql` 失败，该范围仍待自己的 CI/客户端前提。Windows 选定的 portable/
CLI 子集已在 macOS 通过，但原生 Windows 仍须 CI，本地交叉编译/平台 lint 不能替代。
前提见[原生 SQL 验收](../roadmap.md#native-sql-prerequisites)。
