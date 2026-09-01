# SSHX 文档

> **SSH 是通道，X 代表执行。**

`sshx` 是一个面向 Agent 的远程主机执行工具。它通过 SSH/SFTP 连接现有主机，把目标解析、执行预览、安全检查、命令与文件动作、结构化结果和审计留痕收敛到一次 CLI 调用中。

它保持一个简单的模型：一次命令建立一次连接，完成一个明确动作，返回可判断的结果，写入本地审计事件，然后退出；无需在远端安装常驻 Agent，也不引入长期控制面。

文档默认首页是英文。可以使用顶部导航栏里的语言切换入口打开对应中文页面。

## SSHX 擅长什么

- 用稳定的 stdout、stderr 和退出码执行远程命令。
- 把 sudo 密码保存到操作系统密钥链，而不是明文文件。
- 用 `~/.sshx/settings.json` 里的主机短名称代替重复输入 IP、端口、用户和 key 路径。
- 不打开交互式 SFTP 客户端，也能完成常见文件上传、下载和目录操作。
- 用哈希前置条件、备份和原子替换安全地改一个远程文件。
- 输出适合脚本和 AI agent 判断分支的 JSON。
- 用 `--dry-run` 在连接、读取 secret、修改 `known_hosts` 或写配置前预览本地执行计划。
- 写入本地 JSONL 审计日志，同时不记录明文密码、私钥、stdout 或 stderr。
- 一次调用探测系统/网络状态，并在 sshx 运行目录创建可复用的应用插件。
- 用 `sshx login`（可选 `--sudo`）在已配置主机上打开人类交互登录，不必再维护一份 `~/.ssh/config`。

## 心智模型

把 `sshx` 理解成 Agent 工具箱里的远程执行基本件，而不是期望状态或工作流编排平台。`sshx login` 只是给人类用的窄逃生舱，不是 OpenSSH 替代品。

```text
Agent、自动化或人类运维者
        |
        v
Agent 契约：CLI / JSON / 退出码 / dry-run
        |
        v
X 执行：目标解析 / 安全检查 / 动作 / 审计
        |
        v
SSH 通道：认证 / host-key / SSH exec / SFTP
        |
        v
远程主机
```

## 最常用的第一组命令

```bash
# 查看参数和示例
sshx --help

# 执行简单命令
sshx -h=192.168.1.100 -u=root "uptime"

# 使用命名主机
sshx -h=prod-web "systemctl is-active nginx"

# 连接前预览执行计划
sshx -h=prod-web --dry-run --json "sudo systemctl restart nginx"

# 给自动化输出机器可读结果
sshx -h=prod-web --json "systemctl is-active nginx"

# 一次采集完整系统/网络基线
sshx inspect -h=prod-web system.baseline --json
```

## 安全优先

远程操作工具可能造成真实破坏。`sshx` 的默认安全路径是严格的：

- 通过 `known_hosts` 校验主机密钥。
- 密码应进入 OS keyring，而不是 shell history 或配置文件。
- sudo 密码通过 stdin 传入，绝不拼进命令字符串。
- 明显危险的破坏性命令默认会被阻止，除非用户显式绕过。
- 安全检查只是防误操作护栏，不是不可信命令的沙箱。

在生产环境或 agent 驱动工作流中使用前，请先阅读[安全准则](security-guidelines.md)。

## 下一步

- [项目画像与方向](../roadmap.md)定义产品定位、非目标铁律和验收矩阵。
- [快速开始](getting-started.md)帮助你让第一台主机跑通。
- [主机管理](host-management.md)说明命名主机和密钥选择。
- [使用场景](usage-scenarios.md)提供大量日常运维例子。
- [Agent 与脚本模式](agent-scripting.md)说明 JSON、退出码、timeout 和审计日志。
- [主机探测能力与本地插件](inspection-plugins.md)说明内置能力、`plugin create`、信任和观察快照。
- [SFTP 工作流](sftp.md)覆盖上传、下载、列目录、创建目录和删除。
- [受控文件 Apply](apply.md)用备份和哈希检查替换一个远程文件。
- [MCP 服务器（stdio）](mcp.md)说明工具面、进度通知，以及 `--pty` 不在 MCP 范围。
- [审计查询与导出](audit.md)用只读过滤器消费本地 JSONL 审计。
- [契约冻结策略](contract.md)列出 v1 冻结表面和 1.0 门槛。
