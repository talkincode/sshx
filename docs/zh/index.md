# SSHX 文档

`sshx` 是一个跨平台的 SSH/SFTP 命令行客户端，面向经常操作多台远程服务器的人和自动化 agent。它保持一个很简单的模型：一次命令建立一次 SSH 会话，完成指定操作，按需写入本地审计事件，然后退出。

文档默认首页是英文。可以使用顶部导航栏里的语言切换入口打开对应中文页面。

## SSHX 擅长什么

- 用稳定的 stdout、stderr 和退出码执行远程命令。
- 把 sudo 密码保存到操作系统密钥链，而不是明文文件。
- 用 `~/.sshx/settings.json` 里的主机短名称代替重复输入 IP、端口、用户和 key 路径。
- 不打开交互式 SFTP 客户端，也能完成常见文件上传、下载和目录操作。
- 输出适合脚本和 AI agent 判断分支的 JSON。
- 用 `--dry-run` 在连接、读取 secret、修改 `known_hosts` 或写配置前预览本地执行计划。
- 写入本地 JSONL 审计日志，同时不记录明文密码、私钥、stdout 或 stderr。

## 心智模型

把 `sshx` 理解成一个更安全的一次性远程操作助手，而不是交互式 shell 的替代品，也不是远程编排平台。

```text
人类、脚本或 agent
        |
        v
sshx CLI 参数与可选 .env
        |
        v
命名主机解析与安全检查
        |
        v
SSH 命令或 SFTP 操作
        |
        v
结构化结果、退出码、可选审计事件
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

- [快速开始](getting-started.md)帮助你让第一台主机跑通。
- [主机管理](host-management.md)说明命名主机和密钥选择。
- [使用场景](usage-scenarios.md)提供大量日常运维例子。
- [Agent 与脚本模式](agent-scripting.md)说明 JSON、退出码、timeout 和审计日志。
- [SFTP 工作流](sftp.md)覆盖上传、下载、列目录、创建目录和删除。
