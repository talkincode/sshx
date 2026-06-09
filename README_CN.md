<!-- markdownlint-disable MD033 MD036 MD040 MD041 -->

```
 $$$$$$\   $$$$$$\  $$\   $$\ $$\   $$\
$$  __$$\ $$  __$$\ $$ |  $$ |$$ |  $$ |
$$ /  \__|$$ /  \__|$$ |  $$ |\$$\ $$  |
\$$$$$$\  \$$$$$$\  $$$$$$$$ | \$$$$  /
 \____$$\  \____$$\ $$  __$$ | $$  $$<
$$\   $$ |$$\   $$ |$$ |  $$ |$$  /\$$\
\$$$$$$  |\$$$$$$  |$$ |  $$ |$$ /  $$ |
 \______/  \______/ \__|  \__|\__|  \__|


内置密码管理器的安全 SSH 和 SFTP 客户端
```

<div align="center">

[![Go Version](https://img.shields.io/github/go-mod/go-version/talkincode/sshx?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![Release](https://img.shields.io/github/v/release/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://github.com/talkincode/sshx/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/talkincode/sshx?style=flat-square)](https://goreportcard.com/report/github.com/talkincode/sshx)
[![Coverage](https://img.shields.io/badge/coverage-20.0%25-yellow?style=flat-square&logo=go)](https://github.com/talkincode/sshx)

[![GitHub Stars](https://img.shields.io/github/stars/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx/network/members)
[![GitHub Issues](https://img.shields.io/github/issues/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx/pulls)

[![GitHub Downloads](https://img.shields.io/github/downloads/talkincode/sshx/total?style=flat-square&logo=github)](https://github.com/talkincode/sshx/releases)
[![GitHub Contributors](https://img.shields.io/github/contributors/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx/graphs/contributors)
[![Last Commit](https://img.shields.io/github/last-commit/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx/commits/main)
[![Repo Size](https://img.shields.io/github/repo-size/talkincode/sshx?style=flat-square&logo=github)](https://github.com/talkincode/sshx)

[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=flat-square&logo=linux&logoColor=white)](https://github.com/talkincode/sshx/releases)
[![Made with Go](https://img.shields.io/badge/Made%20with-Go-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://github.com/talkincode/sshx/pulls)

[English](./README.md) | 简体中文

</div>

---

# SSHX

`sshx` 是一个无障碍、跨平台的 SSH/SFTP 命令行客户端，内置基于系统密钥链的密码管理器，让你轻松管理和操作多台远程服务器。

## 为什么你需要它？

管理多台服务器时，记住不同的密码、反复输入 sudo 密码都很繁琐。`sshx` 将密码安全存储在系统密钥链中，自动填充 sudo 密码，让你在多台服务器上执行命令时不再为密码烦恼。一个命令，多台服务器，零密码困扰。

## 项目结构

- `cmd/sshx`: 主二进制入口点，负责命令行参数解析和密码管理功能。
- `internal/sshclient`: 核心 SSH/SFTP/脚本执行逻辑和命令安全验证。
- `internal/app`: CLI 命令路由、主机配置管理和密码管理。

## 核心特性

1. 跨平台 SSH/SFTP 操作（支持 sudo 自动填充）。
2. 密码管理（Keychain / Secret Service / Credential Manager）。
3. 主机配置管理，支持为每台主机配置独立的 SSH 密钥。
4. 脚本执行和命令安全验证。

## 安装

### 使用 Go 快速安装（推荐 Go 用户）

如果您已安装 Go 1.21+，可以使用 Go 的内置工具：

#### 直接运行无需安装（类似 npx）

```bash
# 运行最新版本
go run github.com/talkincode/sshx/cmd/sshx@latest --help

# 运行指定版本
go run github.com/talkincode/sshx/cmd/sshx@v0.0.6 -h=192.168.1.100 "uptime"
```

#### 全局安装

```bash
# 安装最新版本到 $GOPATH/bin
go install github.com/talkincode/sshx/cmd/sshx@latest

# 然后可以在任何地方使用
sshx --help
sshx -h=192.168.1.100 "uptime"
```

**注意：** 确保 `$GOPATH/bin`（通常是 `~/go/bin`）在您的 PATH 中。

### 一键安装脚本

#### Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/talkincode/sshx/main/install.sh | bash
```

或下载后运行：

```bash
wget https://raw.githubusercontent.com/talkincode/sshx/main/install.sh
chmod +x install.sh
./install.sh
```

安装特定版本：

```bash
./install.sh v0.0.2
```

#### Windows

以管理员身份打开 PowerShell 并运行：

```powershell
irm https://raw.githubusercontent.com/talkincode/sshx/main/install.ps1 | iex
```

或下载后运行：

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/talkincode/sshx/main/install.ps1" -OutFile "install.ps1"
.\install.ps1
```

安装特定版本：

```powershell
.\install.ps1 -Version v0.0.2
```

### 手动安装

从 [Releases](https://github.com/talkincode/sshx/releases) 下载预编译二进制文件：

**Linux / macOS:**

```bash
# 下载并解压（将 <platform>-<arch> 替换为您的系统）
tar -xzf sshx-<platform>-<arch>.tar.gz

# 移动到系统路径
sudo mv sshx /usr/local/bin/

# 添加执行权限
sudo chmod +x /usr/local/bin/sshx

# 验证安装
sshx --help
```

**Windows:**

1. 下载 `sshx-windows-amd64.zip`
2. 解压文件
3. 将 `sshx.exe` 移动到 PATH 中的目录（例如 `C:\Program Files\sshx`）
4. 或将解压目录添加到系统 PATH

### 从源代码构建

```bash
# 克隆仓库
git clone https://github.com/talkincode/sshx.git
cd sshx

# 构建命令行工具
go build -o bin/sshx ./cmd/sshx

# 查看版本号（也可通过二进制的 --version 参数查看）
make version

# 安装到系统（可选）
# 将二进制安装到 ~/.local/bin，并将 agent 技能安装到 ~/.agents/skills/sshx
make install

# 查看已安装的版本
sshx --version
```

## 快速开始

```bash
# 执行远程命令
sshx -h=192.168.1.100 -u=root "uptime"

# 保存密码以便更轻松访问（交互式输入）
sshx --password-set=root

# 或者为特定主机设置密码
sshx --password-set=192.168.1.100-root

# 执行命令时无需密码标志（使用已保存的密码）
sshx -h=192.168.1.100 -u=root "df -h"

# 一次性测试所有已配置的主机（每台主机 10 秒拨号超时），并在报告中标注认证方式
sshx --host-test-all
```

## Agent / 脚本模式

`sshx` 不仅面向人类终端，也专为脚本和 AI agent 调用而设计，命令执行路径提供稳定、可被机器解析的契约。

默认行为：

- **stdout 与 stderr 分离**并实时流式输出（不使用 PTY，不混入终端控制字符）。
- **透传远程命令的退出码**，作为 `sshx` 自身的进程退出码。

### 退出码

| 退出码    | 含义                                                       |
| -------- | --------------------------------------------------------- |
| `0`      | 命令成功                                                   |
| `1..254` | 远程命令的退出码，原样透传                                  |
| `255`    | `sshx` 层面的失败（连接 / 认证 / 主机密钥 / 超时 / 被拦截） |

### `--json` 结构化输出

加上 `--json` 即可在 stdout 得到单个 JSON 对象（诊断日志仍走 stderr，保证 stdout 纯净）：

```bash
sshx -h=prod-web --json "systemctl is-active nginx"
```

```json
{
  "host": "192.168.1.100",
  "port": "22",
  "user": "root",
  "command": "systemctl is-active nginx",
  "exit_code": 0,
  "success": true,
  "stdout": "active\n",
  "stderr": "",
  "duration_ms": 142,
  "auth_method": "key"
}
```

当发生 `sshx` 层面的失败时，对象中 `exit_code` 为 `-1` 且 `error_kind` 非空（取值为
`timeout`、`auth`、`host_key`、`connect`、`blocked`、`exit_missing`、`config`、`error`
之一），因此始终可以与"远程命令恰好退出 255"区分开来。

### `--timeout` 与 `--pty`

```bash
# 命令运行超过 30 秒则杀掉（也支持 2m 等写法，纯数字按秒处理）
sshx -h=prod-web --timeout=30s "apt-get update"

# 对必须要终端的命令重新启用 PTY
# （注意：PTY 会把 stderr 合并进 stdout，且不能与 --json 同时使用）
sshx -h=prod-web --pty "top -b -n1"
```

超时也可以通过环境变量 `SSH_TIMEOUT` 设置。

## 主机密钥校验 🔐

`sshx` 现在默认与 OpenSSH 一样严格验证主机密钥。程序会读取 `~/.ssh/known_hosts`（或你指定的路径），当主机不存在或密钥发生变化时会立即中断连接并给出修复方案，从源头降低中间人攻击风险。

管理主机密钥的方式：

- **手动添加（推荐）**：`ssh-keyscan -H <host> >> ~/.ssh/known_hosts`
- **首次自动信任**：`sshx --accept-unknown-host -h=<host> ...`（或设置 `SSH_ACCEPT_UNKNOWN_HOST=1`）。第一次连接会写入 known_hosts，之后依旧保持严格校验。
- **自定义信任库**：`sshx --known-hosts=/path/to/known_hosts` 或设置 `SSH_KNOWN_HOSTS=/path/to/known_hosts`。
- **兼容旧行为（不推荐）**：`sshx --insecure-hostkey ...` 或 `SSH_INSECURE_HOST_KEY=1`。这会重新启用 `InsecureIgnoreHostKey`，只应在完全受控的环境下短暂使用。

当远端主机密钥变化时，`sshx` 会提示先删除旧条目再重新连接，确保整个流程可追溯且安全。

## 密码管理

`sshx` 使用操作系统的原生凭据管理器提供安全的密码存储，无需重复输入密码或以明文形式存储密码。

### 支持的平台

- **macOS**: 使用 Keychain Access（钥匙串访问）
- **Linux**: 使用 Secret Service（GNOME Keyring / KDE Wallet）
- **Windows**: 使用 Credential Manager（凭据管理器）

### 密码命令

#### 保存密码

```bash
# 保存默认 sudo 密码（交互式输入，推荐）
sshx --password-set=master

# 保存特定用户的密码
sshx --password-set=root

# 为特定主机+用户组合保存密码
sshx --password-set=192.168.1.100-root

# 直接设置密码（不推荐，不安全）
sshx --password-set=master:yourpassword
```

系统会提示您安全地输入密码（输入时隐藏）。

#### 检查已保存的密码

```bash
# 检查密码是否存在
sshx --password-check=master
sshx --password-check=root

# 输出示例：
# ✓ Password exists for key: master
```

#### 列出已保存的密码

```bash
# 列出常见的密码键
sshx --password-list

# 输出示例：
# Checking password keys in system keyring...
# Service: sshx
#
# Common keys:
#   ✓ master (exists)
#   ✓ root (exists)
#     sudo (not set)
```

#### 获取密码

```bash
# 获取存储的密码（用于调试）
sshx --password-get=master

# 输出示例：
# ✓ Password retrieved from system keyring
#   Service: sshx
#   Key: master
#
# Password: yourpassword
```

#### 删除密码

```bash
# 删除密码
sshx --password-delete=master
sshx --password-delete=root

# 确认消息：
# ✓ Password deleted from system keyring
#   Service: sshx
#   Key: master
```

### 使用已存储的密码

保存密码后,执行 sudo 命令时会自动从系统密钥链中检索密码:

```bash
# 1. 首先保存 sudo 密码
sshx --password-set=master

# 2. 执行 sudo 命令(自动使用存储的密码)
sshx -h=192.168.1.100 -u=root "sudo systemctl status nginx"
sshx -h=192.168.1.100 -u=root "sudo reboot"

# 3. 多服务器场景:为不同服务器保存不同的密码
sshx --password-set=server-A
sshx --password-set=server-B
sshx --password-set=server-C

# 4. 使用 -pk 参数临时指定 sudo 密码 key
sshx -h=192.168.1.100 -pk=server-A "sudo systemctl restart nginx"
sshx -h=192.168.1.101 -pk=server-B "sudo systemctl restart nginx"
sshx -h=192.168.1.102 -pk=server-C "sudo systemctl restart nginx"
```

### 密码键名说明

- **master**: 默认的 sudo 密码键名,用于 sudo 命令
- **root**: root 用户的密码
- **自定义键名**: 您可以使用任何键名,例如 `server-A`、`server-B`、`prod-db` 等

### 多服务器密码管理最佳实践

如果您管理多个服务器,即使用户名相同但密码不同,可以使用以下策略:

```bash
# 场景:管理 3 台服务器,都是 root 用户,但密码各不相同

# 1. 为每台服务器保存密码(使用有意义的 key 名称)
sshx --password-set=prod-web      # 生产环境 Web 服务器
sshx --password-set=prod-db       # 生产环境数据库服务器
sshx --password-set=dev-server    # 开发环境服务器

# 2. 执行命令时使用 -pk 参数指定对应的密码 key
sshx -h=192.168.1.10 -u=root -pk=prod-web "sudo systemctl status nginx"
sshx -h=192.168.1.20 -u=root -pk=prod-db "sudo systemctl status mysql"
sshx -h=192.168.1.30 -u=root -pk=dev-server "sudo docker ps"

# 3. 也可以使用别名简化命令(添加到 ~/.zshrc 或 ~/.bashrc)
alias ssh-prod-web='sshx -h=192.168.1.10 -u=root -pk=prod-web'
alias ssh-prod-db='sshx -h=192.168.1.20 -u=root -pk=prod-db'
alias ssh-dev='sshx -h=192.168.1.30 -u=root -pk=dev-server'

# 然后就可以简单使用:
ssh-prod-web "sudo systemctl restart nginx"
ssh-prod-db "sudo systemctl restart mysql"
ssh-dev "sudo docker-compose up -d"
```

### 环境变量配置

可以通过环境变量自定义 sudo 密码键名(但不如使用 `-pk` 参数灵活):

```bash
# 使用环境变量(每次只能指定一个,需要不停修改)
export SSH_SUDO_KEY=my-sudo-password
sshx --password-set=my-sudo-password
sshx -h=192.168.1.100 "sudo ls -la /root"

# 推荐:使用 -pk 参数,更灵活,不需要修改环境变量
sshx -h=192.168.1.100 -pk=server-A "sudo ls -la /root"
sshx -h=192.168.1.101 -pk=server-B "sudo ls -la /root"
```

### 安全说明

- ✅ 密码使用操作系统原生加密存储
- ✅ 密码永远不会以明文形式存储
- ✅ 每个主机+用户组合都有单独的密码条目
- ✅ 输入时密码被隐藏
- ⚠️ 需要操作系统凭据管理器可用
- ⚠️ 在 Linux 上，需要 Secret Service 守护进程运行（桌面环境通常自动运行）

### 连接环境变量

您可以使用环境变量来避免重复输入凭据：

```bash
# 在 .env 文件中设置或在 shell 中导出
export SSH_HOST=192.168.1.100
export SSH_USER=root
export SSH_PORT=22
export SUDO_PASSWORD=your_sudo_password

# 然后运行命令时无需标志
./bin/sshx "uptime"
```

### SSH 认证偏好设置

- `sshx` 仍然会优先尝试 SSH 密钥认证，但如果服务器拒绝公钥（例如只允许密码登录），并且已经提供了密码，客户端会自动回退到“仅密码”重连，无需手动重试。
- 使用 `--no-key`（或 `--password-only`）即可在单次命令中禁用密钥认证；如果随后提供 `--key=<路径>`，会重新启用公钥登录。
- 如果长期不需要公钥，可以设置环境变量 `SSH_DISABLE_KEY=true`，即便 `~/.sshx/settings.json` 中存在默认密钥路径也会被忽略。
- 当密钥认证启用且未手动指定路径时，`sshx` 仍会自动加载 `~/.ssh/id_rsa`（或设置文件中的默认值），然后再按需回退到密码。

#### 日志级别配置

通过 `SSHX_LOG_LEVEL` 环境变量可以控制日志输出级别：

```bash
# 设置日志级别为 DEBUG（显示详细的调试信息）
export SSHX_LOG_LEVEL=debug

# 设置日志级别为 INFO（默认）
export SSHX_LOG_LEVEL=info

# 设置日志级别为 WARNING
export SSHX_LOG_LEVEL=warning

# 设置日志级别为 ERROR
export SSHX_LOG_LEVEL=error
```

DEBUG 级别下会记录：

- SSH/SFTP 操作的详细过程
- 认证方式的选择与回退细节

### 示例工作流

```bash
# 1. 保存 sudo 密码（交互式输入）
sshx --password-set=master
# Enter password for key 'master': ******

# 2. 验证已保存
sshx --password-check=master
# ✓ Password exists for key: master

# 3. 用于 SSH 命令（sudo 自动使用存储的密码）
sshx -h=192.168.1.100 -u=root "sudo systemctl status docker"
sshx -h=192.168.1.100 -u=root "sudo df -h"

# 4. 用于 SFTP 操作
sshx -h=192.168.1.100 -u=root --upload=local.txt --to=/tmp/remote.txt
sshx -h=192.168.1.100 -u=root --download=/etc/hosts --to=./hosts.txt

# 5. 列出所有已保存的密码键
sshx --password-list
# Common keys:
#   ✓ master (exists)
#     root (not set)

# 6. 完成后，可选择删除密码
sshx --password-delete=master
# ✓ Password deleted from system keyring
```

## 故障排除

### "sshx: command not found"（命令未找到）

**解决方案：**

- 确保 `/usr/local/bin`（或您的安装目录）在您的 PATH 中
- 安装后重启终端
- 或使用完整路径运行：`/usr/local/bin/sshx`

### macOS 安全警告

macOS 可能在首次运行时阻止二进制文件：

```bash
sudo xattr -rd com.apple.quarantine /usr/local/bin/sshx
```

或前往系统偏好设置 → 安全性与隐私 → 点击"仍要打开"

### Windows SmartScreen 警告

如果 Windows Defender SmartScreen 显示警告，请点击"更多信息"，然后点击"仍要运行"。

### 权限被拒绝

```bash
# 确保二进制文件具有执行权限
sudo chmod +x /usr/local/bin/sshx
```

## 开发

```bash
# 运行测试
go test ./...

# 格式化代码
gofmt -w .

# 为所有平台构建
make build-all

# 运行代码检查
make lint
```

> lint 目标需要 `golangci-lint` v2.6.1 或更高版本。使用 `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.1` 安装。

## 许可证

本项目采用 MIT 许可证 - 有关详细信息，请参阅 [LICENSE](LICENSE) 文件。

---

<div align="center">

**[文档](https://github.com/talkincode/sshx/wiki)** •
**[问题](https://github.com/talkincode/sshx/issues)** •
**[讨论](https://github.com/talkincode/sshx/discussions)** •
**[发布版本](https://github.com/talkincode/sshx/releases)**

用 ❤️ 制作，作者 [talkincode](https://github.com/talkincode)

</div>
