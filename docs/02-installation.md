# 安装指南

## TL;DR

```bash
# 方式 1: 二进制安装（推荐）
wget https://github.com/ParaParty/certdx/releases/latest/download/certdx_linux_amd64.tar.gz
tar -xzf certdx_linux_amd64.tar.gz

# 方式 2: 从源码编译
git clone https://github.com/ParaParty/certdx.git
cd certdx && python3 release/build.py
```

## 系统要求

### 服务器要求

- **操作系统**: Linux/macOS/Windows
- **内存**: 最小 512MB，推荐 1GB+
- **存储**: 最小 100MB 可用空间
- **网络**:
  - 出站: 443端口（ACME服务器）
  - 入站: 可配置端口（默认10001）
- **域名**: 拥有可管理DNS的域名

### 客户端要求

- **操作系统**: Linux/macOS/Windows
- **内存**: 最小 128MB
- **存储**: 最小 50MB 可用空间
- **网络**: 能够访问服务器地址

### DNS 提供商支持

支持以下 DNS 提供商进行自动验证：

- Cloudflare
- 腾讯云 DNSPod

## 安装方法

### 方式 1: 预编译二进制（推荐）

#### 下载并安装

```bash
# 设置版本号（替换为最新版本）
VERSION="v0.4.2"
ARCH="linux_amd64"  # 可选: linux_arm64, linux_arm, linux_mips, linux_mipsle, darwin_arm64, windows_amd64

# 下载
wget "https://github.com/ParaParty/certdx/releases/download/${VERSION}/certdx_${ARCH}.tar.gz"

# 解压
tar -xzf "certdx_${ARCH}.tar.gz"
cd certdx_${ARCH}

# 移动到系统路径（可选）
sudo cp certdx_server /usr/local/bin/
sudo cp certdx_client /usr/local/bin/
sudo cp certdx_tools /usr/local/bin/
sudo chmod +x /usr/local/bin/certdx_*
```

#### 验证安装

```bash
certdx_server --version
certdx_client --version
```

### 方式 2: 从源码编译

#### 前置要求

- Go 1.24+
- Git
- Python 3（用于构建脚本）

#### 编译步骤

#### 方法 A: 使用构建脚本（推荐）

```bash
# 克隆仓库
git clone https://github.com/ParaParty/certdx.git
cd certdx

# 执行构建脚本（会自动构建所有平台版本）
python3 release/build.py

# 构建产物在当前目录的 certdx_* 压缩包中
```

#### 方法 B: 手动构建特定模块

```bash
# 克隆仓库
git clone https://github.com/ParaParty/certdx.git
cd certdx

# 编译服务器
cd exec/server
go build -o certdx_server .

# 编译客户端
cd ../client
go build -o certdx_client .

# 编译工具（可选）
cd ../tools
go build -o certdx_tools .
```

#### 安装到系统

```bash
# 复制到系统路径
sudo cp exec/server/certdx_server /usr/local/bin/
sudo cp exec/client/certdx_client /usr/local/bin/
sudo cp exec/tools/certdx_tools /usr/local/bin/
sudo chmod +x /usr/local/bin/certdx_*
```

## 专用组件安装

### Caddy 插件

#### 构建包含插件的 Caddy

创建 `main.go`:

```go
package main

import (
    caddycmd "github.com/caddyserver/caddy/v2/cmd"
    _ "github.com/caddyserver/caddy/v2/modules/standard"
    _ "pkg.para.party/certdx/exec/caddytls"
)

func main() {
    caddycmd.Main()
}
```

编译：

```bash
go build -o caddy-with-certdx main.go
```

#### 使用预编译版本

```bash
# 下载包含 certdx 插件的 Caddy
wget https://github.com/ParaParty/certdx/releases/latest/download/caddy_certdx_linux_amd64.tar.gz
tar -xzf caddy_certdx_linux_amd64.tar.gz
sudo mv caddy /usr/local/bin/
sudo chmod +x /usr/local/bin/caddy
```

## 服务配置

### Systemd 服务

#### 使用项目提供的服务文件

项目提供了标准的 systemd 服务文件，可以直接使用：

```bash
# 复制服务文件到系统目录
sudo cp systemd-service/certdx-server.service /etc/systemd/system/
sudo cp systemd-service/certdx-client.service /etc/systemd/system/

# 创建工作目录
sudo mkdir -p /opt/certdx/config

# 复制程序文件到工作目录
sudo cp certdx_server /opt/certdx/
sudo cp certdx_client /opt/certdx/
sudo chmod +x /opt/certdx/certdx_*

# 复制配置文件
sudo cp config/server_config.toml /opt/certdx/config/
sudo cp config/client_config.toml /opt/certdx/config/
```

#### 启用服务

```bash
# 重新加载 systemd 配置
sudo systemctl daemon-reload

# 启用并启动服务
sudo systemctl enable certdx-server certdx-client
sudo systemctl start certdx-server certdx-client

# 检查状态
sudo systemctl status certdx-server certdx-client

# 查看日志
sudo journalctl -u certdx-server -f
sudo journalctl -u certdx-client -f
```

## 安装验证

### 基本验证

```bash
# 检查程序版本
certdx_server --version
certdx_client --version

# 检查帮助信息
certdx_server --help
certdx_client --help
```

### 连接测试

```bash
# 测试服务器连接（在客户端机器上运行）
certdx_client --conf /opt/certdx/config/client_config.toml --test-connection
```

### 功能测试

```bash
# 查看可用工具命令
certdx_tools --help

# 查看缓存状态（需要配置文件）
certdx_tools show-cache
```

## 常见安装问题

### 权限问题

```bash
# 确保程序有执行权限
chmod +x /usr/local/bin/certdx_*

# 确保数据目录权限正确
sudo chown -R certdx:certdx /var/lib/certdx
sudo chmod 755 /var/lib/certdx
```

### 防火墙配置

```bash
# Ubuntu/Debian
sudo ufw allow 10001/tcp

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=10001/tcp
sudo firewall-cmd --reload
```

### SELinux 配置（CentOS/RHEL）

```bash
# 允许网络连接
sudo setsebool -P httpd_can_network_connect 1

# 如果遇到权限问题，可能需要设置 SELinux 上下文
sudo semanage fcontext -a -t bin_t "/usr/local/bin/certdx_.*"
sudo restorecon -v /usr/local/bin/certdx_*
```

## 升级指南

### 二进制升级

```bash
# 停止服务
sudo systemctl stop certdx-server certdx-client

# 备份当前版本
sudo cp /usr/local/bin/certdx_server /usr/local/bin/certdx_server.backup
sudo cp /usr/local/bin/certdx_client /usr/local/bin/certdx_client.backup

# 下载新版本
wget "https://github.com/ParaParty/certdx/releases/download/${NEW_VERSION}/certdx_${ARCH}.tar.gz"
tar -xzf "certdx_${ARCH}.tar.gz"

# 安装新版本
sudo cp certdx_${ARCH}/certdx_server /usr/local/bin/
sudo cp certdx_${ARCH}/certdx_client /usr/local/bin/

# 启动服务
sudo systemctl start certdx-server certdx-client
```

---

> **下一步**: 完成安装后，请查看 [配置指南](03-configuration.md) 来配置你的 Certdx 系统。
