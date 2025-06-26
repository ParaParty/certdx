# 快速开始指南

## TL;DR

```bash
# 1. 启动服务器
./certdx_server --conf server.toml

# 2. 启动客户端
./certdx_client --conf client.toml

# 3. 证书自动获取和更新 ✅
```

## 前置要求

- **域名**: 拥有可管理的域名（用于 DNS 验证）
- **DNS API**: Cloudflare、腾讯云等 DNS 提供商的 API 凭据
- **操作系统**: Linux/macOS/Windows

## 5分钟快速体验

### 步骤 1: 下载程序

```bash
# 下载最新版本（替换为实际的下载链接）
wget https://github.com/ParaParty/certdx/releases/latest/download/certdx_linux_amd64.tar.gz
tar -xzf certdx_linux_amd64.tar.gz
cd certdx
```

### 步骤 2: 配置服务器

创建服务器配置文件 `server.toml`:

```toml
[ACME]
email = "your-email@example.com"  # 你的邮箱
provider = "r3"          # ACME 提供商

# 允许申请证书的域名（重要：只能为你拥有的域名申请证书）
allowedDomains = [
    "example.com",     # 替换为你的域名
    "*.example.com"    # 支持通配符
]

[DnsProvider]
# 使用 Cloudflare DNS（也支持腾讯云等其他提供商）
type = "cloudflare"
authToken = "your_cloudflare_token"  # 你的 Cloudflare API Token
zoneToken = "your_zone_token"        # Zone Token（可选，与 authToken 相同）

[HttpServer]
enabled = true
secure = true
# 服务器自己的域名（用于 HTTPS API）
names = ["certdx.example.com"]  # 替换为你的服务器域名
token = "your_secret_token"     # API 访问令牌
```

### 步骤 3: 配置客户端

创建客户端配置文件 `client.toml`:

```toml
[Http.MainServer]
url = "https://certdx.example.com:10001/"  # 服务器地址
token = "your_secret_token"                # 与服务器相同的令牌

# 定义需要的证书
[[Certifications]]
name = "web-cert"                          # 证书名称
savePath = "/etc/ssl/certs"                # 证书保存路径
domains = [
    "www.example.com",                     # 替换为你的域名
    "api.example.com"
]
reloadCommand = "systemctl reload nginx"   # 证书更新后执行的命令（可选）
```

### 步骤 4: 启动服务

启动服务器：

```bash
# 前台运行（用于测试）
./certdx_server --conf server.toml

# 或者后台运行
nohup ./certdx_server --conf server.toml > server.log 2>&1 &
```

启动客户端：

```bash
# 在另一个终端中
./certdx_client --conf client.toml
```

### 步骤 5: 验证结果

几分钟后，检查证书是否成功获取：

```bash
# 检查证书文件
ls -la /etc/ssl/certs/
# 应该看到 web-cert.pem 和 web-cert.key

# 验证证书信息
openssl x509 -in /etc/ssl/certs/web-cert.pem -text -noout
```

## 🎉 成功

如果一切正常，你现在有了：

- ✅ 自动获取的 SSL 证书
- ✅ 自动续期机制
- ✅ 证书文件保存在指定位置

## 下一步

- 📖 查看 [配置指南](03-configuration.md) 了解更多配置选项
- 🚀 查看 [部署示例](04-deployment-examples.md) 了解生产环境部署
- 🔧 查看 [运维指南](05-operations.md) 了解监控和维护

## 常见问题

### Q: 证书获取失败？

A: 检查以下内容：

1. DNS API 凭据是否正确
2. 域名是否在 `allowedDomains` 列表中
3. 域名 DNS 解析是否正常

### Q: 客户端连接失败？

A: 检查以下内容：

1. 服务器地址和端口是否正确
2. Token 是否匹配
3. 网络连接是否正常

### Q: 证书文件权限问题？

A: 确保运行客户端的用户有写入 `savePath` 的权限：

```bash
sudo chown -R $USER:$USER /etc/ssl/certs
sudo chmod 755 /etc/ssl/certs
```

---

> **提示**: 这只是一个快速开始示例。生产环境使用请参考 [安装指南](02-installation.md) 和 [部署示例](04-deployment-examples.md)。
