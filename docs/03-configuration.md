# 配置指南

## TL;DR

```bash
# 服务器配置三要素
1. ACME 设置 (邮箱 + 提供商)
2. DNS 提供商配置 (API 凭据)
3. 允许的域名列表

# 客户端配置三要素
1. 服务器连接信息
2. 证书定义 (域名 + 保存路径)
3. 更新后执行命令
```

## 服务器配置

### 配置项详解

#### ACME 提供商

| 提供商 | provider 值 | 说明 |
|-------|-------------|------|
| Let's Encrypt | `r3` | 生产环境（推荐） |
| Let's Encrypt Staging | `r3test` | 测试环境 |
| Google Trust Services | `google` | Google 的 CA 服务 |
| Google Staging | `googletest` | Google 测试环境 |

#### DNS 提供商支持

| 提供商 | type 值 | 所需配置项 |
|-------|--------|------------|
| Cloudflare | `cloudflare` | `authToken`, `zoneToken` |
| 腾讯云 DNSPod | `tencentcloud` | `secretID`, `secretKey` |

#### 域名配置规则

```toml
allowedDomains = [
    "example.com",           # ✅ 允许根域名
    "*.example.com",         # ✅ 允许所有子域名
    "api.example.com",       # ✅ 允许特定子域名
    "*.api.example.com",     # ✅ 允许特定子域名的通配符
    "test.*.example.com"     # ❌ 不支持中间通配符
]
```

## 客户端配置

### HTTP 模式配置

`client.toml`:

```toml
# ===================
# 通用配置
# ===================
[Common]
# 客户端模式: http, grpc
mode = "http"

# 重试次数
retryCount = 3

# 重连间隔（用于 gRPC 模式）
reconnectInterval = "10m"

# ===================
# HTTP 服务器配置
# ===================
[Http]
# 主服务器配置
[Http.MainServer]
url = "https://certdx.example.com:10001/api"
authMethod = "token"
token = "your_super_secret_token"

# 备用服务器配置（可选）
[Http.StandbyServer]
url = "https://certdx-backup.example.com:10001/api"
authMethod = "token"
token = "your_super_secret_token"

# 注意：客户端的HTTP配置中没有Client子配置节

# ===================
# 证书配置
# ===================
# 可以定义多个证书
[[Certifications]]
name = "web-server"
savePath = "/etc/ssl/certs"
domains = [
    "www.example.com",
    "api.example.com"
]
reloadCommand = "systemctl reload nginx"

[[Certifications]]
name = "mail-server"
savePath = "/etc/postfix/ssl"
domains = [
    "mail.example.com",
    "smtp.example.com"
]
reloadCommand = "systemctl reload postfix"

[[Certifications]]
name = "wildcard"
savePath = "/etc/ssl/wildcard"
domains = [
    "*.example.com"
]
# 多个命令用分号分隔
reloadCommand = "systemctl reload nginx; systemctl reload apache2"

# ===================
# 日志配置
# ===================
[Logging]
level = "info"
file = "/var/log/certdx/client.log"
format = "text"
```

### gRPC 模式配置

```toml
[Common]
mode = "grpc"
retryCount = 3
reconnectInterval = "10m"

# ===================
# gRPC 服务器配置
# ===================
[GRPC]
# 主服务器配置
[GRPC.MainServer]
server = "grpc.example.com:9000"
ca = "/etc/certdx/ca.pem"
certificate = "/etc/certdx/client.pem"
key = "/etc/certdx/client.key"

# 备用服务器配置（可选）
[GRPC.StandbyServer]
server = "grpc-backup.example.com:9000"
ca = "/etc/certdx/ca.pem"
certificate = "/etc/certdx/client-backup.pem"
key = "/etc/certdx/client-backup.key"

# 其他配置与 HTTP 模式相同...
```

## Caddy 插件配置

### 基本配置

`Caddyfile`:

```caddyfile
{
    auto_https off
    certdx {
        retry_count 5
        mode http
        reconnect_interval 10m

        http {
            main_server {
                url https://certdx.example.com:10001/
                authMethod token
                token your_super_secret_token
            }
            
            standby_server {
                url https://certdx-backup.example.com:10001/
                authMethod token
                token your_super_secret_token
            }
        }

        # 定义证书
        certificate web-cert {
            example.com
            www.example.com
            api.example.com
        }
        
        certificate wildcard-cert {
            *.example.com
        }
    }
}

# 使用证书
https://example.com {
    tls {
        get_certificate certdx web-cert
    }
    reverse_proxy localhost:8080
}

https://api.example.com {
    tls {
        get_certificate certdx web-cert
    }
    reverse_proxy localhost:8081
}
```

### mTLS 配置

```caddyfile
{
    certdx {
        mode grpc
        
        GRPC {
            main_server {
                server grpc.example.com:9000
                ca /etc/certdx/ca.pem
                certificate /etc/certdx/client.pem
                key /etc/certdx/client.key
            }
        }
        
        certificate secure-cert {
            secure.example.com
        }
    }
}
```

## 安全最佳实践

### 1. 文件权限

```bash
# 配置文件权限
chmod 600 /etc/certdx/*.toml
chown certdx:certdx /etc/certdx/*.toml

# 证书文件权限
chmod 600 /etc/ssl/private/*.key
chmod 644 /etc/ssl/certs/*.pem
```

### 2. Token 安全

```bash
# 生成强随机 Token
openssl rand -base64 32

# 或者使用 uuidgen
uuidgen | tr -d '-'
```

### 3. 网络安全

- 使用 HTTPS/TLS 加密通信
- 限制服务器监听地址
- 配置防火墙规则
- 使用 VPN 或内网通信

### 4. 域名安全

- 严格控制 `allowedDomains` 列表
- 定期审查证书申请日志
- 监控异常证书申请

---

> **下一步**: 配置完成后，查看 [部署示例](04-deployment-examples.md) 了解不同场景的部署方案。
