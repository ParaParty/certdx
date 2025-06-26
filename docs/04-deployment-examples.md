# 部署示例

## TL;DR

```bash
# 单机部署
./certdx_server --conf server.toml &
./certdx_client --conf client.toml

# 生产环境部署（需手动执行以下步骤）
# 1. 配置负载均衡器
# 2. 部署多个服务器实例
# 3. 配置客户端连接到负载均衡器

# Caddy 集成
caddy run --config Caddyfile
```

## 场景 1: 单机部署（开发/测试）

### 架构图

```text
┌─────────────────┐
│   同一台服务器    │
│ ┌─────────────┐ │
│ │ certdx-server │ │
│ └─────────────┘ │
│ ┌─────────────┐ │
│ │ certdx-client │ │
│ └─────────────┘ │
│ ┌─────────────┐ │
│ │Caddy (示例)  │ │
│ └─────────────┘ │
└─────────────────┘
```

### 部署步骤

1. **下载和安装**

```bash
wget https://github.com/ParaParty/certdx/releases/latest/download/certdx_linux_amd64.tar.gz
tar -xzf certdx_linux_amd64.tar.gz
sudo cp certdx_* /usr/local/bin/
```

1. 配置服务器 (`server.toml`)

```toml
[ACME]
email = "admin@example.com"
provider = "r3test"  # 测试环境使用 staging
allowedDomains = ["*.example.com"]

[DnsProvider]
type = "cloudflare"
authToken = "your_token"

[HttpServer]
enabled = true
secure = false  # 单机测试可以不用 HTTPS
listen = "127.0.0.1:10001"
apiPath = "/"
authMethod = "token"
token = "test-token-123"
```

2. 配置客户端 (`client.toml`)

```toml
[Http.MainServer]
url = "http://127.0.0.1:10001/"
token = "test-token-123"

[[Certifications]]
name = "web"
savePath = "/var/lib/caddy/certificates"
domains = ["test.example.com"]
reloadCommand = "caddy reload --config /etc/caddy/Caddyfile"
```

4. 启动服务

```bash
# 启动服务器
certdx_server --conf server.toml &

# 启动客户端
certdx_client --conf client.toml &
```

## 场景 2: 生产环境集中部署

### 架构图

```text
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Web Server 1   │    │  Web Server 2   │    │  Mail Server    │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │certdx-client│ │    │ │certdx-client│ │    │ │certdx-client│ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │Caddy (用户)  │ │    │ │Caddy (用户)  │ │    │ │postfix (用户)│ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │ CertDX Server   │
                    │ (证书管理服务)   │
                    └─────────────────┘
```

> **说明**: 图中的Caddy、postfix等是用户需要自行安装和配置的Web服务器/邮件服务器，certdx负责为这些服务提供SSL证书。

### 服务器部署

1. 高可用服务器配置

```toml
# 主服务器 (server1.toml)
[ACME]
email = "ssl-admin@company.com"
provider = "r3"
allowedDomains = [
    "*.company.com",
    "*.api.company.com",
    "mail.company.com"
]

[DnsProvider]
type = "cloudflare"
authToken = "production_token"

[HttpServer]
enabled = true
secure = true
listen = "0.0.0.0:10001"
apiPath = "/"
authMethod = "token"
names = ["certdx.company.com"]
token = "super_secure_production_token"

# 备用服务器 (server2.toml) - 相同配置，不同监听地址
```

2. 负载均衡配置示例 (用户自行配置)

> **重要说明**: 以下负载均衡配置**不是certdx的功能**，而是用户需要自行配置的外部负载均衡器。certdx本身不提供负载均衡功能。

**Caddy负载均衡配置** (用户需自行配置):

```caddyfile
# 用户需要自行配置的Caddy反向代理
# 这不是certdx的组成部分
certdx.company.com {
    reverse_proxy {
        to 10.0.1.10:10001 10.0.1.11:10001
        
        health_uri /
        health_interval 30s
        health_timeout 5s
        
        fail_duration 30s
        max_fails 3
        
        lb_policy round_robin
    }
    
    tls {
        # 证书文件需要用户自行获取或配置
        cert /etc/ssl/certs/certdx.pem
        key /etc/ssl/private/certdx.key
    }
}
```

### 客户端部署

**Web服务器客户端配置**:

```toml
[Common]
mode = "http"
retryCount = 5

[Http.MainServer]
url = "https://certdx.company.com/"
token = "super_secure_production_token"

[Http.StandbyServer]
url = "https://certdx-backup.company.com/"
token = "super_secure_production_token"

[[Certifications]]
name = "web-ssl"
savePath = "/var/lib/caddy/certificates"  # Caddy证书存放路径
domains = [
    "www.company.com",
    "api.company.com",
    "app.company.com"
]
reloadCommand = "caddy reload --config /etc/caddy/Caddyfile"  # 重载Caddy配置

[[Certifications]]
name = "internal-ssl"
savePath = "/etc/ssl/internal"
domains = ["internal.company.com"]
reloadCommand = "systemctl reload internal-service"
```

> **说明**: 
> - `savePath` 指定certdx将证书文件保存的位置
> - `reloadCommand` 是证书更新后执行的命令，用于通知Caddy等服务重新加载证书
> - 用户需要自行配置Caddy等Web服务器来使用这些证书文件

## 场景 3: 多服务器生产部署

### 架构设计

```text
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web服务器 1   │    │   Web服务器 2   │    │   API服务器     │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │certdx-client│ │    │ │certdx-client│ │    │ │certdx-client│ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │Caddy (用户)  │ │    │ │Caddy (用户)  │ │    │ │node.js (用户)│ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Certdx服务器   │
                    │ (中央证书管理)  │
                    └─────────────────┘
```

### 部署步骤

1. **部署中央服务器**
```bash
# 在证书管理服务器上
wget https://github.com/ParaParty/certdx/releases/latest/download/certdx_linux_amd64.tar.gz
tar -xzf certdx_linux_amd64.tar.gz
sudo cp certdx_server /usr/local/bin/

# 配置并启动服务
sudo systemctl enable certdx-server
sudo systemctl start certdx-server
```

2. **在各个Web服务器上部署客户端**
```bash
# 在每台Web服务器上
wget https://github.com/ParaParty/certdx/releases/latest/download/certdx_linux_amd64.tar.gz
tar -xzf certdx_linux_amd64.tar.gz
sudo cp certdx_client /usr/local/bin/

# 配置客户端连接到中央服务器
sudo systemctl enable certdx-client
sudo systemctl start certdx-client
```

3. **验证部署**
```bash
# 检查证书同步
ls -la /var/lib/caddy/certificates/
sudo systemctl status certdx-client
```

## 场景 4: Caddy 原生集成部署

### Caddyfile 配置
```caddyfile
{
    auto_https off
    certdx {
        retry_count 5
        mode http
        reconnect_interval 5m
        
        http {
            main_server {
                url https://certdx.company.com/
                authMethod token
                token {env.CERTDX_TOKEN}
            }
        }
        
        certificate web-cert {
            company.com
            www.company.com
            api.company.com
            *.api.company.com
        }
        
        certificate admin-cert {
            admin.company.com
            dashboard.company.com
        }
    }
}

# 主网站
https://company.com {
    tls {
        get_certificate certdx web-cert
    }
    root * /var/www/html
    file_server
}

# API 服务
https://api.company.com {
    tls {
        get_certificate certdx web-cert
    }
    reverse_proxy localhost:8080
}

# 管理面板
https://admin.company.com {
    tls {
        get_certificate certdx admin-cert
    }
    reverse_proxy localhost:9000
    
    # 访问控制
    @admin {
        remote_ip 10.0.0.0/8 192.168.0.0/16
    }
    handle @admin {
        reverse_proxy localhost:9000
    }
    respond "Forbidden" 403
}
```

## 监控和验证

### 验证部署步骤

```bash
#!/bin/bash
# 手动验证部署状态

echo "=== Certdx 部署验证 ==="

# 检查服务状态
echo "1. 检查服务状态..."
if systemctl is-active --quiet certdx-server; then
    echo "✅ 服务器正在运行"
else
    echo "❌ 服务器未运行"
    exit 1
fi

# 检查API连通性 (使用实际API)
echo "2. 测试API连通性..."
response=$(curl -s -X POST \
    -H "Authorization: Token $CERTDX_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"domains":["test.example.com"]}' \
    "http://localhost:10001/" \
    || echo "API_ERROR")

if [[ "$response" != "API_ERROR" ]] && echo "$response" | grep -q "fullChain"; then
    echo "✅ API 可访问"
else
    echo "❌ API 不可访问"
    echo "响应: $response"
    exit 1
fi

# 检查缓存状态
echo "3. 检查证书缓存..."
if command -v certdx_tools >/dev/null 2>&1; then
    certdx_tools show-cache
    echo "✅ 缓存状态检查完成"
else
    echo "⚠️  certdx_tools 不可用，跳过缓存检查"
fi

echo "🎉 所有检查通过！部署成功。"
```

### 监控建议

**日志监控**:

```bash
# 查看服务器日志
journalctl -u certdx-server -f

# 查看客户端日志  
journalctl -u certdx-client -f
```

**系统监控**:

```bash
# 检查进程状态
ps aux | grep certdx

# 检查端口占用
ss -tlnp | grep 10001
```

---

> **下一步**: 部署完成后，查看 [运维指南](05-operations.md) 了解日常管理和监控。
