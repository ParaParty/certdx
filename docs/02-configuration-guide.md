# 2. 配置指南

本指南详细介绍 Certdx 服务端和客户端的各项配置选项，包括基础配置、高级功能和生态集成。

## 2.1 服务端配置

### 基础配置结构

服务端使用 TOML 格式的配置文件，主要包含以下几个部分：

```toml
# 基本配置结构
[ACME]          # ACME相关配置
[DnsProvider]   # DNS提供商配置  
[HttpProvider]  # HTTP验证配置（可选）
[HttpServer]    # HTTP API服务器配置
[gRPCSDSServer] # gRPC SDS服务器配置（可选）
[GoogleCloudCredential] # Google Cloud凭证（可选）
```

### ACME 提供商配置

#### 支持的 ACME 提供商

| 提供商 | provider值 | 环境 | 说明 |
|--------|------------|------|------|
| Let's Encrypt (生产) | `r3` | 生产 | 推荐，免费，广泛支持 |
| Let's Encrypt (测试) | `r3test` | 测试 | 用于开发测试 |
| Google Trust Services | `google` | 生产 | 需要Google Cloud账号 |
| Google Trust Services (测试) | `googletest` | 测试 | Google测试环境 |

#### 详细配置选项

```toml
[ACME]
# 【必需】注册邮箱，用于ACME账号注册和重要通知
email = "ssl-admin@company.com"

# 【必需】ACME提供商
# 可选值: r3, r3test, google, googletest
provider = "r3"

# 错误重试次数，默认5次
retryCount = 5

# 验证方式，目前只支持dns
challengeType = "dns"

# 证书生命周期设置
# certLifeTime: 证书有效期（从颁发时间开始计算）
# renewTimeLeft: 续期提前时间（在证书到期前多久开始续期）
# 实际证书有效期 = certLifeTime + renewTimeLeft
certLifeTime = "168h"   # 7天
renewTimeLeft = "24h"   # 1天

# 【必需】允许申请证书的根域名列表
# 只有这些域名及其子域名可以申请证书
allowedDomains = [
    "company.com",
    "dev.company.com",
    "test.company.com"
]
```

#### 生产环境建议

**Let's Encrypt 生产配置**：
```toml
[ACME]
email = "ssl-team@company.com"
provider = "r3"
retryCount = 3
certLifeTime = "720h"    # 30天
renewTimeLeft = "168h"   # 7天
allowedDomains = ["company.com"]
```

**测试环境配置**：
```toml
[ACME]
email = "dev-team@company.com"
provider = "r3test"
retryCount = 5
certLifeTime = "24h"     # 1天
renewTimeLeft = "6h"     # 6小时
allowedDomains = ["test.company.com", "dev.company.com"]
```

### DNS 提供商配置

#### Cloudflare 配置

**方式1：使用 API Token（推荐）**

```toml
[DnsProvider]
type = "cloudflare"
# API Token需要Zone:Edit权限
authToken = "your-api-token"
# Zone Token（可选，用于特定区域）
zoneToken = "your-zone-token"
# 禁用完整传播检查（加速验证，但可能不够可靠）
disableCompletePropagationRequirement = false
```

**获取 Cloudflare API Token**：
1. 登录 Cloudflare 控制台
2. 进入"我的个人资料" → "API令牌"  
3. 点击"创建令牌"
4. 选择"自定义令牌"模板
5. 权限设置：
   - Zone:Zone:Read
   - Zone:DNS:Edit
6. 区域资源：包含所有区域或特定区域

**方式2：使用 Global API Key**

```toml
[DnsProvider]
type = "cloudflare"
# 全局API密钥
email = "your-cloudflare-email@example.com"
apiKey = "your-global-api-key"
```

#### 腾讯云 DNS 配置

```toml
[DnsProvider]
type = "tencent"
# 腾讯云API密钥
secretID = "your-secret-id"
secretKey = "your-secret-key"
# 可选：指定区域
region = "ap-beijing"
```

**获取腾讯云 API 密钥**：
1. 登录腾讯云控制台
2. 进入"访问管理" → "API密钥管理"
3. 创建子用户密钥（推荐）或使用主账号密钥
4. 授予DNS解析相关权限

#### AWS Route53 配置

```toml
[DnsProvider]
type = "route53"
# AWS访问密钥
accessKeyID = "your-access-key-id"
secretAccessKey = "your-secret-access-key"
# 可选：会话令牌（临时凭证）
sessionToken = "your-session-token"
# 可选：指定区域
region = "us-east-1"
```

#### 阿里云 DNS 配置

```toml
[DnsProvider]
type = "alidns"
# 阿里云访问密钥
accessKeyID = "your-access-key-id"
accessKeySecret = "your-access-key-secret"
# 可选：区域
regionID = "cn-hangzhou"
```

### HTTP API 服务器配置

#### 基础配置

```toml
[HttpServer]
# 【必需】启用HTTP API服务器
enabled = true

# 【必需】监听地址
listen = ":19198"

# 【必需】API基础路径
apiPath = "/api"

# 启用HTTPS
secure = true

# 【必需】服务器证书域名
names = ["certdx.company.com"]

# 【必需】API访问令牌
token = "your-secure-api-token-min-32-chars"
```

#### 高级配置

```toml
[HttpServer]
enabled = true
listen = ":19198"
apiPath = "/api/v1"
secure = true
names = ["certdx.company.com"]
token = "your-secure-api-token"

# 自定义证书文件（可选）
# certFile = "/path/to/server.crt"
# keyFile = "/path/to/server.key"

# 客户端证书验证（可选）
# requireClientCert = true
# clientCAs = ["/path/to/client-ca.pem"]

# 超时设置
readTimeout = "30s"
writeTimeout = "30s"
idleTimeout = "60s"

# 请求限制
maxRequestSize = "1MB"
rateLimitPerSecond = 100

# CORS设置
allowOrigins = ["https://admin.company.com"]
allowMethods = ["GET", "POST"]
allowHeaders = ["Authorization", "Content-Type"]
```

### gRPC SDS 服务器配置（可选）

```toml
[gRPCSDSServer]
# 启用gRPC SDS服务器
enabled = true
listen = ":11451"
names = ["grpc-certdx.company.com"]

# TLS配置
# tlsCertFile = "/path/to/grpc-server.crt"
# tlsKeyFile = "/path/to/grpc-server.key"

# mTLS配置
# requireClientCert = true
# clientCAFile = "/path/to/grpc-client-ca.pem"

# gRPC选项
maxReceiveMessageSize = "4MB"
maxSendMessageSize = "4MB"
connectionTimeout = "30s"
keepAliveTime = "30s"
keepAliveTimeout = "5s"
```

### Google Cloud 配置（仅 Google CA）

```toml
[GoogleCloudCredential]
type = "service_account"
project_id = "your-gcp-project-id"
private_key_id = "your-private-key-id"
private_key = """-----BEGIN PRIVATE KEY-----
your-private-key-content
-----END PRIVATE KEY-----"""
client_email = "certdx@your-project.iam.gserviceaccount.com"
client_id = "your-client-id"
auth_uri = "https://accounts.google.com/o/oauth2/auth"
token_uri = "https://oauth2.googleapis.com/token"

# 或者指定服务账号密钥文件路径
# credentialsFile = "/path/to/service-account-key.json"
```

## 2.2 客户端配置

### 基础配置结构

```toml
# 客户端配置文件结构
[Http.MainServer]     # 主服务器配置
[Http.StandbyServer]  # 备用服务器配置（可选）
[[Certifications]]    # 证书配置（可配置多个）
```

### 服务器连接配置

#### 基础连接配置

```toml
[Http.MainServer]
# 服务器 URL
url = "https://certdx.company.com:19198/api"
# 认证令牌
token = "your-secure-api-token"
# 连接超时
timeout = "30s"
# 是否跳过证书验证（仅用于调试）
# insecureSkipVerify = false
```

#### 高可用配置

```toml
[Http.MainServer]
url = "https://certdx-primary.company.com:19198/api"
token = "your-secure-api-token"
timeout = "30s"

[Http.StandbyServer]
url = "https://certdx-backup.company.com:19198/api"
token = "your-secure-api-token"
timeout = "30s"
```

### 证书配置

#### 单个证书配置

```toml
[[Certifications]]
# 证书名称（唯一标识）
name = "web-server-cert"

# 证书存储路径
savePath = "/etc/ssl/certs"

# 域名列表
domains = [
    "www.company.com",
    "api.company.com",
    "admin.company.com"
]

# 证书文件名（可选，默认使用 name）
# certFileName = "company.crt"
# keyFileName = "company.key"

# 文件权限（可选）
# fileMode = "0600"

# 证书更新后执行的命令
reloadCommand = "systemctl reload nginx"

# 检查间隔（可选）
# checkInterval = "1h"
```

#### 多证书配置

```toml
[[Certifications]]
name = "web-frontend"
savePath = "/etc/nginx/ssl"
domains = ["www.company.com", "company.com"]
reloadCommand = "nginx -s reload"

[[Certifications]]
name = "api-backend"
savePath = "/etc/apache2/ssl"
domains = ["api.company.com", "api-v2.company.com"]
reloadCommand = "systemctl reload apache2"

[[Certifications]]
name = "internal-services"
savePath = "/opt/app/certs"
domains = ["internal.company.com", "monitoring.company.com"]
reloadCommand = "/opt/app/reload-certs.sh"
```

### 高级客户端配置

```toml
# 全局客户端配置
[Client]
# 日志级别
logLevel = "info"
# 日志文件
logFile = "/var/log/certdx/client.log"
# 工作目录
workDir = "/var/lib/certdx"
# 检查间隔
checkInterval = "1h"
# 最大重试次数
maxRetries = 3
# 重试间隔
retryInterval = "5m"

[Http.MainServer]
url = "https://certdx.company.com:19198/api"
token = "your-secure-api-token"
timeout = "30s"
# 自定义CA证书
# caCert = "/path/to/ca.pem"
# 客户端证书（mTLS）
# clientCert = "/path/to/client.crt"
# clientKey = "/path/to/client.key"

[[Certifications]]
name = "production-web"
savePath = "/etc/ssl/production"
domains = ["www.company.com", "company.com"]
reloadCommand = "systemctl reload nginx"
# 检查间隔覆盖全局设置
checkInterval = "30m"
# 续期提前时间
renewBefore = "168h"  # 7天
# 最小证书有效期
minValidDuration = "720h"  # 30天
```

## 2.3 生态集成

### Caddy 插件集成

#### 安装 Caddy 插件

```bash
# 方法1：使用xcaddy编译
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/ParaParty/certdx/exec/caddytls

# 方法2：下载预编译版本
wget https://github.com/ParaParty/certdx/releases/latest/download/caddy-with-certdx
```

#### Caddyfile 配置

```caddyfile
# 基础配置
{
    cert_issuer certdx {
        server https://certdx.company.com:19198/api
        token your-secure-api-token
    }
}

# 站点配置
www.company.com {
    tls {
        issuer certdx
    }
    reverse_proxy backend:8080
}

api.company.com {
    tls {
        issuer certdx
    }
    reverse_proxy api-server:3000
}
```

#### 高级 Caddy 配置

```caddyfile
{
    cert_issuer certdx primary {
        server https://certdx-primary.company.com:19198/api
        token primary-token
        timeout 30s
    }
    
    cert_issuer certdx backup {
        server https://certdx-backup.company.com:19198/api
        token backup-token
        timeout 30s
    }
}

# 多站点配置
(common_tls) {
    tls {
        issuer certdx primary
        issuer certdx backup
    }
}

www.company.com {
    import common_tls
    root * /var/www/html
    file_server
}

*.api.company.com {
    import common_tls
    reverse_proxy api-cluster:8080
}
```

### Kubernetes 集成

#### cert-manager ClusterIssuer

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: certdx-issuer
spec:
  certdx:
    # Certdx服务器地址
    server: https://certdx.company.com:19198/api
    # 认证令牌
    token: 
      secretKeyRef:
        name: certdx-token
        key: token
    # 自定义CA证书（可选）
    caBundle: LS0tLS1CRUdJTi... # base64编码的CA证书
```

#### 创建认证密钥

```bash
kubectl create secret generic certdx-token \
  --from-literal=token=your-secure-api-token \
  -n cert-manager
```

#### Certificate 资源配置

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: web-app-tls
  namespace: default
spec:
  secretName: web-app-tls-secret
  issuerRef:
    name: certdx-issuer
    kind: ClusterIssuer
  dnsNames:
    - app.company.com
    - www.app.company.com
    - api.app.company.com
```

#### Ingress 配置

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web-app-ingress
  annotations:
    cert-manager.io/cluster-issuer: certdx-issuer
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
    - hosts:
        - app.company.com
        - www.app.company.com
      secretName: web-app-tls-secret
  rules:
    - host: app.company.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: web-app-service
                port:
                  number: 80
```

### Envoy/Istio 集成

#### Envoy SDS 配置

```yaml
static_resources:
  clusters:
    - name: certdx-sds
      type: LOGICAL_DNS
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: certdx-sds
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: grpc-certdx.company.com
                      port_value: 11451
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: grpc-certdx.company.com

  listeners:
    - name: https-listener
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 443
      filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_certificate_sds_secret_configs:
                  - name: app.company.com
                    sds_config:
                      api_config_source:
                        api_type: GRPC
                        grpc_services:
                          - envoy_grpc:
                              cluster_name: certdx-sds
```

## 2.4 配置参数完整参考

### 服务端配置参数

| 配置项 | 类型 | 默认值 | 描述 |
|--------|------|--------|------|
| **[ACME]** | | | |
| `email` | string | *必需* | ACME账号注册邮箱 |
| `provider` | string | *必需* | ACME提供商：r3, r3test, google, googletest |
| `retryCount` | int | 5 | 错误重试次数 |
| `challengeType` | string | "dns" | 验证方式 |
| `certLifeTime` | duration | "168h" | 证书生命周期 |
| `renewTimeLeft` | duration | "24h" | 续期提前时间 |
| `allowedDomains` | []string | *必需* | 允许申请证书的根域名 |
| **[DnsProvider]** | | | |
| `type` | string | *必需* | DNS提供商类型 |
| `authToken` | string | - | Cloudflare API Token |
| `email` | string | - | Cloudflare邮箱 |
| `apiKey` | string | - | Cloudflare Global API Key |
| `secretID` | string | - | 腾讯云Secret ID |
| `secretKey` | string | - | 腾讯云Secret Key |
| `accessKeyID` | string | - | AWS/阿里云Access Key ID |
| `secretAccessKey` | string | - | AWS Secret Access Key |
| **[HttpServer]** | | | |
| `enabled` | bool | true | 启用HTTP API服务器 |
| `listen` | string | ":19198" | 监听地址 |
| `apiPath` | string | "/api" | API基础路径 |
| `secure` | bool | true | 启用HTTPS |
| `names` | []string | *必需* | 服务器证书域名 |
| `token` | string | *必需* | API访问令牌 |
| `readTimeout` | duration | "30s" | 读取超时 |
| `writeTimeout` | duration | "30s" | 写入超时 |

### 客户端配置参数

| 配置项 | 类型 | 默认值 | 描述 |
|--------|------|--------|------|
| **[Client]** | | | |
| `logLevel` | string | "info" | 日志级别 |
| `logFile` | string | - | 日志文件 |
| `workDir` | string | - | 工作目录 |
| `checkInterval` | duration | "1h" | 检查间隔 |
| `maxRetries` | int | 3 | 最大重试次数 |
| **[Http.MainServer]** | | | |
| `url` | string | *必需* | 服务器URL |
| `token` | string | *必需* | 认证令牌 |
| `timeout` | duration | "30s" | 连接超时 |
| `insecureSkipVerify` | bool | false | 跳过证书验证 |
| **[[Certifications]]** | | | |
| `name` | string | *必需* | 证书名称 |
| `savePath` | string | *必需* | 存储路径 |
| `domains` | []string | *必需* | 域名列表 |
| `reloadCommand` | string | - | 重载命令 |
| `checkInterval` | duration | - | 检查间隔 |
| `renewBefore` | duration | "168h" | 续期提前时间 |

---

## 小结

本章介绍了 Certdx 的完整配置方案：
- ✅ 服务端各模块详细配置
- ✅ 客户端灵活配置选项
- ✅ 主流生态系统集成方法
- ✅ 完整配置参数参考

**下一步**：查看 [运维指南](03-operations-guide.md)，了解日常运维和问题解决。 