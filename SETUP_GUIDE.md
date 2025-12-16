# CertDX Complete Setup Guide

A comprehensive guide to set up CertDX server and client from scratch for automated certificate management.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Phase 1: Server Setup](#phase-1-server-setup)
3. [Phase 2: Client Setup](#phase-2-client-setup)
4. [Phase 3: Verification](#phase-3-verification)
5. [Phase 4: Production Deployment](#phase-4-production-deployment)
6. [Troubleshooting](#troubleshooting)
7. [Quick Reference](#quick-reference)

---

## Prerequisites

Before starting, ensure you have:

- **Two machines or services**: one for server, one for client
- **Go environment**: CertDX is written in Go
- **Domain names**: At least one domain for certificate issuance
- **ACME provider account**: Let's Encrypt, Google, or other ACME provider
- **DNS access**: For DNS-01 challenge validation (recommended)
- **DNS provider credentials**: 
  - For Cloudflare: API key or auth token
  - For Tencent Cloud: Secret ID and key
- **S3 or compatible storage** (optional): For HTTP-01 challenges
- **Google Cloud credentials** (optional): Only if using Google ACME provider

---

## Phase 1: Server Setup

### Step 1.1: Build CertDX Server and Tools

Build the server executable:
```bash
cd /path/to/certdx/exec/server
go build -o certdx_server
```

Build the tools executable:
```bash
cd /path/to/certdx/exec/tools
go build -o certdx_tools
```

Set up the installation directory:
```bash
mkdir -p /opt/certdx/mtls
cp certdx_server /opt/certdx/
cp certdx_tools /opt/certdx/
cd /opt/certdx/
```

### Step 1.2: Generate mTLS Certificates (Recommended)

**This step is optional but highly recommended for production.**

Generate the CA certificate (run once):
```bash
./certdx_tools make-ca
```

Generate the server certificate:
```bash
./certdx_tools make-server -d grpc.example.com
```

Generate client certificate (will be copied to client):
```bash
./certdx_tools make-client -n client-app-1
```

**Certificate files created in `/opt/certdx/mtls/`:**
- `ca.pem` - CA public certificate
- `ca.key` - CA private key
- `server.pem` - Server certificate
- `server.key` - Server private key
- `client-app-1.pem` - Client certificate
- `client-app-1.key` - Client private key

### Step 1.3: Create Server Configuration

Create `/opt/certdx/server_config.toml`:

#### Option A: Production with Let's Encrypt and Cloudflare DNS

```toml
[ACME]
email = "admin@example.com"
provider = "r3"
retryCount = 5
challengeType = "dns"
certLifeTime = "168h"
renewTimeLeft = "24h"
allowedDomains = ["example.com", "another-domain.com"]

[DnsProvider]
disableCompletePropagationRequirement = false
type = "cloudflare"
email = "your-email@example.com"
apiKey = "your-cloudflare-global-api-key"

[HttpServer]
enabled = true
listen = ":19198"
apiPath = "/your-random-secret-path"
authMethod = "mtls"
secure = true
names = ["certdx.example.com"]

[gRPCSDSServer]
enabled = true
listen = ":11451"
```

#### Option B: Testing with Let's Encrypt Staging

```toml
[ACME]
email = "test@example.com"
provider = "r3test"
retryCount = 3
challengeType = "dns"
certLifeTime = "168h"
renewTimeLeft = "24h"
allowedDomains = ["example.com"]

[DnsProvider]
disableCompletePropagationRequirement = false
type = "cloudflare"
email = "your-email@example.com"
apiKey = "your-api-key"

[HttpServer]
enabled = true
listen = ":19198"
apiPath = "/test-path"
authMethod = "token"
secure = false
token = "test-token-12345"

[gRPCSDSServer]
enabled = true
listen = ":11451"
```

#### Option C: Tencent Cloud ACME

```toml
[ACME]
email = "admin@example.com"
provider = "google"
retryCount = 5
challengeType = "dns"
certLifeTime = "168h"
renewTimeLeft = "24h"
allowedDomains = ["example.com"]

[DnsProvider]
type = "tencent"
secretID = "your-secret-id"
SecretKey = "your-secret-key"

[HttpServer]
enabled = true
listen = ":19198"
apiPath = "/your-random-path"
authMethod = "mtls"
secure = true
names = ["certdx.example.com"]

[gRPCSDSServer]
enabled = true
listen = ":11451"
```

**Configuration Notes:**
- `certLifeTime` + `renewTimeLeft` = actual certificate lifetime
- Example: 168h + 24h = 192h (8 days) certificate lifetime
- Renewal starts at 168h mark with 24h grace period
- Generate random string for `apiPath` (acts as minimal security layer)
- For `secure = true`, server must have certificates in `allowedDomains`

### Step 1.4: Start the Server

```bash
cd /opt/certdx
./certdx_server -config server_config.toml
```

Verify server is listening:
```bash
# Test HTTP API endpoint
curl -k https://localhost:19198/your-random-secret-path

# Test gRPC SDS port (should timeout or error without proper client)
nc -zv localhost 11451
```

---

## Phase 2: Client Setup

### Step 2.1: Build CertDX Client

Build the client executable:
```bash
cd /path/to/certdx/exec/client
go build -o certdx_client
```

Set up the installation directory:
```bash
mkdir -p /opt/certdx-client/mtls
cp certdx_client /opt/certdx-client/
cd /opt/certdx-client/
```

### Step 2.2: Configure mTLS Certificates (if using mTLS)

Copy certificates from server to client:

```bash
# From the client machine, copy from server
scp user@server:/opt/certdx/mtls/ca.pem /opt/certdx-client/mtls/
scp user@server:/opt/certdx/mtls/client-app-1.pem /opt/certdx-client/mtls/
scp user@server:/opt/certdx/mtls/client-app-1.key /opt/certdx-client/mtls/

# Set proper permissions
chmod 600 /opt/certdx-client/mtls/client-app-1.key
chmod 644 /opt/certdx-client/mtls/ca.pem
chmod 644 /opt/certdx-client/mtls/client-app-1.pem
```

### Step 2.3: Create Client Configuration

Create `/opt/certdx-client/client_config.toml`:

#### Option A: HTTP Mode with mTLS Authentication

```toml
[Common]
retryCount = 5
mode = "http"

[Http.MainServer]
url = "https://certdx.example.com:19198/your-random-secret-path"
authMethod = "mtls"
ca = "/opt/certdx-client/mtls/ca.pem"
certificate = "/opt/certdx-client/mtls/client-app-1.pem"
key = "/opt/certdx-client/mtls/client-app-1.key"

[[Certifications]]
name = "web"
savePath = "/etc/ssl/private"
domains = ["example.com", "*.example.com"]
reloadCommand = "systemctl reload nginx"

[[Certifications]]
name = "api"
savePath = "/etc/ssl/private"
domains = ["api.example.com", "*.api.example.com"]
reloadCommand = "systemctl restart myapi"
```

#### Option B: HTTP Mode with Token Authentication

```toml
[Common]
retryCount = 5
mode = "http"

[Http.MainServer]
url = "https://certdx.example.com:19198/your-random-secret-path"
authMethod = "token"
token = "your-strong-random-token-here"

[[Certifications]]
name = "web"
savePath = "/etc/ssl/private"
domains = ["example.com", "*.example.com"]
reloadCommand = "systemctl reload nginx"
```

#### Option C: HTTP Mode with Failover

```toml
[Common]
retryCount = 5
mode = "http"

[Http.MainServer]
url = "https://certdx-primary.example.com:19198/api-path"
authMethod = "mtls"
ca = "/opt/certdx-client/mtls/ca.pem"
certificate = "/opt/certdx-client/mtls/client-app-1.pem"
key = "/opt/certdx-client/mtls/client-app-1.key"

[Http.StandbyServer]
url = "https://certdx-backup.example.com:19198/api-path"

[[Certifications]]
name = "web"
savePath = "/etc/ssl/private"
domains = ["example.com", "*.example.com"]
reloadCommand = "systemctl reload nginx"
```

#### Option D: gRPC Mode (Advanced)

```toml
[Common]
retryCount = 5
mode = "grpc"
reconnectInterval = "5m"

[GRPC.MainServer]
server = "certdx.example.com:11451"
ca = "/opt/certdx-client/mtls/ca.pem"
certificate = "/opt/certdx-client/mtls/client-app-1.pem"
key = "/opt/certdx-client/mtls/client-app-1.key"

[[Certifications]]
name = "web"
savePath = "/etc/ssl/private"
domains = ["example.com", "*.example.com"]
reloadCommand = "systemctl reload nginx"
```

#### Option E: gRPC Mode with Failover

```toml
[Common]
retryCount = 5
mode = "grpc"
reconnectInterval = "5m"

[GRPC.MainServer]
server = "certdx-1.example.com:11451"
ca = "/opt/certdx-client/mtls/ca.pem"
certificate = "/opt/certdx-client/mtls/client-app-1.pem"
key = "/opt/certdx-client/mtls/client-app-1.key"

[GRPC.StandbyServer]
server = "certdx-2.example.com:11451"
ca = "/opt/certdx-client/mtls/ca.pem"
certificate = "/opt/certdx-client/mtls/client-app-1.pem"
key = "/opt/certdx-client/mtls/client-app-1.key"

[[Certifications]]
name = "frontend"
savePath = "/opt/myapp/certs"
domains = ["*.myapp.com"]
reloadCommand = "systemctl reload nginx"
```

**Configuration Notes:**
- Use absolute paths for `ca`, `certificate`, and `key`
- Multiple `[[Certifications]]` sections allow multiple certificate sets
- Each certificate can cover multiple domains (SAN - Subject Alternative Names)
- `reloadCommand` is executed when certificates are renewed
- If no reload needed, omit `reloadCommand`

### Step 2.4: Create Certificate Save Directory

```bash
mkdir -p /etc/ssl/private
chmod 755 /etc/ssl/private
```

Ensure the directory is writable by the client process user.

### Step 2.5: Start the Client

```bash
cd /opt/certdx-client
./certdx_client -config client_config.toml
```

Monitor logs to verify:
- Connection to server succeeds
- Certificates are retrieved
- Files are saved to `savePath`
- Reload commands execute successfully

---

## Phase 3: Verification

### Server-Side Verification

Check server process:
```bash
ps aux | grep certdx_server
```

View cached certificates:
```bash
/opt/certdx/certdx_tools show-cache
```

Check server logs:
```bash
journalctl -u certdx-server -f  # if using systemd
```

### Client-Side Verification

Check client process:
```bash
ps aux | grep certdx_client
```

Verify certificates were saved:
```bash
ls -la /etc/ssl/private/web.*
```

Inspect certificate content:
```bash
openssl x509 -in /etc/ssl/private/web.pem -text -noout
```

Verify certificate domains:
```bash
openssl x509 -in /etc/ssl/private/web.pem -noout -text | grep -A1 "Subject Alternative Name"
```

Check certificate expiration:
```bash
openssl x509 -in /etc/ssl/private/web.pem -noout -dates
```

Check client logs:
```bash
journalctl -u certdx-client -f  # if using systemd
```

---

## Phase 4: Production Deployment

### Create Non-Root User (Recommended)

```bash
sudo useradd -r -s /bin/false certdx
sudo chown -R certdx:certdx /opt/certdx
sudo chown -R certdx:certdx /opt/certdx-client
```

### Server Systemd Service

Create `/etc/systemd/system/certdx-server.service`:

```ini
[Unit]
Description=CertDX Certificate Management Server
After=network.target
Documentation=https://github.com/your-org/certdx

[Service]
Type=simple
User=certdx
Group=certdx
WorkingDirectory=/opt/certdx
ExecStart=/opt/certdx/certdx_server -config server_config.toml
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=certdx-server

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable certdx-server
sudo systemctl start certdx-server
```

Monitor:
```bash
sudo systemctl status certdx-server
sudo journalctl -u certdx-server -f
```

### Client Systemd Service

Create `/etc/systemd/system/certdx-client.service`:

```ini
[Unit]
Description=CertDX Certificate Client
After=network.target
Documentation=https://github.com/your-org/certdx

[Service]
Type=simple
User=certdx
Group=certdx
WorkingDirectory=/opt/certdx-client
ExecStart=/opt/certdx-client/certdx_client -config client_config.toml
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=certdx-client

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable certdx-client
sudo systemctl start certdx-client
```

Monitor:
```bash
sudo systemctl status certdx-client
sudo journalctl -u certdx-client -f
```

### Firewall Configuration

**Server-side (if using iptables/ufw):**

```bash
# Allow HTTP API port
sudo ufw allow 19198/tcp

# Allow gRPC SDS port
sudo ufw allow 11451/tcp

# Restrict to specific IPs (recommended)
sudo ufw allow from 192.168.1.0/24 to any port 19198
sudo ufw allow from 192.168.1.0/24 to any port 11451
```

**Client-side:**
- Ensure client can reach server on ports 19198 (HTTP) and 11451 (gRPC)
- Use VPN or private networks for production

### Log Management

Configure logrotate to manage server and client logs:

Create `/etc/logrotate.d/certdx`:
```
/var/log/certdx/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 certdx certdx
    sharedscripts
    postrotate
        systemctl reload certdx-server > /dev/null 2>&1 || true
        systemctl reload certdx-client > /dev/null 2>&1 || true
    endscript
}
```

### Monitoring and Alerting

**Check certificate expiration periodically:**

Create a monitoring script `/opt/certdx-client/check-certs.sh`:
```bash
#!/bin/bash
CERT_DIR="/etc/ssl/private"
ALERT_DAYS=14

for cert in $CERT_DIR/*.pem; do
    if [ -f "$cert" ]; then
        EXPIRY=$(openssl x509 -enddate -noout -in "$cert" | cut -d= -f2)
        EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
        NOW_EPOCH=$(date +%s)
        DAYS_LEFT=$(( ($EXPIRY_EPOCH - $NOW_EPOCH) / 86400 ))
        
        if [ $DAYS_LEFT -lt $ALERT_DAYS ]; then
            echo "WARNING: $cert expires in $DAYS_LEFT days"
        fi
    fi
done
```

Add to crontab:
```bash
0 0 * * * /opt/certdx-client/check-certs.sh
```

---

## Troubleshooting

### Client Cannot Connect to Server

**Symptoms:** Client logs show connection errors

**Solutions:**
1. **Verify server is running:**
   ```bash
   ps aux | grep certdx_server
   ```

2. **Check firewall:**
   ```bash
   nc -zv server-ip 19198  # For HTTP
   nc -zv server-ip 11451  # For gRPC
   ```

3. **Verify DNS:**
   ```bash
   nslookup certdx.example.com
   ping certdx.example.com
   ```

4. **Check configuration:**
   - Verify `url` or `server` address in client config
   - Ensure ports match server configuration

### Certificate Not Saved

**Symptoms:** Certificate files don't appear in `savePath`

**Solutions:**
1. **Check directory permissions:**
   ```bash
   ls -ld /etc/ssl/private
   ```

2. **Verify directory exists:**
   ```bash
   mkdir -p /etc/ssl/private
   ```

3. **Check domain in allowedDomains:**
   ```bash
   # In server_config.toml, verify domain is listed
   grep -A5 "allowedDomains" server_config.toml
   ```

4. **Check logs for errors:**
   ```bash
   journalctl -u certdx-server -f
   journalctl -u certdx-client -f
   ```

### mTLS Connection Fails

**Symptoms:** TLS handshake errors, certificate validation failures

**Solutions:**
1. **Verify certificate files exist:**
   ```bash
   ls -la /opt/certdx-client/mtls/
   ```

2. **Check CA certificate matches:**
   ```bash
   # Compare server and client CA certificates
   diff /opt/certdx/mtls/ca.pem /opt/certdx-client/mtls/ca.pem
   ```

3. **Verify certificate validity:**
   ```bash
   openssl x509 -in /opt/certdx-client/mtls/client-app-1.pem -noout -text
   ```

4. **Check file permissions:**
   ```bash
   chmod 600 /opt/certdx-client/mtls/client-app-1.key
   ```

### Reload Command Not Executing

**Symptoms:** Certificates are retrieved but services aren't reloaded

**Solutions:**
1. **Verify command syntax in config:**
   ```bash
   # Test command manually
   systemctl reload nginx
   ```

2. **Check user permissions:**
   ```bash
   # Client process must have permission to execute
   sudo -u certdx systemctl reload nginx
   ```

3. **Use absolute paths:**
   ```toml
   reloadCommand = "/usr/bin/systemctl reload nginx"
   ```

4. **Check logs:**
   ```bash
   journalctl -u certdx-client -f | grep reload
   ```

### DNS Challenge Fails

**Symptoms:** ACME challenge validation errors in server logs

**Solutions:**
1. **Verify DNS provider credentials:**
   ```bash
   # Check config has correct API key
   grep -A3 "DnsProvider" server_config.toml
   ```

2. **Verify domain is in allowedDomains:**
   ```bash
   grep allowedDomains server_config.toml
   ```

3. **Test DNS resolution:**
   ```bash
   nslookup _acme-challenge.example.com
   ```

4. **Check DNS provider status:**
   - Ensure API key is not expired
   - Verify Cloudflare/Tencent account has DNS zone

### High Memory Usage

**Symptoms:** Server/client consuming excessive memory

**Solutions:**
1. **Check for memory leaks in logs**
2. **Restart services:**
   ```bash
   sudo systemctl restart certdx-server
   sudo systemctl restart certdx-client
   ```
3. **Monitor with:**
   ```bash
   top -p $(pgrep -f certdx)
   ```

---

## Quick Reference

### Important Directories

| Path | Purpose | User |
|------|---------|------|
| `/opt/certdx/` | Server installation | certdx |
| `/opt/certdx/mtls/` | mTLS certificates (server) | certdx |
| `/opt/certdx-client/` | Client installation | certdx |
| `/opt/certdx-client/mtls/` | mTLS certificates (client) | certdx |
| `/etc/ssl/private/` | Saved certificates | any |

### Important Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 19198 | HTTP/HTTPS | CertDX HTTP API |
| 11451 | gRPC | CertDX SDS Server |

### Common Commands

```bash
# Start services
sudo systemctl start certdx-server
sudo systemctl start certdx-client

# Stop services
sudo systemctl stop certdx-server
sudo systemctl stop certdx-client

# View logs (follow)
sudo journalctl -u certdx-server -f
sudo journalctl -u certdx-client -f

# Check service status
sudo systemctl status certdx-server
sudo systemctl status certdx-client

# View cached certificates
/opt/certdx/certdx_tools show-cache

# Inspect certificate
openssl x509 -in /etc/ssl/private/web.pem -text -noout

# Check certificate expiration
openssl x509 -in /etc/ssl/private/web.pem -noout -dates
```

### Security Checklist

- [ ] Use mTLS for authentication in production
- [ ] Generate strong random `apiPath` for HTTP API
- [ ] Use HTTPS/TLS for HTTP API (`secure = true`)
- [ ] Restrict firewall to known client IPs
- [ ] Secure private key files (`chmod 600`)
- [ ] Use non-root user for services
- [ ] Enable systemd service hardening
- [ ] Monitor certificate expiration
- [ ] Regularly review logs for errors
- [ ] Keep CertDX updated with security patches

---

## Support and References

- **CertDX Repository**: [Your repository link]
- **ACME Protocol**: [RFC 8555](https://tools.ietf.org/html/rfc8555)
- **Let's Encrypt**: [https://letsencrypt.org](https://letsencrypt.org)
- **Cloudflare API**: [https://developers.cloudflare.com](https://developers.cloudflare.com)

---

## Version Information

- **Created**: December 2025
- **Last Updated**: December 2025
- **CertDX Version**: Based on current repository state
