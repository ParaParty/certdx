# CertDX Server Configuration Wiki

## Overview

**CertDX** (Certificate Daemon X) is a certificate management daemon with a client-server architecture. The server manages certificates, issues them from ACME providers when requested by clients, and caches them for reuse. CertDX supports multiple client types:
- Standalone client
- Caddy plugin client
- Envoy client (via SDS - Secret Discovery Service)

This wiki documents the `server_config_full.toml` configuration file.

---

## Configuration Sections

### [ACME] - ACME Protocol Configuration

Configures the ACME (Automated Certificate Management Environment) protocol settings for certificate issuance.

#### `email` (string)
- **Description**: Email address for ACME account registration
- **Example**: `"admin@example.com"`
- **Required**: Yes (for ACME operations)
- **Note**: This email will be used for the ACME account with your provider

#### `provider` (string)
- **Description**: ACME service provider to use
- **Supported Values**:
  - `"r3"` - Let's Encrypt production (public trusted certificates)
  - `"r3test"` - Let's Encrypt staging (for testing, not publicly trusted)
  - `"google"` - Google ACME service (production)
  - `"googletest"` - Google ACME service (testing)
- **Example**: `provider = "r3"`
- **Recommendation**: Use `r3test` or `googletest` for development/testing

#### `retryCount` (integer)
- **Description**: Number of times to retry ACME requests on failure
- **Example**: `retryCount = 5`
- **Default**: Recommended value is 3-5
- **Note**: Helps handle transient failures during certificate issuance

#### `challengeType` (string)
- **Description**: Type of ACME challenge to use for domain validation
- **Supported Values**:
  - `"dns"` - DNS-based validation (requires DNS provider configuration)
  - `"http"` - HTTP-based validation (requires HTTP provider configuration)
- **Example**: `challengeType = "dns"`
- **Note**: DNS challenge is more robust for automated environments

#### `certLifeTime` (duration string)
- **Description**: The duration after which a certificate is considered expired and eligible for renewal
- **Format**: Go duration string (e.g., "168h", "24h", "720h")
- **Example**: `certLifeTime = "168h"` (7 days)
- **Important**: This is NOT the actual certificate lifetime. See below for actual lifetime calculation.

#### `renewTimeLeft` (duration string)
- **Description**: Grace period kept after a certificate is marked for renewal
- **Format**: Go duration string
- **Example**: `renewTimeLeft = "24h"`
- **Important**: This is NOT when renewal starts. See below for renewal behavior.

##### Actual Certificate Lifetime and Renewal Behavior

The actual certificate issued by the ACME provider has a lifetime of `certLifeTime + renewTimeLeft`.

**Example with `certLifeTime = "168h"` and `renewTimeLeft = "24h"`:**
- Actual certificate lifetime: 192 hours (168h + 24h)
- After 168 hours: Server marks the certificate as expired and attempts renewal
- Certificate remains valid for an additional 24 hours (until 192h) as a grace period during renewal
- Both server and client check certificates every `renewTimeLeft / 4` interval (every 6 hours in this example)

This design ensures certificates are renewed proactively before they become completely invalid, with a safety buffer to handle renewal delays.

#### `allowedDomains` (string array)
- **Description**: List of root domains that the server is permitted to issue certificates for
- **Example**: 
  ```toml
  allowedDomains = [
      "example.com",
      "another-domain.com",
  ]
  ```
- **Note**: Subdomains of these root domains are allowed (e.g., `*.example.com` is valid for root `example.com`)

---

### [GoogleCloudCredential] - Google Cloud Service Account

Configures Google Cloud credentials for ACME account registration with Google's ACME service.

#### `type` (string)
- **Description**: Type of Google Cloud credential
- **Value**: `"service_account"` (typically used for server-side applications)

#### `project_id` (string)
- **Description**: Google Cloud Project ID

#### `private_key_id` (string)
- **Description**: Key ID from the Google Cloud service account

#### `private_key` (string)
- **Description**: Private key in PEM format (multiline string with `\n` escapes)
- **Format**: 
  ```
  -----BEGIN PRIVATE KEY-----
  [base64 encoded key data]
  -----END PRIVATE KEY-----
  ```
- **Note**: Newlines are represented as `\n` escape sequences in TOML

#### `client_email` (string)
- **Description**: Email address of the Google Cloud service account
- **Example**: `"acme-user@lanlanlu.iam.gserviceaccount.com"`

#### `client_id` (string)
- **Description**: Client ID from the Google Cloud service account

#### `auth_uri` (string)
- **Description**: OAuth 2.0 authorization endpoint
- **Value**: `"https://accounts.google.com/o/oauth2/auth"` (standard Google endpoint)

#### `token_uri` (string)
- **Description**: OAuth 2.0 token endpoint
- **Value**: `"https://oauth2.googleapis.com/token"` (standard Google endpoint)

#### `auth_provider_x509_cert_url` (string)
- **Description**: URL to Google's OAuth 2.0 certificate endpoints
- **Value**: `"https://www.googleapis.com/oauth2/v1/certs"` (standard)

#### `client_x509_cert_url` (string)
- **Description**: URL to this service account's public certificate
- **Format**: `"https://www.googleapis.com/robot/v1/metadata/x509/[service-account-email]"`

---

### [DnsProvider] - DNS Challenge Provider

Configures the DNS provider for ACME DNS-01 challenge validation.

#### `disableCompletePropagationRequirement` (boolean)
- **Description**: Whether to skip waiting for DNS propagation to complete globally
- **Value**: `true` or `false`
- **Default**: `false` (recommended)
- **Note**: Setting to `true` may cause validation failures if DNS hasn't propagated

#### DNS Provider Configuration - Choose One:

##### Cloudflare with Global API Key
```toml
type = "cloudflare"
email = "your-email@example.com"
apiKey = "your-global-api-key"
```
- **email**: Your Cloudflare account email
- **apiKey**: Global API token (found in Cloudflare dashboard)

##### Cloudflare with Auth Token
```toml
type = "cloudflare"
authToken = "your-auth-token"
zoneToken = "your-zone-token"
```
- **authToken**: Scoped authentication token
- **zoneToken**: Zone-specific token
- **Note**: More secure than global API key

##### Tencent Cloud
```toml
type = "tencent"
secretID = "your-secret-id"
SecretKey = "your-secret-key"
```
- **secretID**: Tencent Cloud secret ID
- **SecretKey**: Tencent Cloud secret key

---

### [HttpProvider] - HTTP Challenge Provider

Configures the HTTP provider for storing ACME HTTP-01 challenge files.

#### `type` (string)
- **Description**: Type of HTTP provider backend
- **Current Value**: `"s3"` (Amazon S3 or compatible services)
- **Purpose**: Stores challenge files that ACME providers will verify via HTTP requests

### [HttpProvider.S3] - S3 Configuration

Configures S3-compatible storage for HTTP challenge files.

#### `region` (string)
- **Description**: AWS region or cloud provider region
- **Example**: `"ap-beijing"`

#### `bucket` (string)
- **Description**: S3 bucket name where challenge files are stored
- **Example**: `"cos-1000000000"`

#### `accessKeyId` (string)
- **Description**: S3 access key ID for authentication
- **Example**: `"xxxxxxxxxx"`

#### `accessKeySecret` (string)
- **Description**: S3 access key secret for authentication
- **Example**: `"xxxxxxxx"`

#### `sessionToken` (string)
- **Description**: Temporary session token (if using temporary credentials)
- **Default**: Empty string for permanent credentials

#### `url` (string)
- **Description**: S3 endpoint URL
- **Example**: `"https://cos.ap-beijing.myqcloud.com"` (Tencent COS)
- **Note**: Can be AWS S3, Tencent COS, or other S3-compatible services

---

### [HttpServer] - CertDX HTTP API Server

Configures the HTTP server that exposes CertDX's certificate API.

#### `enabled` (boolean)
- **Description**: Whether the HTTP server is enabled
- **Value**: `true` or `false`

#### `listen` (string)
- **Description**: Network address and port to listen on
- **Format**: `"[ip]:[port"` or `":[port]"` for all interfaces
- **Example**: `":19198"`

#### `apiPath` (string)
- **Description**: Base URL path for the API
- **Example**: `"/1145141919810"`
- **Security Note**: This is a random/obfuscated string that acts as a minimal security layer. Change it to a random string for your deployment to make the API less discoverable. While not a replacement for proper authentication, it provides obscurity.

#### `authMethod` (string)
- **Description**: Authentication method for API requests
- **Supported Values**:
  - `"token"` - Token-based authentication
  - `"mtls"` - Mutual TLS authentication

##### Token Authentication
```toml
authMethod = "token"
token = "your-secret-token-here"
```
- **token**: Secret token that clients must provide
- **Note**: Leave empty to disable token authentication

##### mTLS Authentication
```toml
authMethod = "mtls"
```
- **Description**: Mutual TLS authentication using certificates
- **Certificate Location**: Certificates are stored in the `mtls/` directory relative to the certdx executable
- **Required Files**: 
  - `mtls/ca.pem` - CA certificate (from `certdx_tools make-ca`)
  - `mtls/server.pem` - Server certificate (from `certdx_tools make-server`)
  - `mtls/server.key` - Server private key (from `certdx_tools make-server`)
- **Shared by Both**: Same certificates are used by both the HTTPS server (when `authMethod = "mtls"`) and gRPC SDS server (when mTLS is enabled)
- **Setup**: Generate certificates using `certdx_tools` commands; they are automatically placed in the correct `mtls/` directory

#### `secure` (boolean)
- **Description**: Whether to use HTTPS instead of HTTP
- **Value**: `true` or `false`
- **Note**: When `true`, certificates must be automatically generated for `names` domains

#### `names` (string array)
- **Description**: Domain names for which certificates will be automatically generated
- **Example**:
  ```toml
  names = ["certdxserver.example.com", "*.example.com"]
  ```
- **Behavior**: 
  - CertDX will request certificates from the ACME provider for these domains
  - Must be domains listed in `allowedDomains` under `[ACME]`
  - Certificates are automatically renewed according to ACME settings
  - Used for HTTPS when `secure = true`

---

### [gRPCSDSServer] - Secret Discovery Service (SDS)

Configures the gRPC server implementing the Secret Discovery Service (SDS) protocol, originally defined by Envoy.

#### `enabled` (boolean)
- **Description**: Whether the gRPC SDS server is enabled
- **Value**: `true` or `false`
- **Purpose**: Allows clients to dynamically discover and retrieve certificates via the SDS protocol

#### `listen` (string)
- **Description**: Network address and port for the gRPC server
- **Format**: `"[ip]:[port]"` or `":[port]"` for all interfaces
- **Example**: `":11451"`

#### Supported Clients

The SDS API is used by multiple CertDX client types:
- **Envoy proxies** - Retrieve certificates for proxy configuration
- **Standalone client** - Retrieve certificates for local applications
- **Caddy plugin client** - Retrieve certificates for Caddy web server

---

## Common Configuration Scenarios

### Scenario 1: Production with Let's Encrypt and DNS Challenge

```toml
[ACME]
email = "admin@example.com"
provider = "r3"
retryCount = 5
challengeType = "dns"
certLifeTime = "168h"
renewTimeLeft = "24h"
allowedDomains = ["example.com"]

[DnsProvider]
disableCompletePropagationRequirement = false
type = "cloudflare"
email = "user@example.com"
apiKey = "your-api-key"

[HttpServer]
enabled = true
listen = ":19198"
apiPath = "/your-random-path"
authMethod = "token"
secure = true
names = ["certdx.example.com"]
token = "your-secret-token"
```

### Scenario 2: Testing with Let's Encrypt Staging

```toml
[ACME]
email = "test@example.com"
provider = "r3test"  # Use staging service
retryCount = 3
challengeType = "dns"
# ... rest of configuration
```

### Scenario 3: Envoy Integration with SDS

```toml
[HttpServer]
enabled = true
# HTTP API configuration for standalone clients

[gRPCSDSServer]
enabled = true
listen = ":11451"
# Envoy proxies connect here to retrieve certificates via SDS
```

---

## Security Best Practices

1. **API Path**: Generate a random, hard-to-guess `apiPath` string to make your API less discoverable
2. **Token**: Use strong, randomly generated tokens for token-based authentication
3. **mTLS**: For production environments, prefer mTLS over token-based authentication
4. **DNS Provider Credentials**: Store credentials securely; never commit them to version control
5. **Certificate Names**: Only include domains you actually need certificates for

---

## Tools and Setup

### CertDX Tools

CertDX provides a `certdx_tools` utility for certificate management and configuration tasks.

**Usage:**
```
certdx_tools <command> [options]
```

**Available Commands:**

#### `show-cache`
- **Description**: Print server certificate cache
- **Usage**: `certdx_tools show-cache [options]`
- **Purpose**: View currently cached certificates on the server

#### `google-account`
- **Description**: Register Google Cloud ACME account
- **Usage**: `certdx_tools google-account [options]`
- **Purpose**: Set up a Google Cloud service account for ACME operations

#### `make-ca`
- **Description**: Make gRPC mTLS CA certificate and key
- **Usage**: `certdx_tools make-ca [options]`
- **Purpose**: Generate CA certificate for mTLS authentication; creates files in the `mtls/` directory relative to the certdx executable

#### `make-server`
- **Description**: Make gRPC mTLS Server certificate and key
- **Usage**: `certdx_tools make-server [options]`
- **Purpose**: Generate server certificate for mTLS authentication; used by both the gRPC SDS server and HTTPS server when mTLS mode is enabled (requires CA certificate first)

#### `make-client`
- **Description**: Make gRPC mTLS Client certificate and key
- **Usage**: `certdx_tools make-client [options]`
- **Purpose**: Generate client certificate for mTLS (requires CA certificate first)

**Global Options:**
- `-h, --help` - Print help information
- `-v, --version` - Print version information

**For detailed help on any command:**
```bash
certdx_tools <command> --help
```

### mTLS Certificate Generation Workflow

This workflow sets up mTLS authentication for both the server and clients. All commands are run on the server, and client certificates are then distributed to client machines.

#### Step 1: Generate CA Certificate (Server)

On the server, generate the Certificate Authority:

```bash
certdx_tools make-ca
```

This creates:
- `ca.pem` - CA public certificate
- `ca.key` - CA private key

Files are located in the `mtls/` directory relative to the certdx executable.

#### Step 2: Generate Server Certificate (Server)

On the server, generate the server certificate for both the gRPC SDS server and HTTPS server:

```bash
certdx_tools make-server -d <server-domain-name>
```

**Parameters:**
- `-d <server-domain-name>` - Domain name of the server (e.g., `grpc.example.com` or `certdx.example.com`)

This creates:
- `server.pem` - Server certificate
- `server.key` - Server private key

**Usage**: These files are used by both:
- gRPC SDS server for mTLS client connections
- HTTPS server when `authMethod = "mtls"` is configured

#### Step 3: Generate Client Certificate (Server)

On the server, generate a client certificate:

```bash
certdx_tools make-client -n <client-name>
```

**Parameters:**
- `-n <client-name>` - Unique identifier for this client (e.g., `client1`, `app-server`, `nginx-proxy`)

This creates:
- `<client-name>.pem` - Client certificate
- `<client-name>.key` - Client private key

#### Step 4: Distribute Client Certificates

The generated certificates are automatically stored in the `mtls/` directory relative to the certdx executable. Copy the following files from the server's directory to each client machine:

1. `mtls/ca.pem` - CA public certificate
2. `mtls/<client-name>.pem` - Client certificate
3. `mtls/<client-name>.key` - Client private key

On the client, place these files in the `mtls/` directory relative to the `certdx_client` executable.

**Directory Structure on Client:**
```
certdx_client_executable_path/
├── certdx_client
└── mtls/
    ├── ca.pem
    ├── <client-name>.pem
    └── <client-name>.key
```

**Security Note:** 
- Keep `<client-name>.key` private and secure
- Ensure only the client process can read these files
- Use secure transfer methods (e.g., SCP, encrypted channels)

#### Step 5: Add More Clients (if needed)

Repeat Steps 3-4 for each additional client with a different `<client-name>`. Each client gets:
- The same `ca.pem`
- Unique `<client-name>.pem` and `<client-name>.key`

#### File Locations

All generated certificate files are stored in the `mtls/` directory alongside the certdx executables:

```
certdx_tools_executable_path/
├── certdx_client
├── certdx_server
├── certdx_tools (or certdx_tools.exe on Windows)
└── mtls/
    ├── ca.pem
    ├── ca.key
    ├── server.pem
    ├── server.key
    ├── client1.pem
    ├── client1.key
    ├── client2.pem
    └── client2.key
```

#### Example: Complete mTLS Setup

Setup for server and two clients:

```bash
# Step 1: Generate CA (once)
certdx_tools make-ca

# Step 2: Generate server certificate
certdx_tools make-server -d grpc.example.com

# Step 3a: Generate first client certificate
certdx_tools make-client -n client-app-1
# Copy ca.pem, client-app-1.pem, client-app-1.key to client-1

# Step 3b: Generate second client certificate
certdx_tools make-client -n client-app-2
# Copy ca.pem, client-app-2.pem, client-app-2.key to client-2
```

### Configuration Files

- `server_config_full.toml` - Full example configuration with all options
- `server_config.toml` - Minimal production configuration
- Use `server_config_full.toml` as a template to understand all available options
