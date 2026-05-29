# Breaking changes since v0.5.0 — PEM bundle migration

This version replaces all separate `.pem` / `.key` mTLS files with **single
PEM bundle files**. Every config file, CLI invocation and Caddyfile that
references mTLS material must be updated.

## What changed

| Area | Before | After |
| --- | --- | --- |
| **CA** | `ca.pem` (cert, 0644) + `ca.key` (key, 0600) | `ca.pem` (cert + key bundle, 0600) |
| **Server cert** | `server.pem` + `server.key` | `<name>.pem` — user picks the name via `--name` |
| **Client cert** | `<name>.pem` + `<name>.key` | `<name>.pem` — single bundle |
| **Bundle contents** | — | Entity cert + entity key + CA cert (all PEM blocks in one file) |
| **Permissions** | Certs 0644, keys 0600 | All bundles 0600 (they contain private keys) |
| **Reserved names** | `make-client` rejected `ca` and `server` | Only `ca` is reserved (`server` is no longer special) |
| **Server config** | Auto-discovered `mtls/server.pem` + `.key` + `ca.pem` | Explicit `[MTLS]` section with `pem = "/path/to/bundle.pem"` |
| **Client config (HTTP mTLS)** | `ca`, `certificate`, `key` fields | Single `pem` field |
| **Client config (gRPC)** | `ca`, `certificate`, `key` fields | Single `pem` field |
| **Caddyfile** | `ca`, `certificate`, `key` directives | Single `pem` directive |
| **`make-server`** | No `--name` flag (output always `server.pem/.key`) | `--name` / `-n` is required |

## Migration guide

### 1. Regenerate mTLS material (recommended)

The simplest path — regenerate everything and redistribute:

```sh
rm -rf mtls/
certdx_tools make-ca -o "My Org" -c "My CA"
certdx_tools make-server -n certdx-server -d certdxserver.example.com,sds.example.com
certdx_tools make-client -n caddy-edge
certdx_tools make-client -n envoy-frontend
```

### 2. Convert existing material in place

If you cannot regenerate (e.g. pinned certificates), combine the old
separate files into bundles:

```sh
# CA bundle: cert + key → ca.pem
cat mtls/ca.pem mtls/ca.key > mtls/ca.pem.new
mv mtls/ca.pem.new mtls/ca.pem
rm mtls/ca.key
chmod 0600 mtls/ca.pem

# Server bundle: cert + key + CA cert → <name>.pem
# (extract CA cert from old ca.pem first, or use the newly combined one)
# Old ca.pem only had the cert, so extract just the CERTIFICATE block:
openssl x509 -in mtls/ca.pem -outform PEM -out /tmp/ca-cert-only.pem
cat mtls/server.pem mtls/server.key /tmp/ca-cert-only.pem > mtls/certdx-server.pem
rm mtls/server.pem mtls/server.key
chmod 0600 mtls/certdx-server.pem

# Client bundle: cert + key + CA cert → <name>.pem
cat mtls/myclient.pem mtls/myclient.key /tmp/ca-cert-only.pem > mtls/myclient.pem.new
mv mtls/myclient.pem.new mtls/myclient.pem
rm mtls/myclient.key
chmod 0600 mtls/myclient.pem

rm /tmp/ca-cert-only.pem
```

> **Note:** If you already ran `make-ca` with the new version, `ca.pem` is
> already a bundle (cert + key). To extract just the CA certificate for the
> entity bundles, take only the first `CERTIFICATE` block.

### 3. Update server config

Old:

```toml
# The server auto-discovered mtls/server.pem, mtls/server.key, mtls/ca.pem

[HttpServer]
authMethod = "mtls"

[gRPCSDSServer]
enabled = true
```

New — add an explicit `[MTLS]` section:

```toml
[HttpServer]
authMethod = "mtls"

[gRPCSDSServer]
enabled = true

[MTLS]
pem = "/opt/certdx/mtls/certdx-server.pem"
```

The `--mtls-dir` flag on `certdx_server` is no longer used for mTLS
loading. The server reads the bundle path from config.

### 4. Update client config

Old (HTTP mTLS):

```toml
[Http.MainServer]
url = "https://certdxserver.example.com:19198/api"
authMethod = "mtls"
ca = "/opt/certdx/mtls/ca.pem"
certificate = "/opt/certdx/mtls/myclient.pem"
key = "/opt/certdx/mtls/myclient.key"
```

New:

```toml
[Http.MainServer]
url = "https://certdxserver.example.com:19198/api"
authMethod = "mtls"
pem = "/opt/certdx/mtls/myclient.pem"
```

Old (gRPC):

```toml
[GRPC.MainServer]
server = "sds.example.com:10002"
ca = "/opt/certdx/mtls/ca.pem"
certificate = "/opt/certdx/mtls/myclient.pem"
key = "/opt/certdx/mtls/myclient.key"
```

New:

```toml
[GRPC.MainServer]
server = "sds.example.com:10002"
pem = "/opt/certdx/mtls/myclient.pem"
```

### 5. Update Caddyfile

Old:

```caddyfile
GRPC {
    main_server {
        server sds.example.com:9801
        ca   /opt/certdx/mtls/ca.pem
        certificate /opt/certdx/mtls/caddy.pem
        key  /opt/certdx/mtls/caddy.key
    }
}
```

New:

```caddyfile
GRPC {
    main_server {
        server sds.example.com:9801
        pem /opt/certdx/mtls/caddy.pem
    }
}
```

### 6. Update Envoy SDS config

Envoy still uses separate `certificate_chain`, `private_key` and
`trusted_ca` fields — it reads the raw PEM blocks, not certdx bundles. If
you inline the material from the new entity bundle, split the three PEM
blocks back into the appropriate Envoy fields:

- First `CERTIFICATE` block → `certificate_chain`
- `EC PRIVATE KEY` block → `private_key`
- Second `CERTIFICATE` block → `trusted_ca`

### 7. Update `make-server` invocations

Old:

```sh
certdx_tools make-server -d certdxserver.example.com
```

New — `--name` / `-n` is now required:

```sh
certdx_tools make-server -n certdx-server -d certdxserver.example.com
```
