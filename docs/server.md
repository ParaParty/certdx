# certdx server

`certdx_server` is the central daemon. It registers an ACME account, issues
and renews certificates for the domains you allow, caches them on disk, and
hands them out to consumers over HTTPS or gRPC SDS.

A minimal example config is shipped as `config/server_config.toml`; the
fully-annotated reference is `config/server_config_full.toml`.

## Command line

```
certdx_server [flags]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-c`, `--conf` | `./server.toml` | Path to the TOML config file. |
| `-l`, `--log` | *(stderr)* | Path to a log file. |
| `-d`, `--debug` | `false` | Enable debug logging. |
| `-h`, `--help` | | Print help. |
| `-v`, `--version` | | Print build version. |

## Configuration file

The configuration is a TOML file. Top-level sections:

- `[ACME]` — ACME account and certificate lifetime.
- `[GoogleCloudCredential]` — only when `ACME.provider` is `google` / `googletest`.
- `[DnsProvider]` — only when `ACME.challengeType = "dns"`.
- `[HttpProvider]` (and `[HttpProvider.S3]`) — only when `ACME.challengeType = "http"`.
- `[HttpServer]` — HTTPS distribution endpoint for `certdx_client` and Caddy.
- `[gRPCSDSServer]` — gRPC SDS endpoint for Envoy and the gRPC client mode.

### `[ACME]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `email` | string | `""` | Email used for ACME account registration. |
| `provider` | string | `"r3"` | One of `r3`, `r3test`, `google`, `googletest`. |
| `retryCount` | int | `5` | Per-issuance retry count. |
| `challengeType` | string | `"dns"` | `dns` or `http`. |
| `certLifeTime` | duration string | `"168h"` | Lifetime of issued certificates the server requests/tracks. |
| `renewTimeLeft` | duration string | `"24h"` | Renew when remaining lifetime drops below this. The renewal check runs every `renewTimeLeft / 4`. |
| `allowedDomains` | string list | *(required)* | Root domains the server is allowed to issue. Requests for domains outside this list are rejected. |

Supported ACME providers:

| Value | Directory URL |
| --- | --- |
| `r3` | Let's Encrypt production |
| `r3test` | Let's Encrypt staging |
| `google` | Google Trust Services production |
| `googletest` | Google Trust Services staging |

When using a Google provider, the server will automatically register an EAB
account on first start if `[GoogleCloudCredential]` is present. Otherwise,
register manually with `certdx_tools google-account` — see [tools.md](tools.md).

### `[GoogleCloudCredential]`

A flat copy of a Google Cloud service-account JSON key, encoded as TOML
key/value pairs. Only used by Google ACME providers. When present, the server
uses it to register the EAB account automatically on first start. See
[setup.md](setup.md#google-cloud-credentials) for how to obtain it. An example
block is in `config/server_config_full.toml`.

### `[DnsProvider]`

| Key | Type | Notes |
| --- | --- | --- |
| `type` | string | `cloudflare` or `tencentcloud`. |
| `disableCompletePropagationRequirement` | bool | Skip the lego "wait for full propagation" step. |
| `email`, `apiKey` | string | Cloudflare global API key auth. |
| `authToken`, `zoneToken` | string | Cloudflare scoped token auth (alternative to global). |
| `secretID`, `secretKey` | string | Tencent Cloud credentials. |

Exactly one credential set must be configured for the chosen `type`.

### `[HttpProvider]` and `[HttpProvider.S3]`

Used for HTTP-01 challenges. Today the only supported `type` is `s3`, but
any S3-compatible object store works (AWS S3, Tencent COS, MinIO, …).
Configure the bucket as the webroot for the ACME
`/.well-known/acme-challenge/` path on the public hostnames covered by
`allowedDomains`.

```toml
[HttpProvider]
type = "s3"

[HttpProvider.S3]
region = "ap-beijing"
bucket = "cos-1000000000"
accessKeyId = "..."
accessKeySecret = "..."
sessionToken = ""
url = "https://cos.ap-beijing.myqcloud.com"
```

### `[HttpServer]`

The HTTPS endpoint that `certdx_client` and the Caddy plugin call into.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Enable the HTTP server. |
| `listen` | string | `":10001"` | Listen address. |
| `apiPath` | string | `"/"` | Base API path. A leading `/` is added automatically if missing. |
| `authMethod` | string | `"token"` | `token` or `mtls`. |
| `secure` | bool | `false` | When `true`, the server obtains a certificate for itself via ACME and serves HTTPS. Required when running on the public internet. |
| `names` | string list | `[]` | SANs for the self-issued server certificate. Required when `secure = true`. Must be issuable under `ACME.allowedDomains`. |
| `token` | string | `""` | Shared bearer token (only with `authMethod = "token"`). Empty disables token auth. |

When `authMethod = "mtls"`, the server loads its certificate from
`mtls/server.pem` and `mtls/server.key`, and trusts client certificates
signed by `mtls/ca.pem`. The `mtls/` directory is resolved next to the
executable, or under the current working directory. Generate the contents
with `certdx_tools` (`make-ca`, `make-server`, `make-client`); see
[tools.md](tools.md).

### `[gRPCSDSServer]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Enable the gRPC SDS server. |
| `listen` | string | `":10002"` | Listen address. |
| `names` | string list | `[]` | SANs for the SDS server certificate (required when enabled). |

The gRPC endpoint always uses mTLS. It loads its certificate from
`mtls/server.pem` and `mtls/server.key` and trusts client certificates signed
by `mtls/ca.pem`. Envoy (or `certdx_client` in gRPC mode) presents a client
certificate signed by the same CA.

## Runtime files

The server creates and reads these next to the executable (or the current
working directory — whichever exists):

| Name | Purpose |
| --- | --- |
| `mtls/` | CA, server and per-client certificates for mTLS / gRPC SDS. |
| `private/` | ACME account private keys (one file per email + provider). |
| `cache.json` | Issued-certificate cache. Inspect with `certdx_tools show-cache`. |

## Common validation errors

The config is checked on startup; any failure aborts the process.

- `AllowedDomains is empty` — set `ACME.allowedDomains`.
- `challenge type: <x> not supported` — must be `dns` or `http`.
- `ACME provider not supported: <x>` — see the table above.
- `secure http server with no name` — set `HttpServer.names` when `secure = true`.
- `no grpc server name` — set `gRPCSDSServer.names` when enabled.
- `DnsProvider Cloudflare: empty Email or APIKey` — provide either the
  global key pair or the auth/zone token pair.
