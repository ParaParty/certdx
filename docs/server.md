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
| `-c`, `--conf` | *(required)* | Path to the TOML config file. |
| `--data-dir` | *(install-mode default)* | Collapses both config (`mtls/`) and state (`private/`, `cache.json`) roots onto this directory. Env: `CERTDX_DATA_DIR`. |
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
- `[MTLS]` — path to the server's PEM bundle (required when using mTLS or gRPC).

### `[ACME]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `email` | string | `""` | Email used for ACME account registration. |
| `provider` | string | `"r3"` | One of `r3`, `r3test`, `google`, `googletest`. |
| `retryCount` | int | `5` | Per-issuance retry count. |
| `challengeType` | string | `"dns"` | `dns` or `http`. |
| `certLifeTime` | duration string | `"168h"` | Lifetime of issued certificates the server requests/tracks. Must be positive. |
| `renewTimeLeft` | duration string | `"24h"` | Renew when remaining lifetime drops below this. The renewal check runs every `renewTimeLeft / 4`. Must be positive and shorter than `certLifeTime`. |
| `allowedDomains` | string list | *(required)* | Root domains the server is allowed to issue. Requests for domains outside this list are rejected. |
| `maxCacheEntries` | int | `0` | Cap on the number of distinct cert packs the cache tracks. `0` means unlimited. |

A certificate is requested to stay valid for `certLifeTime + renewTimeLeft`,
so that sum is what the ACME provider has to be able to issue. Both Let's
Encrypt and Google Trust Services cap at 90 days; a configuration whose sum
exceeds that is rejected at startup rather than yielding certificates that
expire long before the server thinks they do.

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
| `nameservers` | string list | Resolvers used for the DNS-01 propagation check, as `host` or `host:port`. URLs and entries with whitespace are rejected at startup. |
| `dnsTimeout` | duration string | Per-query timeout for the propagation check. Must be positive. |
| `email`, `apiKey` | string | Cloudflare global API key auth. |
| `authToken`, `zoneToken` | string | Cloudflare scoped token auth (alternative to global). |
| `secretID`, `secretKey` | string | Tencent Cloud credentials. |

Exactly one credential set must be configured for the chosen `type`.

With `disableCompletePropagationRequirement = true` the authoritative-server
check is skipped, so the TXT record is instead verified on the resolvers in
`nameservers` before the challenge is handed to the ACME server. Without
`nameservers`, that mode does no verification at all — set both together.

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

`acl` is optional and controls the canned ACL sent with the challenge object:

- leave the key out (the default): `public-read` is sent, which is what certdx
  has always done, so an existing ACL-enabled bucket keeps working after an
  upgrade;
- `acl = ""`: no canned-ACL header is sent at all. Buckets created since April
  2023 have ACLs disabled by default and reject any `x-amz-acl` header, so this
  is the setting for them — make the challenge path publicly readable with a
  bucket policy instead;
- any other AWS canned ACL (`private`, `public-read-write`,
  `authenticated-read`, `aws-exec-read`, `bucket-owner-read`,
  `bucket-owner-full-control`) is sent as-is; anything else is rejected at
  startup.

### `[HttpServer]`

The HTTPS endpoint that `certdx_client` and the Caddy plugin call into.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Enable the HTTP server. |
| `listen` | string | `":10001"` | Listen address. |
| `apiPath` | string | `"/"` | Base API path. A leading `/` is added automatically if missing. |
| `authMethod` | string | `"token"` | `token` or `mtls`. Any other value is rejected at startup. |
| `secure` | bool | `false` | When `true`, the server obtains a certificate for itself via ACME and serves HTTPS. Required when running on the public internet. |
| `names` | string list | `[]` | SANs for the self-issued server certificate. Required when `secure = true`. Must be issuable under `ACME.allowedDomains`. |
| `token` | string | `""` | Shared bearer token (only with `authMethod = "token"`). Required unless `allowAnonymous = true`. |
| `allowAnonymous` | bool | `false` | Serve without any authentication. Only then is an empty `token` accepted. |
| `allowInsecureToken` | bool | `false` | Silence the startup warning about serving the token and private keys over plain HTTP (`secure = false`). |

An enabled token-auth server with an empty `token` used to serve every caller
anonymously by accident. That is now an error: to run without authentication,
say so with `allowAnonymous = true`.

With `secure = false` the bearer token and the issued private keys travel in
cleartext, so the server logs a warning on every start. Run it only on a
trusted network (or behind a TLS terminator), and set `allowInsecureToken =
true` to acknowledge the trade-off and silence the warning.

When `authMethod = "mtls"`, the server loads its mTLS material from the
PEM bundle specified in `[MTLS].pem`. The bundle contains the server cert,
server key and CA cert.

Generate the bundle with `certdx_tools` (`make-ca`, `make-server`,
`make-client`); see [tools.md](tools.md).

### `[gRPCSDSServer]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Enable the gRPC SDS server. |
| `listen` | string | `":10002"` | Listen address |

The gRPC endpoint always uses mTLS. It loads the certificate and CA from the
bundle at `[MTLS].pem`. Envoy (or `certdx_client` in gRPC mode) presents a
client certificate signed by the same CA.

### `[MTLS]`

Required when `HttpServer.authMethod = "mtls"` or `gRPCSDSServer.enabled = true`.

| Key | Type | Notes |
| --- | --- | --- |
| `pem` | path | Path to the server PEM bundle (server cert + key + CA cert). |

## Runtime files

The server creates and reads these next to the executable (or the current
working directory — whichever exists):

| Name | Purpose |
| --- | --- |
| `private/` | ACME account private keys (one file per email + provider). |
| `cache.json` | Issued-certificate cache. Inspect with `certdx_tools show-certs`. |

## Common validation errors

The config is checked on startup; any failure aborts the process.

- `AllowedDomains is empty` — set `ACME.allowedDomains`.
- `challenge type: <x> not supported` — must be `dns` or `http`.
- `ACME provider not supported: <x>` — see the table above.
- `secure http server with no name` — set `HttpServer.names` when `secure = true`.
- `DnsProvider Cloudflare: empty Email or APIKey` — provide either the
  global key pair or the auth/zone token pair.
