# certdx client

`certdx_client` is the standalone consumer. It connects to a certdx server,
fetches the certificates you ask for, writes them to disk, and runs your
reload command whenever a certificate changes.

A minimal example config is shipped as `config/client_config.toml`; the
fully-annotated reference is `config/client_config_full.toml`.

## Command line

```
certdx_client [flags]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-c`, `--conf` | `./client.toml` | Path to the TOML config file. |
| `-l`, `--log` | *(stderr)* | Path to a log file. |
| `-d`, `--debug` | `false` | Enable debug logging. |
| `-t`, `--test` | `false` | Test mode: skip TLS verification on the HTTP server. |
| `-h`, `--help` | | Print help. |
| `-v`, `--version` | | Print build version. |

## Configuration file

Top-level sections:

- `[Common]` — operating mode and retry/reconnect tuning.
- `[Http.MainServer]` / `[Http.StandbyServer]` — used when `Common.mode = "http"`.
- `[GRPC.MainServer]` / `[GRPC.StandbyServer]` — used when `Common.mode = "grpc"`.
- `[[Certifications]]` — one entry per certificate to fetch.

### `[Common]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `retryCount` | int | `5` | Per-request retry count. |
| `mode` | string | `"http"` | `http` or `grpc`. |
| `reconnectInterval` | duration string | `"10m"` | gRPC only. Reconnect to the server every interval if disconnected; also used to retry the main server while running on the standby. |

### `[Http.MainServer]` / `[Http.StandbyServer]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `url` | string | *(required for main)* | Full URL including the server's `apiPath`. |
| `authMethod` | string | `"token"` | `token` or `mtls`. |
| `token` | string | `""` | Shared bearer token; required with `authMethod = "token"`. |
| `ca` | path | | mTLS CA. Required with `authMethod = "mtls"`. |
| `certificate` | path | | mTLS client certificate. Required with `authMethod = "mtls"`. |
| `key` | path | | mTLS client private key. Required with `authMethod = "mtls"`. |

`StandbyServer` is optional; if `url` is set, it must also pass validation. The
client falls back to the standby when the main server is unreachable and
periodically retries the main server based on `reconnectInterval`.

### `[GRPC.MainServer]` / `[GRPC.StandbyServer]`

The gRPC endpoint always uses mTLS.

| Key | Type | Notes |
| --- | --- | --- |
| `server` | string | `host:port` of the certdx gRPC SDS endpoint. |
| `ca` | path | CA that signed the server certificate. |
| `certificate` | path | Client certificate (signed by the same CA). |
| `key` | path | Client private key. |

`StandbyServer` is optional; same fallback semantics as in HTTP mode.

Generate the mTLS material with `certdx_tools` (`make-ca`, `make-server`,
`make-client`); see [tools.md](tools.md).

### `[[Certifications]]`

Each entry describes one certificate to fetch and where to write it.

| Key | Type | Notes |
| --- | --- | --- |
| `name` | string | File base name. The certificate is written to `<savePath>/<name>.pem` and the private key to `<savePath>/<name>.key`. |
| `savePath` | path | Output directory. Must exist and be writable by the client process. |
| `domains` | string list | SANs to request. Wildcards (e.g. `*.example.com`) are supported when the server uses DNS-01. |
| `reloadCommand` | string | Shell command executed after a successful write. Typical values: `systemctl reload nginx`, `bash /opt/acme/reload.sh`. |

Example:

```toml
[[Certifications]]
name = "wildcard-example"
savePath = "/etc/ssl/certdx"
domains = ["*.example.com", "example.com"]
reloadCommand = "systemctl reload nginx"
```

## Renewal cadence

The client polls the server on the same cadence as the server's renewal
check (`ACME.renewTimeLeft / 4`). When the server returns a newer
certificate, the client overwrites both files and runs `reloadCommand`.

Writes are atomic via a temp-file-and-rename, so a downstream service
reading the cert mid-update never observes a torn or partial file. The
reload command runs only when both `<savePath>/<name>.pem` and `.key`
already existed — the very first install is treated as a bootstrap
where the downstream service is not yet up.

## Common validation errors

- `no certification configured` — add at least one `[[Certifications]]`.
- `wrong certification configuration for <name>` — `name`, `savePath` and
  `domains` are all required.
- `http main server url is empty` — set `Http.MainServer.url` when in HTTP mode.
- `grpc main server url is empty` — set `GRPC.MainServer.server` when in gRPC mode.
- `file not found: <path>` — an mTLS path does not exist.
- `unsupported mode: <x>` — `Common.mode` must be `http` or `grpc`.
