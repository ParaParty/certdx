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
| `-c`, `--conf` | *(required)* | Path to the TOML config file. |
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
- `[[Profile.TencentCloud]]` / `[[Profile.Kubernetes]]` — named credentials for update actions.
- `[[Certificate]]` — one entry per certificate to fetch, each with its update actions.

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
| `pem` | path | | PEM bundle (client cert + key + CA cert). Required with `authMethod = "mtls"`. |

`StandbyServer` is optional; if `url` is set, it must also pass validation. The
client falls back to the standby when the main server is unreachable and
periodically retries the main server based on `reconnectInterval`.

### `[GRPC.MainServer]` / `[GRPC.StandbyServer]`

The gRPC endpoint always uses mTLS.

| Key | Type | Notes |
| --- | --- | --- |
| `server` | string | `host:port` of the certdx gRPC SDS endpoint. |
| `pem` | path | PEM bundle (client cert + key + CA cert). |

`StandbyServer` is optional; same fallback semantics as in HTTP mode.

Generate the mTLS material with `certdx_tools` (`make-ca`, `make-server`,
`make-client`); see [tools.md](tools.md).

### `[[Certificate]]`

Each entry describes one certificate to fetch and one or more update
actions describing where it should go.

| Key | Type | Notes |
| --- | --- | --- |
| `name` | string | Identifies the certificate in logs, and is the file base name used by the file action. |
| `domains` | string list | SANs to request. Wildcards (e.g. `*.example.com`) are supported when the server uses DNS-01. |

At least one `[[Certificate.UpdateAction]]` is required. Each action
table belongs to the `[[Certificate]]` above it, so keep a certificate's
actions together and do not interleave two certificates.

### `[[Certificate.UpdateAction]]`

Every action carries a `type` key selecting what to do with the renewed
material. Actions for one certificate run concurrently, each on its own
goroutine, retried `Common.retryCount` times; a failing action never
stops the others or the daemon.

#### `type = "file"`

| Key | Type | Notes |
| --- | --- | --- |
| `savePath` | path | Output directory. The certificate is written to `<savePath>/<name>.pem` and the private key to `<savePath>/<name>.key`. |
| `reloadCommand` | string | Shell command executed after a successful write. Typical values: `systemctl reload nginx`, `bash /opt/acme/reload.sh`. It is killed if it runs longer than 5 minutes. |

#### `type = "tencentCloud"`

Re-points Tencent Cloud resources at the renewed certificate. On each
update it looks up the uploaded certificates whose SANs equal this
certificate's `domains`, picks the newest one that expires before the
renewed certificate (by comparing `CertEndTime` with the renewed
certificate's real expiry), and calls `UpdateCertificateInstance` on it.
If the account holds no matching certificate, the action logs a warning
and does nothing — it never uploads a certificate that is not already
bound. Uploaded certificates that expire after the renewed one are never
replaced. A certificate expiring at the same second as the renewed one is
checked with `DescribeCertificateDetail` (grant
`ssl:DescribeCertificateDetail`): if it holds the same certificate it is
treated as already uploaded, otherwise (e.g. a same-domain reissue) it is
replaced like any other.

The action then polls the deploy record
(`DescribeHostUpdateRecordDetail`) until every resource has been
re-bound, for up to five minutes, and reports failed resources as an
error. Grant the profile's credentials `ssl:DescribeHostUpdateRecordDetail`
so the update is confirmed; without it the action logs a warning and
assumes the deploy succeeded. If Tencent Cloud already stores the renewed
certificate (an earlier delivery uploaded it but did not finish), the
resources are re-bound to the stored copy instead.

Throttling and other transient API errors are retried with backoff. A
deploy that failed or could not be confirmed is reported once and not
retried: replaying the upload cannot change the outcome.

| Key | Type | Notes |
| --- | --- | --- |
| `profile` | string | Name of a `[[Profile.TencentCloud]]` entry. |
| `resourceTypes` | string list | One or more of `clb`, `cdn`, `waf`, `live`, `vod`, `ddos`, `tke`, `apigateway`, `tcb`, `teo`. |
| `resourceTypesRegions` | table list | Optional per-resource-type region filter. Every `resourceType` used here must also appear in `resourceTypes`. |

#### `type = "kubernetes"`

Patches `kubernetes.io/tls` secrets in place. On each update it lists
secrets across all namespaces, keeps the ones annotated with
`party.para.certdx/domains` whose domains this certificate covers, and
rewrites `tls.crt` / `tls.key`. It never creates secrets and never
touches any other field. Secrets already holding the same material are
skipped, so consuming pods are not restarted for nothing.

| Key | Type | Notes |
| --- | --- | --- |
| `profile` | string | Name of a `[[Profile.Kubernetes]]` entry. |

Annotation domains are comma-separated, case-insensitive and
de-duplicated. A secret is patched when every annotated domain is
covered by one of the certificate's `domains`:

- a plain entry covers itself and any subdomain, like the server's
  allowlist: `example.com` covers `foo.example.com`;
- a wildcard entry covers itself and names exactly one label below it:
  `*.example.com` covers `*.example.com` and `foo.example.com`, but not
  `foo.bar.example.com` and not the apex `example.com` — list the apex
  explicitly if the secret needs it.

Only `kubernetes.io/tls` secrets are listed (a `type=kubernetes.io/tls`
field selector), so other secrets never leave the apiserver.

The service account needs cluster-wide `list`, `get` and `update` on
secrets:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
    name: certdx-client
rules:
    - apiGroups: [""]
      resources: ["secrets"]
      verbs: ["list", "get", "update"]
```

### `[[Profile.TencentCloud]]` / `[[Profile.Kubernetes]]`

Named credentials referenced by update actions. Names are scoped per
profile type, so a Tencent Cloud profile and a Kubernetes profile may
share a name.

| Section | Key | Notes |
| --- | --- | --- |
| `[[Profile.TencentCloud]]` | `name` | Referenced by `profile` in a `tencentCloud` action. |
| | `secretID` / `secretKey` | Tencent Cloud API credentials. Both required. |
| | `endpoint` | Optional, defaults to `ssl.tencentcloudapi.com`. |
| `[[Profile.Kubernetes]]` | `name` | Referenced by `profile` in a `kubernetes` action. |
| | `kubeConfig` | Path to a kubeconfig. Empty means in-cluster, then `$KUBECONFIG`, then `~/.kube/config`. |

Example:

```toml
[[Profile.Kubernetes]]
name = "cluster-a"
kubeConfig = ""

[[Certificate]]
name = "wildcard-example"
domains = ["*.example.com", "example.com"]

[[Certificate.UpdateAction]]
type = "file"
savePath = "/etc/ssl/certdx"
reloadCommand = "systemctl reload nginx"

[[Certificate.UpdateAction]]
type = "kubernetes"
profile = "cluster-a"
```

## Renewal cadence

The client polls the server on the same cadence as the server's renewal
check (`ACME.renewTimeLeft / 4`). When the server returns a newer
certificate, every update action configured for it runs.

The file action's writes are atomic via a temp-file-and-rename, so a
downstream service reading the cert mid-update never observes a torn or
partial file. Its reload command runs only when both
`<savePath>/<name>.pem` and `.key` already existed — the very first
install is treated as a bootstrap where the downstream service is not
yet up.

## Common validation errors

- `no certificate configured` — add at least one `[[Certificate]]`.
- `wrong certificate configuration for <name>` — `name` and `domains` are
  both required.
- `certificate <name> has no update action configured` — add at least one
  `[[Certificate.UpdateAction]]`.
- `update action #<n>: no type set` / `unsupported type: <x>` — every
  action needs a known `type`.
- `<action> update action: no such profile: <name>` — the `profile` does
  not match any entry of the matching profile type.
- `unsupported profile type: <x>` — only `TencentCloud` and `Kubernetes`
  exist under `[Profile]`.
- `http main server url is empty` — set `Http.MainServer.url` when in HTTP mode.
- `grpc main server url is empty` — set `GRPC.MainServer.server` when in gRPC mode.
- `file not found: <path>` — an mTLS path does not exist.
- `unsupported mode: <x>` — `Common.mode` must be `http` or `grpc`.
