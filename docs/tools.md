# certdx tools (`certdx_tools`)

A general-purpose CLI for operating a certdx deployment. Use it to inspect
the server's cache, generate the mTLS material that secures gRPC SDS and
mTLS-mode HTTPS, register Google ACME accounts, and — among other tasks —
rotate expiring Tencent Cloud certificates.

## Usage

```
certdx_tools <command> [options]
```

`-h` / `--help` and `-v` / `--version` are consistent across the root
command and every subcommand.

Available commands:

| Command (and aliases) | Purpose |
| --- | --- |
| [`show-cache`](#show-cache) | Print the contents of the server's certificate cache. |
| [`google-account`](#google-account) | Register a Google ACME EAB account. |
| [`make-ca`](#make-ca) | Create the mTLS CA. |
| [`make-server`](#make-server) | Issue an mTLS server certificate. |
| [`make-client`](#make-client) | Issue an mTLS client certificate. |
| [`tencent-cloud-certificate-updater`](#tencent-cloud-certificate-updater) (alias: `tx-update`, `tencent-cloud-certificates-updater`) | Pull a cert from a certdx server and replace expiring Tencent Cloud certificates. |
| [`kubernetes-certificate-updater`](#kubernetes-certificate-updater) (alias: `k8s-update`, `k8s-certificate-updater`) | Pull a cert from a certdx server and patch annotated Kubernetes TLS secrets. |

The mTLS commands write into an `mtls/` directory next to the executable
(or the current working directory). Run them in the same directory you run
`certdx_server` from — typically `/opt/certdx` — so the server picks them
up automatically. To override the location explicitly, pass `--mtls-dir
<path>`; the flag is honored by `make-ca`, `make-server`, `make-client`,
and `certdx_server` itself. When a command ensures the directory exists,
it is chmod'd to `0700`. Cert PEMs are written with mode `0644` and
private keys with mode `0600`.

`make-client` reserves the names `ca` and `server` (case-insensitive,
trimmed) so a typo cannot silently overwrite the CA or server material.

---

## `show-cache`

Reads `cache.json` from the working directory and prints the cached
certificates' metadata. Use it to confirm the server has issued the expected
domains.

```sh
certdx_tools show-cache
```

## `google-account`

Registers a Google Trust Services ACME account using EAB credentials. The
account key is saved into `private/<email>_<provider>.key` so the server can
load it later.

Usually you do not need this command: if `[GoogleCloudCredential]` is set in
the server config, the server will register an EAB account automatically on
first start. Use this command only when you want to register an account
manually (for example, on a host that does not have access to the Google
Cloud credentials).

| Flag | Required | Description |
| --- | --- | --- |
| `-e`, `--email` | yes | Email address to register. |
| `-k`, `--kid` | yes | EAB key id. |
| `-m`, `--hmac` | yes | EAB B64 HMAC. |
| `-t`, `--test-account` | | Register against the Google staging endpoint (`googletest`). |
| `-h`, `--help` | | Print help. |

Example:

```sh
certdx_tools google-account \
    --email me@example.com \
    --kid AAAA \
    --hmac BBBB
```

## `make-ca`

Creates the private CA used by certdx mTLS. Writes `mtls/ca.pem`,
`mtls/ca.key`, and `mtls/counter.txt`. Refuses to overwrite existing files.
The directory is created with mode `0700`, the CA cert with `0644`, and
the CA key with `0600`.

| Flag | Default | Description |
| --- | --- | --- |
| `-o`, `--organization` | `CertDX Private` | Subject `O`. |
| `-c`, `--common-name` | `CertDX Private Certificate Authority` | Subject `CN`. |
| `--mtls-dir` | *(empty: discover via cwd → exec dir)* | Override the mTLS material directory. |

## `make-server`

Issues the server-side mTLS certificate (`mtls/server.pem`, `mtls/server.key`)
signed by the CA. Run after `make-ca`.

| Flag | Required | Description |
| --- | --- | --- |
| `-d`, `--dns-names` | yes | Comma-separated SANs. Must include every name a client will dial. |
| `-o`, `--organization` | | Subject `O`. Default `CertDX Private`. |
| `-c`, `--common-name` | | Subject `CN`. Default `CertDX Secret Discovery Service`. |
| `--mtls-dir` | | Override the mTLS material directory. |

Example:

```sh
certdx_tools make-server -d certdxserver.example.com,sds.example.com
```

## `make-client`

Issues a client certificate (`mtls/<name>.pem`, `mtls/<name>.key`) signed by
the CA. Run once per consumer (`certdx_client`, Caddy host, Envoy, etc.).

The names `ca` and `server` are reserved (case-insensitive, trimmed) so a
typo cannot silently overwrite the CA or server material.

| Flag | Required | Description |
| --- | --- | --- |
| `-n`, `--name` | yes | Logical client name. Becomes the file name. Must not be `ca` or `server`. |
| `-d`, `--dns-names` | | Optional SANs. |
| `-o`, `--organization` | | Subject `O`. |
| `-c`, `--common-name` | | Subject `CN`. Default `CertDX Client: <name>`. |
| `--mtls-dir` | | Override the mTLS material directory. |

Example:

```sh
certdx_tools make-client --name caddy-edge -d edge.example.com
```

Distribute the resulting `<name>.pem` / `<name>.key` (and a copy of `ca.pem`)
to the client.

---

## `tencent-cloud-certificate-updater`

Aliases: `tx-update`, `tencent-cloud-certificates-updater`.

Acts as a one-shot certdx client: connects to a certdx server, pulls the
configured certificates, then calls the Tencent Cloud SSL API to replace
matching certificates that are about to expire. Suitable for running on a
cron schedule.

```sh
certdx_tools tencent-cloud-certificate-updater -c updater.toml
```

| Flag | Default | Description |
| --- | --- | --- |
| `-c`, `--conf` | `./client.toml` | Path to the TOML config. |
| `-d`, `--debug` | `false` | Enable debug logging. |
| `-h`, `--help` | | Print help. |

### Config file

A working example is shipped as
`config/client_tencentcloud_certificate_updater.toml`.

```toml
[Http.MainServer]
url = "https://certdxserver.example.com:10001/"
token = "KFCCrazyThursdayVMe50"

[Authorization]
secretID = "tencent cloud secret id"
secretKey = "tencent cloud secret key"

[[Certifications]]
name = "display name"
domains = ["*.example.com"]
resourceTypes = ["teo"]
resourceTypesRegions = [
    { resourceType = "", regions = [] }
]
```

Sections:

- `[Http.MainServer]` — same shape as a `certdx_client` HTTP main server.
- `[Authorization]` — Tencent Cloud SecretId / SecretKey.
- `[[Certifications]]` — one entry per cert to update:
  - `name` — display name shown in Tencent Cloud SSL.
  - `domains` — used to locate the existing certificates on
    <https://console.cloud.tencent.com/ssl> that should be replaced.
  - `resourceTypes` — list of resource types whose bindings should be
    re-pointed to the new certificate. Tencent Cloud values include
    `clb`, `cdn`, `waf`, `live`, `vod`, `ddos`, `tke`, `apigateway`, `tcb`, `teo`.
    See <https://cloud.tencent.com/document/product/400/91649>.
  - `resourceTypesRegions` — optional per-resource-type region filter, e.g.
    `[{ resourceType = "clb", regions = ["ap-guangzhou"] }]`.

---

## `kubernetes-certificate-updater`

Aliases: `k8s-update`, `k8s-certificate-updater`.

Acts as a one-shot certdx client targeting Kubernetes. It lists every
`kubernetes.io/tls` secret across the cluster, picks the ones annotated
with `party.para.certdx/domains`, fetches the matching certificate from
the certdx server, and patches `tls.crt` / `tls.key` in place. It does
not create new secrets and does not modify any other field.

The updater terminates after every annotated secret has been refreshed
once (or after a 10-minute deadline). Run it as a Kubernetes Job or
CronJob.

```sh
certdx_tools kubernetes-certificate-updater -c k8s-updater.toml
```

| Flag | Default | Description |
| --- | --- | --- |
| `-c`, `--conf` | `./client.toml` | Path to the certdx client TOML config. |
| `--k8sConf` | *(empty)* | Kubeconfig path. Empty: use the in-cluster service account, falling back to `$KUBECONFIG` / `~/.kube/config`. |
| `-d`, `--debug` | `false` | Enable debug logging. |
| `-h`, `--help` | | Print help. |

### Annotating secrets

Mark every TLS secret you want managed with the domain list the certdx
server should issue:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: wildcard-example
  namespace: edge
  annotations:
    party.para.certdx/domains: "*.example.com,example.com"
type: kubernetes.io/tls
data:
  tls.crt: ""
  tls.key: ""
```

Domains are comma-separated, case-insensitive, and de-duplicated.
Secrets whose domains are not covered by any `[[Certifications]].domains`
entry in the updater config are skipped with a warning.

### Config file

A minimal example is shipped as `config/client_k8s.toml`. The schema is
the regular `certdx_client` config (see [client.md](client.md)) —
`savePath` and `reloadCommand` are not used and may be omitted:

```toml
[Http.MainServer]
url = "https://certdxserver.example.com:10001/"
token = "KFCCrazyThursdayVMe50"

[[Certifications]]
name = "domainsToWatch"
domains = [
    "*.example.com",
    "*.mm.example.com",
]
```

The `domains` lists in `[[Certifications]]` act as the allowlist for the
updater: a secret annotated with `foo.example.com` is allowed because it
is covered by `*.example.com`. gRPC mode (`Common.mode = "grpc"` plus
`[GRPC.MainServer]`) is supported as well.

### RBAC

The updater performs a cluster-wide list of secrets, plus get/update on
the ones it touches. The minimum role is:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: certdx-secret-updater
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["list", "get", "update"]
```

Bind it to the service account that runs the Job / CronJob with a
`ClusterRoleBinding`.
