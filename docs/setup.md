# Setup guide

This guide is the long form of [quickstart.md](quickstart.md). Read it when
you need something beyond the simple HTTPS-token deployment: a different
ACME provider, mTLS, gRPC SDS, Envoy, Caddy, or Kubernetes.

Reference pages with every option:

- [server.md](server.md) — server config.
- [client.md](client.md) — client config.
- [caddytls.md](caddytls.md) — Caddyfile syntax.
- [tools.md](tools.md) — `certdx_tools` subcommands.

## Architecture

`certdx_server` is the only component that talks to the ACME CA. Everything
else — `certdx_client`, the Caddy plugin, Envoy via SDS, the Kubernetes
secret updater, the Tencent Cloud updater — is a consumer that pulls
finished certificates from the server.

## 1. Pick the ACME provider

Configured under `[ACME]` in the server config (see [server.md](server.md)).

| Provider | Use when |
| --- | --- |
| `r3` | Default. Let's Encrypt production. |
| `r3test` | Let's Encrypt staging — for first-time setup and CI. |
| `google` | Google Trust Services. Requires EAB registration. |
| `googletest` | Google Trust Services staging. |

### Google Cloud credentials

The Google providers (`google`, `googletest`) require an EAB account. If you
set `[GoogleCloudCredential]` in the server config, the server registers the
EAB account automatically on first start using the Google Public CA API.

To obtain the credential:

1. Open the Google Cloud Console and create (or pick) a project.
2. Enable the **Public Certificate Authority API** for that project.
3. Grant the principal the **Public CA External Account Key Creator** IAM
   role.
4. Create a service account with that role and download a JSON key.
5. Open the JSON file and copy every key/value pair into the
   `[GoogleCloudCredential]` section of the server config. The
   `private_key` field contains literal `\n` escapes — keep them as-is.

A full example layout is shipped as `config/server_config_full.toml`.

If you cannot put the JSON credential on the server host, register the EAB
account manually instead with `certdx_tools google-account` (see
[tools.md](tools.md)).

## 2. Pick a challenge type

Configured by `ACME.challengeType`.

### DNS-01 (recommended)

Required for wildcard certificates. Configure `[DnsProvider]`:

- `cloudflare` — either `email` + `apiKey` (global API key) or `authToken` +
  `zoneToken` (scoped tokens).
- `tencentcloud` — `secretID` + `secretKey`.

### HTTP-01

Configure `[HttpProvider]` with `type = "s3"` and the S3-compatible bucket
that serves your domains. Wildcards are not supported with HTTP-01.

## 3. Pick a distribution mode

The server can expose certificates in three ways. They are independent and
can be enabled together.

### HTTPS with bearer token

Easiest to deploy. In `[HttpServer]` set `enabled = true`,
`authMethod = "token"`, `secure = true`, `names = ["certdx.example.com"]`,
and a long random `token`. The server issues its own ACME certificate for
`names` so it can serve HTTPS.

Clients (`certdx_client`, the Caddy plugin, the Tencent Cloud updater) point
at the resulting HTTPS URL with the same token.

### HTTPS with mTLS

Set `HttpServer.authMethod = "mtls"`. Issue the CA and server/client
certificates with `certdx_tools` (see [mtls](#mtls) below). Clients use
`authMethod = "mtls"` plus `ca`, `certificate` and `key` paths.

### gRPC SDS

Set `gRPCSDSServer.enabled = true` and provide `names` for the SDS server
certificate. mTLS is mandatory; reuse the same `mtls/` directory.

Consumers:

- `certdx_client` with `Common.mode = "grpc"` and `[GRPC.MainServer]`.
- The Caddy plugin in `mode grpc`.
- Envoy directly, via its standard SDS configuration; no certdx client is
  needed in that case.

## mTLS

The mTLS material lives in an `mtls/` directory. By default it is
discovered next to the executable, or under the current working directory.
Override the location with the `--mtls-dir <path>` flag (passed to
`certdx_server`, `make-ca`, `make-server`, or `make-client`). The
directory is created with mode `0700`; certs land at `0644` and private
keys at `0600`. The server reads
`mtls/server.pem`, `mtls/server.key` and `mtls/ca.pem`; clients use a
per-client `<name>.pem` / `<name>.key` plus a copy of `ca.pem`.

Generate everything with `certdx_tools` on the server host:

```sh
certdx_tools make-ca
certdx_tools make-server -d certdxserver.example.com,sds.example.com
certdx_tools make-client --name nginx-edge
certdx_tools make-client --name caddy-edge
certdx_tools make-client --name envoy-frontend
```

`-d` on `make-server` must include every name a client will dial. Distribute
`ca.pem` plus each `<name>.pem` / `<name>.key` to the matching consumer.
Keep `ca.key` only on the server host. The names `ca` and `server` are
reserved for the CA and server-cert files; `make-client` rejects them so a
typo cannot silently overwrite the CA or server material.

See [tools.md](tools.md) for the full flag set.

## 4. Server-side install

Download the release archive, unpack it and move the resulting directory to
`/opt/certdx`:

```sh
tar -xzf certdx_linux_amd64.tar.gz
sudo mv certdx_linux_amd64 /opt/certdx
```

The directory contains everything the server needs:

```
/opt/certdx/
├── certdx_server
├── certdx_client       (unused on a server-only host)
├── certdx_tools
├── config/
│   ├── server_config.toml
│   └── ...
├── systemd-service/
└── LICENSE
```

When the server runs from `/opt/certdx`, it creates these alongside the
binary as needed:

```
/opt/certdx/
├── mtls/        (only if using mTLS / gRPC SDS)
├── private/     (ACME account keys)
└── cache.json   (created by the server)
```

Install and start the systemd unit shipped in the archive:

```sh
sudo cp /opt/certdx/systemd-service/certdx-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now certdx-server
journalctl -u certdx-server -f
```

## 5. Client-side install

### Standalone client

Use the same release archive on the client host — unpack it and move the
directory to `/opt/certdx` exactly as for the server. Edit
`config/client_config.toml`, then enable the client unit:

```sh
sudo cp /opt/certdx/systemd-service/certdx-client.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now certdx-client
```

The client writes `<savePath>/<name>.pem` and `.key`, then runs
`reloadCommand`. Typical reload commands:

- nginx: `systemctl reload nginx`
- haproxy: `systemctl reload haproxy`
- custom: `bash /opt/acme/reload.sh`

### Caddy

Build a Caddy binary that includes the certdx plugin:

```sh
xcaddy build --with pkg.para.party/certdx/exec/caddytls
```

Configure it via the `certdx { ... }` global option and use
`tls { get_certificate certdx <id> }` per site. See [caddytls.md](caddytls.md).

### Envoy via SDS

The certdx server's gRPC SDS endpoint is a normal Envoy SDS service. Envoy
talks to it directly — no certdx client is needed.

1. **Create an Envoy client certificate** with `certdx_tools make-client
   --name envoy-frontend`. You will inline the contents of
   `mtls/ca.pem`, `mtls/envoy-frontend.pem` and `mtls/envoy-frontend.key`
   into the Envoy config below.

2. **Tell the server which secrets Envoy will request** via Envoy's node
   metadata. Each top-level key under `domains` is a secret name; its value
   is the list of SANs to issue. The certdx server uses this metadata to
   know which domains to serve when Envoy requests a given secret name.

   ```yaml
   node:
     id: envoy-frontend
     cluster: envoy-frontend
     metadata:
       domains:
         wildcard_example: ["*.example.com", "example.com"]
         api_example:      ["api.example.com"]
   ```

   The domains must be covered by the server's `ACME.allowedDomains`.

3. **Define an SDS cluster** that points at the certdx gRPC endpoint and uses
   the client certificate for mTLS. Use `LOGICAL_DNS`, force HTTP/2, and
   pin TLS to 1.3:

   ```yaml
   static_resources:
     clusters:
     - name: certdx_sds
       type: LOGICAL_DNS
       connect_timeout: 1s
       typed_extension_protocol_options:
         envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
           "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
           explicit_http_config:
             http2_protocol_options:
               initial_stream_window_size:     65536    # 64 KiB
               initial_connection_window_size: 1048576  # 1 MiB
               allow_connect: false
               connection_keepalive:
                 interval: 30s
                 timeout:  20s
       load_assignment:
         cluster_name: certdx_sds
         endpoints:
         - lb_endpoints:
           - endpoint:
               address:
                 socket_address:
                   address: sds.example.com
                   port_value: 10002
       transport_socket:
         name: envoy.transport_sockets.tls
         typed_config:
           "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
           common_tls_context:
             tls_params:
               tls_minimum_protocol_version: TLSv1_3
               tls_maximum_protocol_version: TLSv1_3
             tls_certificates:
             - certificate_chain:
                 inline_string: |
                   -----BEGIN CERTIFICATE-----
                   <contents of envoy-frontend.pem>
                   -----END CERTIFICATE-----
               private_key:
                 inline_string: |
                   -----BEGIN PRIVATE KEY-----
                   <contents of envoy-frontend.key>
                   -----END PRIVATE KEY-----
             validation_context:
               trusted_ca:
                 inline_string: |
                   -----BEGIN CERTIFICATE-----
                   <contents of ca.pem>
                   -----END CERTIFICATE-----
   ```

   The client certificate, private key and CA are inlined here so the SDS
   cluster can come up before any filesystem secrets are loaded.

4. **Reference an SDS secret on a listener.** The `name` field must match a
   key under `node.metadata.domains`:

   ```yaml
   transport_socket:
     name: envoy.transport_sockets.tls
     typed_config:
       "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
       common_tls_context:
         tls_certificate_sds_secret_configs:
         - name: wildcard_example
           sds_config:
             initial_fetch_timeout: 120s
             resource_api_version: V3
             api_config_source:
               api_type: GRPC
               transport_api_version: V3
               grpc_services:
               - envoy_grpc:
                   cluster_name: certdx_sds
   ```

   On startup Envoy opens a streaming SDS request to the certdx server,
   which responds with the matching certificate and pushes a new version
   on every renewal — Envoy hot-swaps the certificate without a restart.

### Kubernetes

Use `certdx_tools kubernetes-certificate-updater` to refresh existing
`kubernetes.io/tls` secrets in-place. The updater finds every TLS secret
annotated with `party.para.certdx/domains`, asks the certdx server for
the matching certificate, and patches the secret — it never creates new
secrets and never edits anything else.

Mark each secret you want managed:

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
  tls.crt: ""   # placeholder; the updater will fill these in
  tls.key: ""
```

Provide the updater with a certdx client config that lists every domain
set under `[[Certifications]]` (a minimal example is shipped as
`config/client_k8s.toml`). Domains in a secret's annotation must be
covered by one `[[Certifications]].domains` entry — secrets whose domains
fall outside the allowlist are skipped.

Run it as a one-shot Job or on a schedule with a CronJob. The updater
requires cluster-wide read/list of TLS secrets and update on the ones it
matches:

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

In-cluster invocation uses the pod's service account automatically. To
run it outside the cluster, point it at a kubeconfig with `--k8sConf`.
See [tools.md](tools.md#kubernetes-certificate-updater) for the full flag
set.

### Tencent Cloud certificate replacement

For Tencent Cloud resources (CLB, CDN, WAF, TEO, …) that hold an uploaded
certificate, run `certdx_tools tencent-cloud-certificate-updater` on a
schedule (cron / systemd timer) to fetch the latest certificate from the
server and re-bind expiring ones. See [tools.md](tools.md#tencent-cloud-certificate-updater).

## 6. Operations

- **Logs:** pass `-l /path/to/log` to redirect, `-d` to enable debug.
- **Test mode:** `certdx_client -t` skips TLS verification on the server URL,
  useful while bringing up `secure = true` for the first time.
- **Cache:** inspect with `certdx_tools show-cache` in the server's working
  directory.
- **Renewal cadence:** the server checks every `ACME.renewTimeLeft / 4` and
  renews when remaining lifetime drops below `renewTimeLeft`.
- **Releases:** prebuilt archives are published for `linux/{amd64,arm,arm64}`,
  `darwin/arm64` and `windows/amd64`, plus a `caddy_certdx_*` bundle
  containing a Caddy binary with the plugin baked in.

## 7. Security notes

- The bearer token grants the holder any certificate the server can issue for
  `allowedDomains`. Treat it like a secret; rotate by changing the token on
  both sides.
- Prefer mTLS for cross-host deployments.
- Private keys are written with `0600`. Make sure `savePath` and the `mtls/`
  directory are not world-readable.
- Set `HttpServer.secure = true` whenever the server is reachable outside a
  trusted network.
