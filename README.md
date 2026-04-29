# CertDX

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/ParaParty/certdx)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**One ACME daemon for your whole fleet.** CertDX runs ACME in a single
place, caches the certificates, and hands them out to as many services as
you need over HTTPS or gRPC SDS — so individual hosts never touch ACME, DNS
APIs, or rate limits.

## Highlights

- **One issuer, many consumers** — `certdx_server` is the only thing that
  talks to Let's Encrypt or Google Trust Services. Every other host pulls
  finished certificates from it.
- **Wildcards out of the box** — DNS-01 challenges via Cloudflare or Tencent
  Cloud, including `*.example.com`. One wildcard certificate is shared across
  all consumers, so you never hit CA rate limits no matter how many hosts or
  services need it.
- **Drop-in for what you already run:**
  - **Standalone agent** that writes `<name>.pem` / `<name>.key` to disk and
    runs `systemctl reload nginx` (or any command).
  - **Caddy plugin** as a `get_certificate` provider.
  - **Envoy** via gRPC SDS — hot-swaps certificates with no restart.
  - **Kubernetes secret updater** that refreshes annotated `kubernetes.io/tls`
    secrets in-place — usable as a one-shot Job or CronJob.
  - **Tencent Cloud updater** that re-binds expiring certificates on
    CLB / CDN / WAF / TEO and friends.
- **Auth that fits the deployment** — shared bearer token over HTTPS for
  simple setups, mTLS or gRPC SDS for everything else.
- **Resilient by design** — clients support a standby server with
  automatic failover; the server keeps a local cache so restarts are cheap.

## How it works

```
ACME CA  <----->  certdx_server  ----->  certdx_client       --(file + reload)-->  nginx / haproxy / ...
                       |          ----->  Caddy plugin        --(in-memory)----->  Caddy
                       +--------- ----->  Envoy (SDS)         --(hot reload)---->  Envoy listeners
                                  ----->  certdx_tools k8s    --(patch secret)-->  Kubernetes TLS secrets
```

The server is the only component talking to the ACME CA; everything else is
a consumer.

## Supported clients

| Client | How it works |
| --- | --- |
| **certdx client** | Standalone daemon. Writes cert/key files to disk and runs a reload command (e.g. `systemctl reload nginx`). |
| **Caddy plugin** | Caddy [`get_certificate`](https://caddyserver.com/docs/caddyfile/directives/tls#get_certificate) module — certificates stay in memory, no files. |
| **Envoy (gRPC SDS)** | Envoy connects to the server's SDS endpoint directly; certificates are hot-swapped with no restart. |
| **Kubernetes secret updater** | `certdx_tools kubernetes-certificate-updater` patches annotated `kubernetes.io/tls` secrets in-place — run as a Job or CronJob. |
| **certdx tools** | General-purpose CLI: inspect the cache, generate mTLS material, register Google ACME accounts, replace expiring Tencent Cloud / Kubernetes certificates, and more. |

## Quick start

Grab the latest release archive for your platform from GitHub releases,
unpack it and move it into place:

```sh
tar -xzf certdx_linux_amd64.tar.gz
sudo mv certdx_linux_amd64 /opt/certdx
```

`/opt/certdx` now has `certdx_server`, `certdx_client`, `certdx_tools`,
example configs under `config/`, and ready-to-use systemd units under
`systemd-service/`. Edit `config/server_config.toml` and
`config/client_config.toml`, then enable the units:

```sh
sudo cp /opt/certdx/systemd-service/certdx-server.service /etc/systemd/system/
sudo cp /opt/certdx/systemd-service/certdx-client.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now certdx-server certdx-client
```

Full walk-through: [docs/quickstart.md](docs/quickstart.md).

## Documentation

| | |
| --- | --- |
| [Quickstart](docs/quickstart.md) | 5-minute server + client setup. |
| [Setup guide](docs/setup.md) | All deployment options (mTLS, gRPC SDS, Envoy, Caddy, K8s). |
| [Server reference](docs/server.md) | Every option in `server_config.toml`. |
| [Client reference](docs/client.md) | Every option in `client_config.toml`. |
| [Caddy plugin](docs/caddytls.md) | Caddyfile syntax. |
| [Tools](docs/tools.md) | `certdx_tools` subcommands (cache, mTLS material, Tencent Cloud updater, …). |

External: [DeepWiki](https://deepwiki.com/ParaParty/certdx).
