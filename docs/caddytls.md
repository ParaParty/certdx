# Caddy plugin

This plugin lets Caddy fetch certificates from a certdx server instead of
running ACME itself. It registers a Caddy app named `certdx` and a
[`get_certificate`](https://caddyserver.com/docs/caddyfile/directives/tls#get_certificate)
provider you can use per site.

## Building

The plugin is a Caddy module, not a standalone binary. Build a Caddy binary
that includes it with [`xcaddy`](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build --with pkg.para.party/certdx/exec/caddytls
```

That pulls the published version of the plugin and the matching
`pkg.para.party/certdx` core from the module proxy.

Official release archives `caddy_certdx_<os>_<arch>` already ship a Caddy
binary built with this plugin.

### Building from a local checkout

If you are iterating on the plugin or on `pkg.para.party/certdx` itself,
point xcaddy at both the plugin source AND the parent module. The two
flags are needed together — without `--replace`, xcaddy resolves the
parent `pkg.para.party/certdx` import via the registry instead of your
checkout, and you'll silently build against the published version:

```sh
GOWORK=off xcaddy build \
  --with pkg.para.party/certdx/exec/caddytls=./exec/caddytls \
  --replace pkg.para.party/certdx=./
```

`GOWORK=off` is required because xcaddy creates its temp build dir
inside the repo (which sits in the `go.work` workspace). Without it,
Go enters workspace mode and bypasses the `--replace` flags, leading
to "cannot find module" failures or silent fallback to the registry
version. `release/build.py --dev` sets this for you.

To verify the resulting binary actually picked up your local code,
inspect its embedded build metadata:

```sh
go version -m ./caddy | grep certdx
```

Both `pkg.para.party/certdx` and `pkg.para.party/certdx/exec/caddytls`
should show `=> /path/to/your/checkout (devel)` — the `=>` line is
the proof that `--replace` was honored. The recorded version may
still read `vX.Y.Z` (the latest registry tag), but the bound source
is from your checkout.

## Caddyfile syntax

The plugin is configured through the global `certdx { ... }` block, then
referenced per-site with `tls { get_certificate certdx <cert-id> }`. Use
`auto_https off` so Caddy does not try to obtain certificates itself.

### Global `certdx` block

```caddyfile
{
    auto_https off
    certdx {
        retry_count 5
        mode http               # http | grpc
        reconnect_interval 10m  # gRPC reconnect cadence

        http {
            main_server { ... }
            standby_server { ... }   # optional
        }

        GRPC {
            main_server { ... }
            standby_server { ... }   # optional
        }

        certificate <cert-id> {
            domain1
            domain2
            ...
        }
    }
}
```

Top-level directives:

| Directive | Argument | Notes |
| --- | --- | --- |
| `retry_count` | int | Per-request retry count. |
| `mode` | `http` \| `grpc` | Transport to use. |
| `reconnect_interval` | duration | gRPC reconnect cadence (same semantics as the standalone client). |
| `http` | block | HTTP transport options. |
| `GRPC` | block | gRPC transport options. |
| `certificate <id>` | block | Defines a certificate id and the SANs it should cover. Used by `get_certificate certdx <id>`. |

### `http { main_server | standby_server }` block

| Directive | Notes |
| --- | --- |
| `url` | Full URL including the server's `apiPath`. |
| `authMethod` | `token` (default) or `mtls`. |
| `token` | Bearer token for `authMethod token`. |
| `ca`, `certificate`, `key` | mTLS material for `authMethod mtls`. |

### `GRPC { main_server | standby_server }` block

| Directive | Notes |
| --- | --- |
| `server` | `host:port` of the certdx gRPC SDS endpoint. |
| `ca`, `certificate`, `key` | mTLS material (always required for gRPC). |

### Per-site usage

```caddyfile
https://example.com {
    tls {
        get_certificate certdx my-cert
    }
}
```

`my-cert` must match a `certificate <id> { ... }` block in the global config.

## Full example

```caddyfile
{
    auto_https off
    certdx {
        retry_count 10
        mode grpc
        reconnect_interval 15m

        http {
            main_server {
                url https://certdxserver.example.com:19198/1145141919810
                authMethod token
                token KFCCrazyThursdayVMe50
            }
        }

        GRPC {
            main_server {
                server sds.example.com:9801
                ca   /opt/certdx/mtls/ca.pem
                certificate /opt/certdx/mtls/caddy.pem
                key  /opt/certdx/mtls/caddy.key
            }
        }

        certificate wildcard-example {
            *.example.com
            example.com
        }
    }
}

https://app.example.com {
    tls {
        get_certificate certdx wildcard-example
    }
    reverse_proxy localhost:9090
}
```

## See also

- Caddy `get_certificate` directive: <https://caddyserver.com/docs/caddyfile/directives/tls#get_certificate>
- [server.md](server.md) for the matching server configuration.
- [tools.md](tools.md) for generating the mTLS material in gRPC mode.
