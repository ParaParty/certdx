# CertDX domain glossary

This file defines the vocabulary used in `certdx`'s code, configs, and
docs. If a term is ambiguous between code and conversation, this file is
the authoritative spelling and meaning. Update it whenever a new domain
term enters the codebase.

## Roles in the deployment

- **certdx_server**: the single ACME issuer for a fleet. Talks to
  Let's Encrypt or Google Trust Services, caches certificates, and
  serves them to clients over HTTP and/or gRPC SDS.
- **certdx_client**: a standalone daemon that pulls certificates from a
  `certdx_server` and writes them to disk, optionally running a reload
  command (e.g. `systemctl reload nginx`).
- **Caddy plugin** (`exec/caddytls`): a Caddy module that consumes
  `certdx_server` directly via Caddy's `get_certificate` extension
  point, with no `certdx_client` daemon in between.
- **Envoy SDS consumer**: any Envoy instance that connects to the
  `certdx_server` gRPC SDS endpoint and hot-swaps certificates on
  receipt.
- **certdx_tools**: the operator CLI for one-shot tasks (cert cache
  inspection, mTLS material generation, ACME account registration, and
  the Tencent Cloud / Kubernetes certificate updaters).

## Lifecycle vocabulary

- **Subscriber**: a goroutine that has called `Server.Subscribe(entry)`
  on a cache entry and not yet `Release`d it. The renewal goroutine is
  alive while at least one subscriber is registered.
- **Renewer**: the per-entry goroutine spawned by the first subscriber
  (the 0→1 transition). It re-checks expiry on `RenewTimeLeftDuration / 4`
  intervals and obtains a new certificate when the cached one expires.
- **Stop**: the public lifecycle hand-off. Both `CertDXServer.Stop()` and
  `CertDXClientDaemon.Stop()` cancel the daemon's root context exactly
  once. Every internal subgoroutine selects on the root context, so
  `Stop` drains them all without a separate stop chan.

## Cert cache

- **Cert pack**: a single named bundle of domains served as one
  certificate. The Envoy SDS protocol identifies cert packs by
  `ResourceName`; the HTTP API does not name them and just returns the
  cert for the requested domain set.
- **Cache entry** (`ServerCertCacheEntry`): the in-memory record for one
  cert pack — current cert + version + subscriber refcount + the
  `updated` channel that broadcasts renewal events.
- **Version**: a monotonically increasing renewal counter on each cache
  entry. Subscribers pass the last version they observed to
  `WaitForUpdate`; the renewer increments it on every successful
  renewal. Pairs with the `updated` channel to make the broadcast
  miss-free.
- **Snapshot**: an atomic read of `(cert, version)` from a cache entry.
  Always read the pair via `entry.Snapshot()` rather than separately, so
  callers don't observe a torn pair across a renewal.

## ACME

- **Allow-list** (`ACME.allowedDomains`): the set of base domains a
  `certdx_server` is willing to issue under. Any cert request whose
  domains aren't all subdomains of this list is rejected with
  `domain.ErrNotAllowed`.
- **Provider** (`ACME.provider`): the ACME directory to use — `r3`,
  `r3test`, `google`, `googletest`, or the in-process `mock`. The list
  and URL lookup live in `pkg/acme/acmeproviders/`.
- **Mock provider**: an in-process ACME stand-in (`pkg/acme/mock.go`)
  that mints self-signed leaf certs without contacting any ACME server.
  The e2e test suite uses it for hermetic test runs.
- **Challenge provider**: the DNS-01 or HTTP-01 backend that satisfies
  the ACME challenge. Lives under `pkg/acme/challengeproviders/` —
  `cloudflare`, `tencentcloud`, and `s3` (HTTP-01). The Google EAB
  helper sits separately under `pkg/acme/acmeproviders/google/`; it is
  not a challenge backend.

## Failover

- **Main**, **Standby**: the two `CertDXgRPCClient` instances a
  `certdx_client` in gRPC mode runs against. Main is the preferred
  server; standby is engaged when main has been unreachable for
  `RetryCount * 15s`.
- **Failover session**: a single FAILOVER → TRY_FALLBACK →
  RESTART_MAIN cycle on the gRPC client. Scoped by a `sessionCtx`
  derived from `rootCtx`. Cancelled either when main recovers (the
  fallback goroutine sees a message arrive) or when `Stop()` fires.
- **Reset**: legacy term for "cancel the current failover session". The
  current implementation expresses this as `sessionCancel()` followed by
  the dispatcher creating a fresh session.

## On-disk artifacts

- **`mtls/`**: the directory holding mTLS material. Discovery order is
  `--mtls-dir` flag, then `mtls/` under cwd, then `mtls/` next to the
  executable.
- **`cache.json`**: the server's persisted cert cache, written next to
  the executable. Schema is the JSON encoding of
  `map[domain.Key]ServerCacheFileEntry`.
- **`private/`**: the directory holding ACME account private keys. One
  key per `(email, provider)` pair, named `<email>_<provider>.key`.
- **Counter**: the `mtls/counter.txt` file holding the next CA serial
  number. Only used by `certdx_tools make-server` / `make-client`.

## Wire contracts (must-not-break)

- **HTTP API**: `POST /` on the server with a JSON body
  `api.HttpCertReq`, returning `api.HttpCertResp`. Called by
  `certdx_client` in HTTP mode and the Caddy plugin in HTTP mode.
- **gRPC SDS**: the standard Envoy `SecretDiscoveryService` protocol on
  the server, with cert-pack metadata in the `Node.Metadata` field
  under the `domains` key. Consumed by Envoy directly and by
  `certdx_client` in gRPC mode.
- **Caddyfile syntax**: the `certdx { ... }` global option and the
  `certdx <cert-id>` `get_certificate` provider directive.
- **Kubernetes annotation**: `party.para.certdx/domains`. Comma-
  separated, case-insensitive, de-duplicated.
