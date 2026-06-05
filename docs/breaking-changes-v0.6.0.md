# Breaking changes in v0.6.0

v0.6.0 ships two intertwined breaking changes:

1. **Single PEM bundles** replace separate `.pem` / `.key` mTLS files
   everywhere (config, CLI flags, Caddyfile, on-disk layout).
2. **Install-mode aware path resolution** replaces cwd-based discovery
   so the same binaries can be shipped via tarball or via
   `.deb`/`.rpm` (FHS).

Every config file, CLI invocation and Caddyfile that references mTLS
material or relied on cwd state lookup must be updated. There is no
compatibility shim.

---

## 1. mTLS PEM bundles

### What changed

| Area | Before | After |
| --- | --- | --- |
| **CA** | `ca.pem` (cert, 0644) + `ca.key` (key, 0600) | `ca.pem` (cert + key bundle, 0600) |
| **Server cert** | `server.pem` + `server.key` | `<name>.pem` — user picks the name via `--name` |
| **Client cert** | `<name>.pem` + `<name>.key` | `<name>.pem` |
| **Bundle contents** | — | Entity cert + entity key + CA cert in one PEM file |
| **Permissions** | Certs 0644, keys 0600 | All bundles 0600 |
| **Reserved names** | `make-client` rejected `ca` and `server` | Only `ca` is reserved |
| **Server config** | Auto-discovered `mtls/server.{pem,key}` + `ca.pem` | Explicit `[MTLS]` section with `pem = "/path/to/bundle.pem"` |
| **Client config (HTTP mTLS / gRPC)** | `ca`, `certificate`, `key` fields | Single `pem` field |
| **Caddyfile** | `ca`, `certificate`, `key` directives | Single `pem` directive |
| **`make-server`** | No `--name` flag (always produced `server.pem`/`.key`) | `--name` / `-n` is required |
| **`make-*` output** | Dumped PEM to stdout | Prints the absolute bundle path it wrote |

### Library API

If you embed certdx:

- `pkg/paths`: `MtlsServerCertPath` / `MtlsClientCertPath` removed.
  `MtlsCAPath()` returns one path. New `MtlsBundlePath(name)`.
- `pkg/client/mtls.go` and `pkg/server/mtls.go` removed. The shared
  helper now lives in **`pkg/mtls`**:
  - `mtls.LoadServer(bundlePath) (*tls.Config, error)` —
    `RequireAndVerifyClientCert` config for server endpoints.
  - `mtls.LoadClient(bundlePath) (*tls.Config, error)` — client config
    with the bundle's CA cert in `RootCAs`.
- `pkg/config/client`: `ClientMtlsConfig` keeps only `PEM` (was `CA`,
  `Certificate`, `Key`).
- `pkg/config/server`: new `[MTLS]` section with a `pem` field;
  validated when mTLS or gRPC SDS is enabled.

### Migration — regenerate (recommended)

```sh
rm -rf mtls/
certdx_tools make-ca -o "My Org" -c "My CA"
certdx_tools make-server -n certdx-server -d certdxserver.example.com,sds.example.com
certdx_tools make-client -n caddy-edge
certdx_tools make-client -n envoy-frontend
```

### Migration — convert in place

If you cannot regenerate (pinned certificates), combine the old separate
files into bundles:

```sh
# CA bundle: cert + key → ca.pem
cat mtls/ca.pem mtls/ca.key > mtls/ca.pem.new
mv mtls/ca.pem.new mtls/ca.pem
rm mtls/ca.key
chmod 0600 mtls/ca.pem

# Extract just the CA CERTIFICATE block for entity bundles
openssl x509 -in mtls/ca.pem -outform PEM -out /tmp/ca-cert-only.pem

# Server bundle: cert + key + CA cert → <name>.pem
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

### Config updates

**Server** — add an explicit `[MTLS]` section:

```toml
[HttpServer]
authMethod = "mtls"

[gRPCSDSServer]
enabled = true

[MTLS]
pem = "/etc/certdx/mtls/certdx-server.pem"
```

**Client (HTTP mTLS)**:

```toml
[Http.MainServer]
url = "https://certdxserver.example.com:19198/api"
authMethod = "mtls"
pem = "/etc/certdx/mtls/myclient.pem"
```

**Client (gRPC)**:

```toml
[GRPC.MainServer]
server = "sds.example.com:10002"
pem = "/etc/certdx/mtls/myclient.pem"
```

**Caddyfile**:

```caddyfile
GRPC {
    main_server {
        server sds.example.com:9801
        pem /etc/certdx/mtls/caddy.pem
    }
}
```

### Envoy SDS note

Envoy still uses separate `certificate_chain`, `private_key` and
`trusted_ca` fields. If you inline material from the new entity bundle,
split the three PEM blocks back into the appropriate Envoy fields:

- First `CERTIFICATE` block → `certificate_chain`
- `EC PRIVATE KEY` block → `private_key`
- Second `CERTIFICATE` block → `trusted_ca`

---

## 2. Install-mode aware path resolution

certdx now picks one of two layouts at startup, based on where the
executable lives:

| Mode | Trigger | Config root (mtls/) | State root (cache.json, private/) |
| --- | --- | --- | --- |
| **FHS** | `GOOS=linux` **and** exe in `/usr/{,local/}{bin,sbin}` | `/etc/certdx/` | `/var/lib/certdx/` |
| **Local** | anything else (tarball, macOS, Windows, dev builds) | `<exeDir>` | `<exeDir>` |

Notes:

- The config root holds `mtls/` (cert material is treated as
  configuration, read-only at runtime). The state root holds
  `cache.json` and `private/` (ACME account keys).
- The exe path is resolved through `filepath.EvalSymlinks`, so a
  symlink such as `/usr/local/bin/certdx_server` → `/opt/certdx/...`
  lands on the symlink target's directory in Local mode.
- The location of the **config file itself** is independent — it is
  controlled by `--conf`.

### 2.1. `cwd`-based discovery removed

Previously certdx would look for `mtls/`, `private/` and `cache.json`
under the current working directory. **This fallback is removed.**

If you launched certdx from an arbitrary directory expecting it to find
state there, set `--data-dir` (or `CERTDX_DATA_DIR`) explicitly.

### 2.2. `--mtls-dir` replaced by `--data-dir` / `CERTDX_DATA_DIR`

`certdx_tools` no longer accepts `--mtls-dir`. Use `--data-dir` to
point at the **parent** of `mtls/`:

```sh
# Old
certdx_tools make-ca   --mtls-dir /opt/certdx/mtls -o "My Org" -c "My CA"
certdx_tools make-server --mtls-dir /opt/certdx/mtls -n certdx-server -d ...

# New
certdx_tools make-ca   --data-dir /opt/certdx -o "My Org" -c "My CA"
certdx_tools make-server --data-dir /opt/certdx -n certdx-server -d ...

# Or via env
export CERTDX_DATA_DIR=/opt/certdx
certdx_tools make-ca -o "My Org" -c "My CA"
```

When `--data-dir` / `CERTDX_DATA_DIR` is set, it **collapses both the
config root and the state root** onto that one directory. This is what
tarball installs and the e2e test harness rely on.

`certdx_server` accepts the same flag and env var (flag wins).
`certdx_tools` honours both for `make-ca`, `make-server`, `make-client`
and `show-certs`.

### 2.3. `certdx_client` no longer accepts `--data-dir`

The client process never reads `cache.json` or ACME account keys; its
mTLS bundle path comes from config. The `--data-dir` flag and
`CERTDX_DATA_DIR` environment variable are therefore client-irrelevant
and have been removed from `certdx_client`. Server and tools still
accept both.

### 2.4. `--conf` is now required

`certdx_server` and `certdx_client` no longer have a default config
path. Both binaries refuse to start unless `--conf <path>` is given.

- Tarball units pass `--conf /opt/certdx/config/server_config.toml`
  (or `client_config.toml`).
- FHS units pass `--conf /etc/certdx/server.toml`
  (or `client.toml`).

### 2.5. `make-*` tools print paths instead of PEM blocks

```text
$ certdx_tools make-ca --data-dir /opt/certdx -o "My Org" -c "My CA"
Wrote CA bundle: /opt/certdx/mtls/ca.pem
Wrote serial counter: /opt/certdx/mtls/counter.txt

$ certdx_tools make-server --data-dir /opt/certdx -n certdx-server -d host.example
Wrote bundle: /opt/certdx/mtls/certdx-server.pem
```

If your automation captured stdout PEM, switch to reading the printed
file.

### 2.6. systemd unit flavors

`systemd-service/` now ships two flavors:

- `certdx-{server,client}.service` — **tarball flavor**, unchanged:
  `WorkingDirectory=/opt/certdx`, explicit `--conf`,
  `--log /tmp/certdx-{server,client}.log`.
- `certdx-{server,client}-fhs.service` — **FHS flavor** for deb/rpm:
  `ExecStart=/usr/bin/certdx_server --conf /etc/certdx/server.toml`,
  runs as root, `StateDirectory=certdx`, journald logging,
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
  `PrivateTmp` hardening. `/etc/certdx/mtls/` is read-only at runtime
  (the server only reads its bundle; tools create it pre-install).

### 2.7. Library API changes

- `paths.ServerCacheSave() string` → `paths.ServerCachePath() (string, error)`.
- `server.NewCertStore()` → `server.NewCertStore() (CertStore, error)`.
- `server.MakeCertDXServer()` → `server.MakeCertDXServer() (*CertDXServer, error)`.

The new error returns surface unrecoverable path-resolution failures
(missing exe, broken symlink, unwritable state root) instead of
silently writing `cache.json` in cwd.

---

## Migration checklist

1. **Re-issue mTLS material** with the new tools (`make-ca`,
   `make-server --name <n>`, `make-client --name <n>`); distribute the
   resulting `.pem` bundles.
2. **Update server / client / Caddy configs** to the single `pem` /
   `[MTLS].pem` field instead of CA/cert/key triples.
3. **Pick an install mode.** Staying on `/opt/certdx` keeps you in
   Local mode and needs no path changes.
4. **Replace `--mtls-dir <X>`** with `--data-dir <parent-of-X>` (or
   `CERTDX_DATA_DIR`). Drop `--data-dir` / `CERTDX_DATA_DIR` from
   client invocations — the client no longer accepts them.
5. **Add `--conf <path>`** to every server/client invocation — the
   implicit default is gone.
6. **If you relied on cwd discovery** for `mtls/`, `private/` or
   `cache.json`, set `--data-dir` / `CERTDX_DATA_DIR` to that
   directory.
7. **If you parse PEM from `make-*` stdout**, switch to reading the
   bundle file the tool prints.
8. **If you package via `.deb` / `.rpm`**, install to `/usr/bin/`, use
   the `*-fhs.service` units, and place mtls bundles under
   `/etc/certdx/mtls/` (config root) — not `/var/lib/certdx/`.
9. **If you embed certdx as a library**, switch to `pkg/mtls`
   (`LoadServer` / `LoadClient`) and handle the new error returns from
   `paths.ServerCachePath`, `server.NewCertStore`, and
   `server.MakeCertDXServer`.
