# certdx tools (`certdx_tools`)

A general-purpose CLI for operating a certdx deployment. Use it to inspect
the server's cache, generate the mTLS material that secures gRPC SDS and
mTLS-mode HTTPS, and register Google ACME accounts.

Pushing renewed certificates to Tencent Cloud or to Kubernetes secrets is
no longer done here: both are update actions of `certdx_client`, see
[client.md](client.md).

## Usage

```
certdx_tools <command> [options]
```

`-h` / `--help` and `-v` / `--version` are consistent across the root
command and every subcommand.

Available commands:

| Command (and aliases) | Purpose |
| --- | --- |
| [`show-certs`](#show-certs) | Print the contents of the server's certificate cache. |
| [`google-account`](#google-account) | Register a Google ACME EAB account. |
| [`make-ca`](#make-ca) | Create the mTLS CA. |
| [`make-server`](#make-server) | Issue an mTLS server certificate. |
| [`make-client`](#make-client) | Issue an mTLS client certificate. |

The mTLS commands write into an `mtls/` directory under the resolved
config root. The root is picked in this order:

1. `--data-dir <path>` flag (honored by `make-ca`, `make-server`,
   `make-client`, `show-certs`). Sets both the config root and the
   state root to the same directory.
2. `CERTDX_DATA_DIR` environment variable (same semantics).
3. Install-mode default: for FHS installs (`/usr/bin/certdx_tools`),
   config root is `/etc/certdx/` (mtls bundles) and state root is
   `/var/lib/certdx/` (`cache.json`, `private/`). For Local installs,
   both default to the directory containing the executable.

`--data-dir` points at the **parent** of `mtls/`, not at `mtls/` itself.
When a command ensures the directory exists, it is chmod'd to `0700`.
All bundles are written with mode `0600` (they contain private keys).

The `make-*` commands print the path of each file they wrote rather
than dumping the PEM blocks to stdout.

`make-client` and `make-server` reserve the name `ca` (case-insensitive,
trimmed) so a typo cannot silently overwrite the CA bundle.

---

## `show-certs`

Reads `cache.json` from the resolved data root (see `--data-dir`) and
prints the cached certificates' metadata. Use it to confirm the server
has issued the expected domains.

```sh
certdx_tools show-certs
```

| Flag | Default | Description |
| --- | --- | --- |
| `--data-dir` | *(install-mode default)* | Parent directory of `cache.json`. Env: `CERTDX_DATA_DIR`. |

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

Creates the private CA used by certdx mTLS. Writes `mtls/ca.pem` (a bundle
containing the CA cert and CA key) and `mtls/counter.txt`. Refuses to
overwrite existing files. The directory is created with mode `0700`, the
bundle with `0600`.

| Flag | Default | Description |
| --- | --- | --- |
| `-o`, `--organization` | `CertDX Private` | Subject `O`. |
| `-c`, `--common-name` | `CertDX Private Certificate Authority` | Subject `CN`. |
| `--data-dir` | *(install-mode default)* | Parent directory of `mtls/`. Env: `CERTDX_DATA_DIR`. |

## `make-server`

Issues a server-side mTLS certificate bundle (`mtls/<name>.pem`: server cert +
server key + CA cert) signed by the CA. Run after `make-ca`.

| Flag | Required | Description |
| --- | --- | --- |
| `-n`, `--name` | yes | Bundle file name. Must not be `ca`. |
| `-d`, `--dns-names` | yes | Comma-separated SANs. Must include every name a client will dial. |
| `-o`, `--organization` | | Subject `O`. Default `CertDX Private`. |
| `-c`, `--common-name` | | Subject `CN`. Default `CertDX Secret Discovery Service`. |
| `--data-dir` | | Parent directory of `mtls/`. Env: `CERTDX_DATA_DIR`. |

Example:

```sh
certdx_tools make-server -n certdx-server -d certdxserver.example.com,sds.example.com
```

## `make-client`

Issues a client certificate bundle (`mtls/<name>.pem`: client cert + client
key + CA cert) signed by the CA. Run once per consumer (`certdx_client`,
Caddy host, Envoy, etc.).

The name `ca` is reserved (case-insensitive, trimmed) so a typo cannot
silently overwrite the CA bundle.

| Flag | Required | Description |
| --- | --- | --- |
| `-n`, `--name` | yes | Logical client name. Becomes the file name. Must not be `ca`. |
| `-d`, `--dns-names` | | Optional SANs. |
| `-o`, `--organization` | | Subject `O`. |
| `-c`, `--common-name` | | Subject `CN`. Default `CertDX Client: <name>`. |
| `--data-dir` | | Parent directory of `mtls/`. Env: `CERTDX_DATA_DIR`. |

Example:

```sh
certdx_tools make-client --name caddy-edge -d edge.example.com
```

Distribute the resulting `<name>.pem` bundle to the client.

