# Docker

The published image carries all three binaries, so one image covers the
server, the client and the operational tooling.

## What is in the image

| | |
| --- | --- |
| Binaries | `/app/certdx_server`, `certdx_client`, `certdx_tools`, symlinked into `/usr/local/bin` |
| Base | `debian:trixie-slim` with `ca-certificates` |
| User | `65532:65532` (non-root) |
| Data dir | `/data`, pre-created and owned by `65532` |
| Entrypoint | none — the first argument names the binary to run |

The image sets `CERTDX_DATA_DIR=/data`, so mTLS material is read from
`/data/mtls/` and state (`cache.json`, `private/`) is written to `/data`.
The path is pinned rather than derived from the binaries' location;
override it per container with `-e CERTDX_DATA_DIR=<path>` or the
`--data-dir` flag. Both the environment variable and the
`/usr/local/bin` symlinks survive `docker exec` and login shells, so an
interactive session inside the container needs no extra flags. See
[setup.md](setup.md) for the path rules outside containers.

There is no entrypoint, so every invocation names a binary:

```sh
docker run --rm paraparty/certdx:<tag> certdx_client --version
```

## Building the image

```sh
release/build-docker.sh          # paraparty/certdx:<short-commit>
release/build-docker.sh --dev    # paraparty/certdx:<short-commit>-dev
```

On Windows use `release/build-docker.ps1` with the optional `-Dev`
switch.

The builder stage runs `release/build.py docker`, the same script that
produces release archives, so the container binaries carry the same
version stamp as a release build. That stamp comes from `git describe`
executed inside the builder, which is why the whole repository —
including `.git` — is part of the build context. Build from a clean
checkout: uncommitted changes surface as a `-dirty` suffix in
`--version`.

`--dev` keeps debug symbols and disables optimisation and inlining, so
the binaries can be attached to with delve. Everything else about the
image is identical.

## Server setup

**1. Write the config**, here `/srv/certdx/server.toml`. See
[quickstart.md](quickstart.md) for a worked example and
[server.md](server.md) for the full option list.

**2. Start the server:**

```sh
docker run -d --name certdx-server --restart unless-stopped \
    -p 10001:10001 \
    -v /srv/certdx/server.toml:/etc/certdx/server.toml:ro \
    -v certdx-server-data:/data \
    paraparty/certdx:<tag> \
    certdx_server --conf /etc/certdx/server.toml
```

Publish whatever `HttpServer.listen` (default `:10001`) and
`gRPCSDSServer.listen` (default `:10002`) are set to. With
`secure = true` the server issues its own certificate for `names`, so
that name must resolve here and the published port must be reachable.
The `certdx-server-data` volume must persist: it holds the ACME account
keys under `private/`, the certificate cache `cache.json`, and the mTLS
bundles under `mtls/`.

**3. Watch the first issuance:**

```sh
docker logs -f certdx-server
docker run --rm -v certdx-server-data:/data \
    paraparty/certdx:<tag> certdx_tools show-certs
```

**4. For mTLS or gRPC SDS**, generate the bundles into the same volume
before starting the server, then set `[MTLS] pem` to
`/data/mtls/certdx-server.pem`:

```sh
docker run --rm -v certdx-server-data:/data \
    paraparty/certdx:<tag> certdx_tools make-ca
docker run --rm -v certdx-server-data:/data \
    paraparty/certdx:<tag> certdx_tools make-server \
    -n certdx-server -d certdx.example.com
```

Consumer bundles come from `certdx_tools make-client`; copy them out of
the volume to each client. See [setup.md](setup.md) for the full mTLS
and SDS walkthrough.

## Running the client

```sh
docker run -d --name certdx-client \
    -v /srv/certdx/client.toml:/etc/certdx/client.toml:ro \
    paraparty/certdx:<tag> \
    certdx_client --conf /etc/certdx/client.toml
```

`--conf` is required and has no default. The client keeps no state of
its own, so it needs no data volume. If it uses `file` update actions,
mount the directory they write to and make sure `65532` can write to it
— the reload command runs inside the container, so a container-local
nginx reload is rarely what you want. Containerised clients usually use
the `kubernetes` or `tencentCloud` update actions instead.

## Running the tools

`certdx_tools` is a one-shot command. Point it at the same volume the
server uses; it picks up `/data` from the image's `CERTDX_DATA_DIR`
without further flags:

```sh
docker run --rm \
    -v certdx-server-data:/data \
    paraparty/certdx:<tag> \
    certdx_tools show-certs
```

The same applies to `make-ca`, `make-server` and `make-client`, which
write their bundles into `/data/mtls/`.

## Kubernetes

Ready-to-adapt manifests live in `config/kubernetes/`. Since the image
has no entrypoint, the pod spec must set `command`:

```yaml
containers:
    - name: client
      image: paraparty/certdx:<tag>
      command:
          - certdx_client
      args:
          - --conf=/etc/certdx/client.toml
```

The shipped Deployment runs with `readOnlyRootFilesystem: true`. That is
fine for the `kubernetes` update action, which keeps no local state; add
a writable volume at `/data` if the workload needs one.
