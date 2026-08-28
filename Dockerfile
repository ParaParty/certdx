FROM golang:1.26.2-trixie AS builder

# git: build.py derives the version from `git describe`.
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum ./
COPY exec/client/go.mod exec/client/go.sum ./exec/client/
COPY exec/server/go.mod exec/server/go.sum ./exec/server/
COPY exec/tools/go.mod exec/tools/go.sum ./exec/tools/

RUN for m in client server tools; do \
        (cd "exec/$m" && GOWORK=off go mod download) || exit 1; \
    done

COPY . .

ARG DEV=0

RUN python3 release/build.py docker --output /out $([ "$DEV" = 1 ] && echo --dev)

FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/certdx_server /out/certdx_client /out/certdx_tools /app/

# Symlinks keep the binaries on any PATH (login shells reset it from
# /etc/profile), while os.Executable resolves back to /app so they stay out of
# FHS install mode. The data dir is pinned rather than derived from that path.
RUN install -d -o 65532 -g 65532 -m 0755 /data && \
    for b in certdx_server certdx_client certdx_tools; do \
        ln -s "/app/$b" "/usr/local/bin/$b"; \
    done

ENV CERTDX_DATA_DIR="/data"

USER 65532:65532
