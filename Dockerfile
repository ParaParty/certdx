FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY .container-build/certdx_server .container-build/certdx_client .container-build/certdx_tools /app/

# Symlinks keep the binaries on any PATH (login shells reset it from
# /etc/profile), while os.Executable resolves back to /app so they stay out of
# FHS install mode. The data dir is pinned rather than derived from that path.
RUN install -d -o 65532 -g 65532 -m 0755 /data && \
    for b in certdx_server certdx_client certdx_tools; do \
        ln -s "/app/$b" "/usr/local/bin/$b"; \
    done

ENV CERTDX_DATA_DIR="/data"

USER 65532:65532
