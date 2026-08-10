FROM golang:1.26.2-trixie AS builder

WORKDIR /src

COPY go.mod go.sum ./
COPY exec/tools/go.mod exec/tools/go.sum ./exec/tools/

RUN cd exec/tools && GOWORK=off go mod download

COPY pkg ./pkg
COPY exec/tools ./exec/tools

ARG VERSION=dev
ARG BUILD_DATE=unknown

RUN cd exec/tools && \
    CGO_ENABLED=0 GOWORK=off go build \
        -trimpath \
        -ldflags="-s -w -X main.buildTag=${VERSION} -X main.buildDate=${BUILD_DATE}" \
        -o /out/certdx_tools .

FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/certdx_tools ./certdx_tools

USER 65532:65532

ENTRYPOINT ["/app/certdx_tools"]
