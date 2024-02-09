# Build the manager binary
FROM golang:1.22 AS builder
ARG TARGETOS
ARG TARGETARCH
ENV GOPROXY https://goproxy.cn,direct

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
COPY go.work go.work
COPY go.work.sum go.work.sum
COPY exec/clusterissuer/go.mod exec/clusterissuer/go.mod
COPY exec/clusterissuer/go.sum exec/clusterissuer/go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download
WORKDIR /workspace/exec/clusterissuer
RUN go mod download

WORKDIR /workspace
# Copy the go source
COPY pkg/ pkg/
COPY exec/clusterissuer/cmd/main.go exec/clusterissuer/cmd/main.go
COPY exec/clusterissuer/api/ exec/clusterissuer/api/
COPY exec/clusterissuer/internal/controller/ exec/clusterissuer/internal/controller/


# Build
# the GOARCH has not a default value to allow the binary be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
WORKDIR /workspace/exec/clusterissuer
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager cmd/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM alpine:3.19.1
WORKDIR /
COPY --from=builder /workspace/exec/clusterissuer/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
