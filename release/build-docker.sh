#!/usr/bin/env bash

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
git_commit="$(git -C "$repo_root" rev-parse --short=8 HEAD)"
build_date="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
image="paraparty/certdx-client:${git_commit}"

docker build \
    --build-arg "VERSION=${git_commit}" \
    --build-arg "BUILD_DATE=${build_date}" \
    --tag "$image" \
    "$repo_root"

printf 'Built %s\n' "$image"
