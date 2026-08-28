#!/usr/bin/env bash

set -euo pipefail

dev=0
for arg in "$@"; do
    case "$arg" in
        --dev) dev=1 ;;
        *) printf 'Unknown argument: %s\nUsage: %s [--dev]\n' "$arg" "$0" >&2; exit 2 ;;
    esac
done

repo_root="$(git rev-parse --show-toplevel)"
git_commit="$(git -C "$repo_root" rev-parse --short=8 HEAD)"
image="paraparty/certdx:${git_commit}"
if [[ $dev -eq 1 ]]; then
    image="${image}-dev"
fi

docker build \
    --build-arg "DEV=${dev}" \
    --tag "$image" \
    "$repo_root"

printf 'Built %s\n' "$image"
