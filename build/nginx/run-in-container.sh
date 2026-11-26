#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build nginx with build.sh and run smoke-test.sh inside a clean container.
# This is the test bed for the supported OS images (requirement I-2).
#
# Usage: run-in-container.sh IMAGE [build.sh options...]
#   IMAGE: almalinux:8, almalinux:9, almalinux:10, ubuntu:22.04 or ubuntu:24.04
#
# Environment:
#   PLATFORM  container platform (default: linux/amd64, the target arch)
#   ENGINE    container engine (default: docker; podman also works)
#   PRODUCT   product name passed to build.sh and smoke-test.sh
#
# CloudLinux images are not freely available: CloudLinux must be checked on
# a real server.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="${PLATFORM:-linux/amd64}"
ENGINE="${ENGINE:-docker}"

[ $# -ge 1 ] || { sed -n '4,16p' "$0" >&2; exit 2; }
IMAGE="$1"
shift

case "$IMAGE" in
almalinux:8 | almalinux:9 | almalinux:10 | ubuntu:22.04 | ubuntu:24.04) ;;
*) echo "error: unsupported image: $IMAGE" >&2; exit 2 ;;
esac

echo "==> $IMAGE ($PLATFORM)"
"$ENGINE" pull -q --platform "$PLATFORM" "$IMAGE" >/dev/null
"$ENGINE" image inspect --format '==> image digest: {{index .RepoDigests 0}}' "$IMAGE" || true

started="$(date +%s)"
# A snapshot of the scripts is mounted read-only: bash reads a script while
# it runs, so editing the originals must not affect a running build. The
# build runs in the container's /var/tmp and installs into the container's
# filesystem only.
snapshot="$(mktemp -d)"
trap 'rm -rf "$snapshot"' EXIT
cp -R "$SCRIPT_DIR/." "$snapshot/"
chmod -R a+rX "$snapshot"
env_args=()
if [ -n "${PRODUCT:-}" ]; then
	env_args=(-e "PRODUCT=$PRODUCT")
fi
"$ENGINE" run --rm --platform "$PLATFORM" ${env_args[@]+"${env_args[@]}"} \
	-v "$snapshot:/src:ro" \
	"$IMAGE" \
	bash -c '/src/build.sh "$@" && /src/smoke-test.sh' run-in-container "$@"
echo "==> $IMAGE: total $(($(date +%s) - started)) s"
