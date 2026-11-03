#!/bin/bash
# Cross-compiles release binaries for all supported targets into ./dist.
# Run from the repo root: docker/cross/release-all.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGETS=(
    x86_64-pc-windows-gnu
    aarch64-unknown-linux-gnu
    armv7-unknown-linux-gnueabihf
)

for target in "${TARGETS[@]}"; do
    echo "== $target =="
    "$SCRIPT_DIR/build.sh" "$target"
done

echo
echo "Done. To clean up leftover containers (e.g. after a build got killed):"
echo "  docker ps -a --filter ancestor=rust-cross"
echo "  docker rm -f <container-id>"
echo "To free disk space, remove the image (build caches stay in their own volumes):"
echo "  docker image rm rust-cross"
