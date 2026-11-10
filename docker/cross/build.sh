#!/bin/bash
# Cross-compiles a release binary for one target inside the rust-cross Docker image,
# then copies it into ./dist. Run from the repo root.
#
# Usage: docker/cross/build.sh <target-triple>
#   x86_64-pc-windows-gnu
#   x86_64-unknown-linux-musl
#   aarch64-unknown-linux-musl
#   armv7-unknown-linux-musleabihf
set -euo pipefail

TARGET="${1:?Usage: $0 <target-triple>}"
BIN=zeroconf-p2p-vpn
IMAGE=rust-cross
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$TARGET" in
x86_64-pc-windows-gnu)
    SUFFIX=.exe
    BUILD_CMD="cargo build --release --target $TARGET"
    ;;
x86_64-unknown-linux-musl | aarch64-unknown-linux-musl | armv7-unknown-linux-musleabihf)
    SUFFIX=
    BUILD_CMD="cargo zigbuild --release --target $TARGET"
    ;;
*)
    echo >&2 "unknown target: $TARGET"
    exit 1
    ;;
esac

docker build -t "$IMAGE" "$SCRIPT_DIR"
mkdir -p dist

# Docker creates named volumes root-owned; hand the target volume to the host user the build runs as.
docker run --rm -v "build-target-$TARGET":/t "$IMAGE" chown "$(id -u):$(id -g)" /t

# Mount sibling path dependencies (`path = "../x"` in Cargo.toml) where cargo resolves them from
# inside the container: /src/../x == /x.
DEP_MOUNTS=()
for rel in $(grep -oP 'path = "\K\.\./[^"]+' Cargo.toml || true); do
    DEP_MOUNTS+=(-v "$(cd "$rel" && pwd):/${rel#../}:ro")
done

# Git info is resolved on the host: the container has no usable .git view (ownership, jj).
# build.rs picks these up as build info; see ZEROCONF_GIT_* there.
GIT_REV="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_DESCRIBE="$(git describe --tags --always --long --dirty=-modified 2>/dev/null || echo unknown)"

# Fat LTO's final link needs more RAM than this host reliably has free; thin LTO
# only applies to these cross builds, not the native release profile in Cargo.toml.
docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$(pwd)":/src \
    -w /src \
    -v cargo-registry:/usr/local/cargo/registry \
    -v cargo-git:/usr/local/cargo/git \
    -v zig-cache:/cache \
    -v "build-target-$TARGET":/src/target \
    -v "$(pwd)/dist":/dist \
    ${DEP_MOUNTS[@]+"${DEP_MOUNTS[@]}"} \
    -e CARGO_PROFILE_RELEASE_LTO=thin \
    -e ZEROCONF_GIT_REV="$GIT_REV" \
    -e ZEROCONF_GIT_DESCRIBE="$GIT_DESCRIBE" \
    "$IMAGE" \
    bash -c "$BUILD_CMD && cp target/$TARGET/release/$BIN$SUFFIX /dist/$BIN-$TARGET$SUFFIX"
