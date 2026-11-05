# Cross-compilation image for Windows/Linux (static musl) release builds.
# Build: docker build -t rust-cross docker/cross
# Use via docker/cross/build.sh.
FROM rust:1.98-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    mingw-w64 \
    cmake \
    protobuf-compiler \
    libprotobuf-dev \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*
# cmake is needed to build aws-lc-sys (TLS backend pulled in via iroh/rustls) for the cross targets.

# Zig provides the musl cross-toolchain used by cargo-zigbuild for the Linux targets.
RUN python3 -m venv /opt/zig-venv && /opt/zig-venv/bin/pip install ziglang
ENV PATH="/opt/zig-venv/bin:${PATH}"
RUN cargo install cargo-zigbuild --locked

RUN rustup target add \
    x86_64-pc-windows-gnu \
    x86_64-unknown-linux-musl \
    aarch64-unknown-linux-musl \
    armv7-unknown-linux-musleabihf
