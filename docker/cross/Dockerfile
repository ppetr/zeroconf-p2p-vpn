# Cross-compilation image for Windows/arm64/armv7 release builds.
# Build: docker build -t rust-cross docker/cross
# Use via docker/cross/build.sh.
FROM rust:1.98-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    mingw-w64 \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    gcc-arm-linux-gnueabihf \
    g++-arm-linux-gnueabihf \
    libc6-dev-armhf-cross \
    cmake \
    protobuf-compiler \
    libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*
# cmake is needed to build aws-lc-sys (TLS backend pulled in via iroh/rustls) for the cross targets.

RUN rustup target add \
    x86_64-pc-windows-gnu \
    aarch64-unknown-linux-gnu \
    armv7-unknown-linux-gnueabihf
