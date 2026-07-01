# Run from the parent directory with `docker -f docker``
#FROM scratch
FROM debian:stable-slim AS base
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    net-tools \
    netcat-openbsd \
    python3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

FROM base AS runnner

ENTRYPOINT ["/zeroconf-p2p-vpn"]
