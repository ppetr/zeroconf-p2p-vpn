# systemd as PID 1, for testing the real systemd unit (see systemd-test.sh).
FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd \
    systemd-sysv \
    dbus \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/sbin/init"]
