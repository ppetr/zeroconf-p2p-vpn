# Run from the parent directory with `docker -f docker``
#FROM scratch
FROM debian:stable-slim

COPY target/debug/zeroconf-p2p-vpn zeroconf-p2p-vpn

ENTRYPOINT ["/zeroconf-p2p-vpn"]
