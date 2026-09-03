#!/usr/bin/env -S bats --show-output-of-passing-tests

setup_file() {
    (cd .. && CARGO_BUILD_WARNINGS=allow cargo build --quiet >&3)
    docker compose up -d --build >&3
    bats::on_failure() {
        # Only works with Bats 1.11+
        docker compose logs
    }

    echo -n "Waiting for tun0 in all nodes: " >&3
    for node in node-{alice,bob,charlie} ; do
        until docker compose exec -T "${node}" ip link show tun0 >/dev/null 2>&1 ; do echo -n "." >&3; sleep 1; done
    done
    echo " up" >&3

    # Ask each node for its own derived VPN address instead of hard-coding it: `show` is a pure
    # function of the node's config + key, the same derivation the daemon uses for its Advertise.
    export ALICE_VPN BOB_VPN CHARLIE_VPN
    ALICE_VPN="$(vpn_addr node-alice)"
    BOB_VPN="$(vpn_addr node-bob)"
    CHARLIE_VPN="$(vpn_addr node-charlie)"
    echo "VPN addresses: alice=${ALICE_VPN} bob=${BOB_VPN} charlie=${CHARLIE_VPN}" >&3
}

teardown_file() {
    echo "~~~ Teardown ~~~" >&3
    docker compose down
}

# Prints a node's VPN IPv6 address, as reported by `zeroconf-p2p-vpn show` on its own config.
vpn_addr() {
    docker compose exec -T "$1" /zeroconf-p2p-vpn show config.toml | awk '/^VPN address:/ { print $3 }'
}

# A single ICMPv6 echo from a node to an address; returns ping's exit status.
ping_once() {
    docker compose exec -T "$1" ping -6 -c1 -W2 "$2"
}

# Retries ping_once for up to ~30s, for links that need the QUIC handshake to complete first.
wait_ping() {
    for _ in $(seq 30) ; do
        ping_once "$1" "$2" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

send_data() {
    set -e
    local wc_file="$1"
    echo "[1a] Listening in node-alice on port 1234" >&3
    docker compose exec -T node-alice bash -c 'timeout -v 30 ncat --recv-only -6 -l 1234 </dev/null | wc --bytes' >"$wc_file" 2>&3 &
    sleep 1

    echo "[2] Sending data from node-bob" >&3
    docker compose exec -T node-bob bash -c "timeout -v 30 pv --numeric --stop-at-size --size 100M --stats -petab /dev/urandom | ncat --send-only -6 fdbd:a6ce:654d:0:6f56:d923:de1e:5588 1234" >&3 2>&3
    echo "[1b] Waiting for the listener to finish" >&3
    wait %1
}

@test "Send a stream of big data" {
    local wc_file="$BATS_TEST_TMPDIR/wc_out"
    run send_data "$wc_file"
    [ "$status" -eq 0 ]

    echo -n "[3] Checking the output of 'wc': " >&3
    cat "$wc_file" >&3
    [ "$(<"$wc_file")" = "104857600" ]
}

@test "Alice and Bob ping each other" {
    run wait_ping node-alice "$BOB_VPN"
    [ "$status" -eq 0 ]
    run wait_ping node-bob "$ALICE_VPN"
    [ "$status" -eq 0 ]
}

@test "Alice and Charlie ping each other" {
    run wait_ping node-alice "$CHARLIE_VPN"
    [ "$status" -eq 0 ]
    run wait_ping node-charlie "$ALICE_VPN"
    [ "$status" -eq 0 ]
}

@test "Bob and Charlie cannot reach each other" {
    # Bob and Charlie are not each other's peer, so neither has a route to the other's VPN
    # address and the ping must fail.
    run ping_once node-bob "$CHARLIE_VPN"
    [ "$status" -ne 0 ]
    run ping_once node-charlie "$BOB_VPN"
    [ "$status" -ne 0 ]
}
