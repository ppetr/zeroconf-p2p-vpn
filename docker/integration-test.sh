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

# Resolves `name` via `getent ahosts` from inside node `$1`, retrying for up to ~30s (a peer's DNS
# entry only appears once its handshake completes, the same timing dependency wait_ping has above)
# until the answer contains `$3`.
wait_dns() {
    local node="$1" name="$2" expected_addr="$3"
    for _ in $(seq 30) ; do
        docker compose exec -T "$node" getent ahosts "$name" 2>/dev/null | grep -qF "$expected_addr" && return 0
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

@test "Peer names resolve via DNS, and other lookups still fall through" {
    # None of these containers run systemd/D-Bus or have `resolvconf` installed, so this
    # exercises dns-host-config's last-resort backend: a direct, static /etc/resolv.conf edit.
    run wait_dns node-alice bob.p2p "$BOB_VPN"
    [ "$status" -eq 0 ]
    run wait_dns node-alice charlie.p2p "$CHARLIE_VPN"
    [ "$status" -eq 0 ]
    run wait_dns node-bob alice.p2p "$ALICE_VPN"
    [ "$status" -eq 0 ]
    run wait_dns node-charlie alice.p2p "$ALICE_VPN"
    [ "$status" -eq 0 ]

    # Our resolver answers REFUSED for anything outside ".p2p", so a name outside that suffix
    # must still fall through to the original nameserver this host had (Docker's embedded DNS,
    # which resolves other containers by their compose service name) -- proving the "our server
    # first, the original nameserver(s) after" ordering the static backend relies on actually
    # works end to end, not just that the file has the right lines.
    run docker compose exec -T node-alice getent ahosts node-bob
    [ "$status" -eq 0 ]
}

@test "DNS only resolves a node's own configured peers" {
    # node-bob only peers with node-alice, so it has no "charlie" entry in its own DNS zone --
    # this must be NXDOMAIN, not an answer, and not just "REFUSED falls through to nothing".
    run docker compose exec -T node-bob getent ahosts charlie.p2p
    [ "$status" -ne 0 ]
}
