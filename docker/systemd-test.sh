#!/usr/bin/env -S bats --show-output-of-passing-tests

# Runs the real systemd unit (../systemd/zeroconf-p2p-vpn.service) in a container with systemd as
# PID 1, next to node-bob, and checks the Type=notify start, native journal logging, a prompt stop
# and a visible start failure.

UNIT=zeroconf-p2p-vpn.service

setup_file() {
    (cd .. && CARGO_BUILD_WARNINGS=allow cargo build --quiet >&3)
    docker compose --profile systemd up -d --build node-bob node-systemd >&3
    bats::on_failure() {
        # Only works with Bats 1.11+
        sd journalctl -u "$UNIT" --no-pager
    }

    echo -n "Waiting for systemd to finish booting: " >&3
    sd systemctl is-system-running --wait >&3 || true
}

teardown_file() {
    echo "~~~ Teardown ~~~" >&3
    docker compose --profile systemd down
}

# Runs a command inside the systemd container.
sd() {
    docker compose exec -T node-systemd "$@"
}

# Retries a command for up to ~30s.
retry() {
    for _ in $(seq 30) ; do
        "$@" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

peer_logged() {
    sd journalctl -u "$UNIT" --no-pager -q "F_PEER=bob" | grep -q "$1"
}

@test "systemctl start returns once the daemon is ready (Type=notify)" {
    run sd systemctl start "$UNIT"
    [ "$status" -eq 0 ]
    run sd systemctl show -p ActiveState --value "$UNIT"
    [ "$output" = "active" ]
    # READY=1 is sent after the TUN device is set up.
    run sd ip link show tun0
    [ "$status" -eq 0 ]
}

@test "The daemon writes native journal records with filterable fields" {
    run sd journalctl -u "$UNIT" -o verbose --no-pager -n 20
    [ "$status" -eq 0 ]
    [[ "$output" == *"_TRANSPORT=journal"* ]]
    [[ "$output" == *"PRIORITY="* ]]
    # A peer's connection logs carry the peer as a field, which can be filtered on.
    run retry peer_logged "Handshake successfully completed"
    [ "$status" -eq 0 ]
}

@test "systemctl stop is prompt and logs the shutdown" {
    local start=$SECONDS
    run sd systemctl stop "$UNIT"
    [ "$status" -eq 0 ]
    [ $((SECONDS - start)) -lt 15 ]
    run sd systemctl show -p ActiveState --value "$UNIT"
    [ "$output" = "inactive" ]
    run sd journalctl -u "$UNIT" --no-pager -q
    [[ "$output" == *"Shutdown requested"* ]]
    run sd journalctl -u "$UNIT" --no-pager -q "F_PEER=bob"
    [[ "$output" == *"Connection ended"* ]]
}

@test "A failing start fails systemctl start and names the cause in the journal" {
    sd mkdir -p "/etc/systemd/system/$UNIT.d"
    printf '[Service]\nExecStart=\nExecStart=/usr/local/sbin/zeroconf-p2p-vpn /nonexistent.toml\n' |
        docker compose exec -T node-systemd tee "/etc/systemd/system/$UNIT.d/bad.conf" >/dev/null
    sd systemctl daemon-reload

    run sd systemctl start "$UNIT"
    [ "$status" -ne 0 ]
    # Restart=on-failure keeps retrying, so the unit is not left in "active".
    run sd systemctl is-active "$UNIT"
    [ "$output" != "active" ]
    run sd journalctl -u "$UNIT" --no-pager -q -n 20
    [[ "$output" == *"nonexistent.toml"* ]]

    sd systemctl stop "$UNIT"
    sd rm -f "/etc/systemd/system/$UNIT.d/bad.conf"
    sd systemctl daemon-reload
    sd systemctl reset-failed "$UNIT" || true
}
