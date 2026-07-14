#!/usr/bin/env -S bats --show-output-of-passing-tests

setup_file() {
    (cd .. && CARGO_BUILD_WARNINGS=allow cargo build --quiet >&3)
    docker compose up -d --build >&3
    bats::on_failure() {
        # Only works with Bats 1.11+
        docker compose logs
    }

    echo -n "Waiting for tun0 in both nodes: " >&3
    for node in node-{alice,bob} ; do
        until docker compose exec -T "${node}" ip link show tun0 >/dev/null 2>&1 ; do echo -n "." >&3; sleep 1; done
    done
    echo " up" >&3
}

teardown_file() {
    echo "~~~ Teardown ~~~" >&3
    docker compose down
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
