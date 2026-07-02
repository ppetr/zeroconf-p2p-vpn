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
    docker compose down
}

@test "Send a stream of big data" {
    echo "[1] Listening in node-alice on port 1234" >&3
    local wc_file="$BATS_TEST_TMPDIR/wc_out"
    docker compose exec -T node-alice bash -c 'nc -6 -l 1234 | wc --bytes' >"$wc_file" &
    sleep 1

    echo "[2] Sending data from node-bob" >&3
    run docker compose exec -T node-bob bash -c "pv --numeric --stop-at-size --size 100M --stats -petab /dev/urandom | nc -6 -N fdbd:a6ce:654d:0:6f56:d923:de1e:5588 1234"
    [ "$status" -eq 0 ]
    echo "$output" >&3
    run wait
    [ "$status" -eq 0 ]
    run cat "$wc_file"
    [ "$output" = "104857600" ]
}
