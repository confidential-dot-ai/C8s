#!/bin/bash
# Boot real systemd with the worker image's host units and check that nothing
# runs before the measured worker document is staged. The test replaces unit
# payloads only; dependency ordering, Requires= failures and the production
# preset are the image's. Driver mode needs Docker; --inside runs only in its
# disposable container.
set -euo pipefail

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ "${1:-}" != --inside ]]; then
    command -v docker >/dev/null || { echo "docker required" >&2; exit 2; }
    IMG=c8s-worker-systemd-test
    CTR=c8s-worker-systemd-$$
    docker build -q -t "$IMG" - <<'EOF'
FROM debian:12
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    systemd systemd-sysv systemd-timesyncd && apt-get clean && rm -rf /var/lib/apt/lists/*
CMD ["/sbin/init"]
EOF
    trap 'docker rm -f "$CTR" >/dev/null 2>&1 || true' EXIT
    docker run -d --privileged --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock \
        --name "$CTR" "$IMG" >/dev/null
    state=""
    for _ in $(seq 1 30); do
        state=$(docker exec "$CTR" systemctl is-system-running 2>/dev/null || true)
        case "$state" in running|degraded) break ;; esac
        sleep 1
    done
    case "$state" in running|degraded) ;; *) echo "systemd failed to settle: $state" >&2; exit 2 ;; esac
    docker cp "$TESTS_DIR/.." "$CTR":/ngi >/dev/null
    docker exec "$CTR" bash /ngi/tests/worker-systemd-test.sh --inside
    exit 0
fi
[[ $EUID == 0 && $(cat /proc/1/comm) == systemd ]] || { echo "--inside requires disposable root systemd" >&2; exit 2; }
. "$TESTS_DIR/lib.sh"
: "${FAIL?tests/lib.sh must count assertions and summarize must exit on a failure}"

EXTRA=/extra
bash "$TESTS_DIR/stage-worker-extra.sh" "$EXTRA"
UNITS=$EXTRA/etc/systemd/system
PRESET=usr/lib/systemd/system-preset/50-worker.preset

# Staging is one unit; a oneshot is a boot gate that finishes before any pod
# can start; everything else is a host service that must wait for staging.
# worker-invariants.sh holds the image to that split.
mapfile -t BAKED < <(cd "$UNITS" && printf '%s\n' *.service | sort)
STAGED=()
GATES=()
for unit in "${BAKED[@]}"; do
    [[ $unit == worker-stage.service ]] && continue
    if grep -qx 'Type=oneshot' "$UNITS/$unit"; then GATES+=("$unit"); else STAGED+=("$unit"); fi
done

install -D -m644 "$EXTRA/$PRESET" "/$PRESET"
for unit in "${BAKED[@]}"; do
    install -D -m644 "$UNITS/$unit" "/etc/systemd/system/$unit"
done

# The external attester and the stock AppArmor loader are the only units not
# in this repository. Their test payloads wait indefinitely.
for unit in attestation-api apparmor; do
    install -D -m644 /dev/stdin "/etc/systemd/system/$unit.service" <<EOF
[Unit]
Description=test $unit payload
[Service]
ExecStart=/bin/sleep infinity
[Install]
WantedBy=multi-user.target
EOF
done

# Staging reaches a real disk and a real attester, every gate real hardware,
# and every service below them a real payload. Each is replaced by a file
# switch this test owns.
install -D -m644 /dev/stdin /etc/systemd/system/worker-stage.service.d/90-test-payload.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/bin/sh -c 'test ! -e /run/worker-stage-fail'
EOF
for unit in "${STAGED[@]}"; do
    install -D -m644 /dev/stdin "/etc/systemd/system/$unit.d/90-test-payload.conf" <<'EOF'
[Service]
Type=simple
EnvironmentFile=
ExecStartPre=
ExecStart=
ExecStart=/bin/sleep infinity
ExecStartPost=
ExecStop=
EOF
done
# A failing gate must block the runtime, not power off the test host.
for unit in "${GATES[@]}"; do
    install -D -m644 /dev/stdin "/etc/systemd/system/$unit.d/90-test-payload.conf" <<EOF
[Unit]
FailureAction=none
[Service]
ExecStart=
ExecStart=/bin/sh -c 'test ! -e /run/gate-fail-$unit'
ExecStop=
EOF
done
systemctl daemon-reload

CASE=units
for unit in "${BAKED[@]}"; do
    ok "$unit under test is the image's" \
        test "$(systemctl show -p FragmentPath --value "$unit")" = "/etc/systemd/system/$unit"
done

CASE=presets
mapfile -t PRESET_UNITS < <(grep -Ev '^[[:space:]]*(#|$)' "$EXTRA/$PRESET" | awk '{print $2}')
ok "the production preset applies" systemctl preset "${PRESET_UNITS[@]}"
enablement() { systemctl is-enabled "$1" 2>/dev/null || true; }
while read -r verb unit; do
    ok "$unit is ${verb}d" test "$(enablement "$unit")" = "${verb}d"
done < <(grep -Ev '^[[:space:]]*(#|$)' "$EXTRA/$PRESET")

# Check the parsed production poweroff policy, then disable it so the failure
# scenarios do not power off the test host.
CASE=staging-policy
ok "staging powers the worker off on failure" \
    test "$(systemctl show -p FailureAction --value worker-stage.service)" = poweroff-force
install -D -m644 /dev/stdin /etc/systemd/system/worker-stage.service.d/95-test-no-poweroff.conf <<'EOF'
[Unit]
FailureAction=none
EOF
systemctl daemon-reload

# The dependencies under test, as systemd parsed them.
contains() { case " $1 " in *" $2 "*) return 0 ;; *) return 1 ;; esac; }
ordered_after() { contains "$(systemctl show -p After --value "$1")" "$2"; }
required_by_the_runtime() { contains "$(systemctl show -p Requires --value containerd.service)" "$1"; }
active() { systemctl is-active --quiet "$1"; }
not_active() { ! active "$1"; }
boot() { systemctl start "${STAGED[@]}"; }
scenario_reset() {
    systemctl stop "${STAGED[@]}" worker-stage.service "${GATES[@]}" >/dev/null 2>&1 || true
    systemctl reset-failed >/dev/null 2>&1 || true
    rm -f /run/worker-stage-fail /run/gate-fail-*
}

CASE=ordering
for unit in "${STAGED[@]}"; do
    ok "$unit is ordered after staging" ordered_after "$unit" worker-stage.service
done
for unit in "${GATES[@]}"; do
    ok "$unit is ordered before the runtime" ordered_after containerd.service "$unit"
done

CASE=boot
scenario_reset
ok "the worker boots" boot
ok "staging is active" active worker-stage.service
for unit in "${STAGED[@]}"; do ok "$unit active" active "$unit"; done
for unit in "${GATES[@]}"; do
    if required_by_the_runtime "$unit"; then
        ok "$unit active" active "$unit"
    else
        # The disk mounts are only ordered before the runtime; at boot
        # local-fs.target starts them.
        ok "$unit is not pulled in by the runtime" not_active "$unit"
    fi
done

CASE=staging-failure
scenario_reset
: > /run/worker-stage-fail
ok "startup fails visibly" not boot
ok "staging failed" systemctl is-failed --quiet worker-stage.service
for unit in "${STAGED[@]}"; do ok "$unit stayed down" not_active "$unit"; done

CASE=gate-failure
scenario_reset
: > /run/gate-fail-scratch-enforce.service
ok "startup fails visibly" not boot
ok "the gate failed" systemctl is-failed --quiet scratch-enforce.service
ok "the runtime stayed down" not_active containerd.service
ok "the kubelet stayed down" not_active kubelet.service

scenario_reset
summarize "worker host units behind authenticated staging"
