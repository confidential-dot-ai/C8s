#!/bin/bash
# Run the byte-exact production script in a disposable Linux container. Device
# I/O and C8s are stubs; Go tests cover the actual cryptography and staging.
# No host /run or /etc directories are mutated, and no privileged mount is used.
set -euo pipefail

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ "${1:-}" != --inside ]]; then
    command -v docker >/dev/null || { echo "docker required" >&2; exit 2; }
    exec docker run --rm --network=none \
        -v "$TESTS_DIR/..:/ngi:ro" debian:12 \
        bash /ngi/tests/rke2-role-test.sh --inside
fi
[[ $EUID == 0 && $(uname -s) == Linux ]] || { echo "--inside requires disposable root Linux" >&2; exit 2; }
. "$TESTS_DIR/lib.sh"
. "$TESTS_DIR/launch-fixtures.sh"
SCRIPT=$TESTS_DIR/../c8s/mkosi.extra/usr/local/bin/rke2-role.sh
BIN=/tmp/c8s-role-test-bin
OUT=/tmp/c8s-role-test-output
install_launch_stubs "$BIN"
export PATH="$BIN:/usr/sbin:/usr/bin:/sbin:/bin"
export CRED_PLATFORM=tdx

run_script() {
    RC=0
    bash "$SCRIPT" > "$OUT" 2>&1 || RC=$?
}

for platform in tdx snp; do
    for role in server agent; do
        CASE="$platform/$role"
        reset_launch_fixture
        launch_media "$role"
        CRED_PLATFORM=$platform run_script
        ok "verified boot succeeds" test "$RC" -eq 0
        marker=server; other=agent
        if [[ $role == agent ]]; then marker=agent; other=server; fi
        ok "selected role marker remains" test -f "/run/confos/role-$marker"
        ok "other role stays absent" test ! -e "/run/confos/role-$other"
        ok "prepare runs only after stage" test -f "$C8S_ROLE_FIXTURE/prepared"
        ok "mount type/options/device are exact" test -s "$C8S_ROLE_FIXTURE/mount-args"
        ok "host disk mount is bounded" test -f "$C8S_ROLE_FIXTURE/mount-bounded"
        ok "media is unmounted" test -f "$C8S_ROLE_FIXTURE/unmounted"
        ok "baked platform reaches verifier" grep -qx -- "--platform=$platform" "$C8S_ROLE_FIXTURE/stage-args"
    done
done

for scenario in missing-disk missing-config missing-signature invalid-signature invalid-config udev-failure mount-failure mount-timeout prepare-failure; do
    CASE=$scenario
    reset_launch_fixture
    launch_media server
    case "$scenario" in
        missing-disk) rm "$C8S_ROLE_FIXTURE/disk-present" ;;
        missing-config) rm "$C8S_ROLE_FIXTURE/media/launch.yaml" ;;
        missing-signature) rm "$C8S_ROLE_FIXTURE/media/launch.yaml.sig" ;;
        invalid-signature) printf '%s\n' invalid > "$C8S_ROLE_FIXTURE/media/launch.yaml.sig" ;;
        invalid-config) printf '%s\n' invalid > "$C8S_ROLE_FIXTURE/media/launch.yaml" ;;
        udev-failure) : > "$C8S_ROLE_FIXTURE/udev-fails" ;;
        mount-failure) : > "$C8S_ROLE_FIXTURE/mount-fails" ;;
        mount-timeout) : > "$C8S_ROLE_FIXTURE/mount-times-out" ;;
        prepare-failure) : > "$C8S_ROLE_FIXTURE/prepare-fails" ;;
    esac
    # Failure cleanup must invalidate a stale prior verdict, including when
    # failure occurs before C8s can authenticate or clear its own outputs.
    : > /run/confos/role-server
    : > /run/confos/role-agent
    run_script
    ok "failure propagates" test "$RC" -ne 0
    ok "neither role remains authorized" no_launch_markers
    ok "preparation did not complete" test ! -e "$C8S_ROLE_FIXTURE/prepared"
done

CASE=invalid-baked-platform
reset_launch_fixture
launch_media server
CRED_PLATFORM=invalid run_script
ok "invalid build platform fails" test "$RC" -ne 0
ok "invalid platform cannot reach c8s" test ! -e "$C8S_ROLE_FIXTURE/stage-args"
ok "invalid platform cannot select a role" no_launch_markers

CASE=host-input-never-evaluated
reset_launch_fixture
launch_media '$(touch /tmp/c8s-role-input-executed)'
run_script
ok "unrecognized input is rejected by verifier boundary" test "$RC" -ne 0
ok "script never evaluates launch contents" test ! -e /tmp/c8s-role-input-executed
ok "input failure clears role" no_launch_markers

summarize "authenticated launch script"
