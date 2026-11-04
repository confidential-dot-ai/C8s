#!/bin/bash
# Run each image's production finalize hook against both attester
# configurations from the pinned confos tree. No image build or TEE is
# needed; GNU sed runs in Linux.
set -euo pipefail

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ "${1:-}" != --inside ]]; then
    # The node and CDS images each narrow a composed attester.
    FINALIZE_SCRIPTS=(/ngi/c8s/mkosi.finalize /cgi/cds/mkosi.finalize)
    CONFOS_DIR=${CONFOS_DIR:-"$TESTS_DIR/../../../confos"}
    [[ -d "$CONFOS_DIR" ]] || { echo "CONFOS_DIR must name the pinned confos checkout" >&2; exit 2; }
    CONFOS_DIR=$(cd "$CONFOS_DIR" && pwd)
    for script in "${FINALIZE_SCRIPTS[@]}"; do
        docker run --rm --network=none \
            -v "$TESTS_DIR/..:/ngi:ro" \
            -v "$TESTS_DIR/../../cds-guest:/cgi:ro" \
            -v "$CONFOS_DIR:/confos:ro" \
            -e "FINALIZE_SCRIPT=$script" \
            debian:12 bash /ngi/tests/attester-finalize-test.sh --inside
    done
    exit 0
fi
[[ $(uname -s) == Linux ]] || { echo "--inside requires Linux" >&2; exit 2; }
. "$TESTS_DIR/lib.sh"
SCRIPT=${FINALIZE_SCRIPT:?FINALIZE_SCRIPT must name the finalize hook under test}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export BUILDROOT=$WORK/root
mkdir -p "$BUILDROOT/etc/attestation-api"
CONFIG=$BUILDROOT/etc/attestation-api/config.toml

run_finalize() {
    RC=0
    bash "$SCRIPT" > "$WORK/stdout" 2> "$WORK/stderr" || RC=$?
}

for profile in attest attest-gpu; do
    CASE=$profile
    source_config=/confos/mkosi/base/mkosi.profiles/$profile/mkosi.extra/etc/attestation-api/config.toml
    cp "$source_config" "$CONFIG"
    run_finalize
    ok "finalization succeeds" test "$RC" -eq 0
    ok "exactly one bind setting remains" test "$(grep -c '^bind = ' "$CONFIG")" -eq 1
    ok "bind is loopback only" grep -qx 'bind = "127.0.0.1:8400"' "$CONFIG"
    # A bind-only edit must preserve every byte of the remaining selected
    # profile, including GPU quote and collateral-cache settings.
    sed '/^bind = /d' "$source_config" > "$WORK/source-rest"
    sed '/^bind = /d' "$CONFIG" > "$WORK/final-rest"
    ok "all other configuration is preserved" cmp -s "$WORK/source-rest" "$WORK/final-rest"
done

source_config=/confos/mkosi/base/mkosi.profiles/attest/mkosi.extra/etc/attestation-api/config.toml
for CASE in missing-bind changed-port already-loopback; do
    case "$CASE" in
        missing-bind) sed '/^bind = /d' "$source_config" > "$CONFIG" ;;
        changed-port) sed 's/0.0.0.0:8400/0.0.0.0:8401/' "$source_config" > "$CONFIG" ;;
        already-loopback) sed 's/0.0.0.0:8400/127.0.0.1:8400/' "$source_config" > "$CONFIG" ;;
    esac
    cp "$CONFIG" "$WORK/before"
    run_finalize
    ok "unexpected source configuration fails the build" test "$RC" -ne 0
    ok "rejected input is unchanged" cmp -s "$WORK/before" "$CONFIG"
done

CASE=missing-config
rm "$CONFIG"
run_finalize
ok "missing source configuration fails the build" test "$RC" -ne 0
ok "missing source configuration is not synthesized" test ! -e "$CONFIG"

summarize "attester finalize ($SCRIPT)"
