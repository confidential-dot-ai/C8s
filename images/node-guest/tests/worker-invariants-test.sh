#!/usr/bin/env bash
# Exercise the worker invariants gate against a copied tree: each case breaks
# one input and requires the gate to refuse it by rule. The pinned confos
# checkout stays read-only.
set -euo pipefail

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$TESTS_DIR/../../.." && pwd)
CONFOS_DIR=${CONFOS_DIR:-$REPO_DIR/confos}
[ -f "$CONFOS_DIR/kernel/gpu.config" ] \
    || { echo "CONFOS_DIR must name the pinned confos checkout" >&2; exit 2; }
CONFOS_DIR=$(cd "$CONFOS_DIR" && pwd -P)
. "$TESTS_DIR/lib.sh"
: "${FAIL?tests/lib.sh must count assertions and summarize must exit on a failure}"

WORK=$(mktemp -d)
PRISTINE=$WORK/pristine
FIXTURE=$WORK/fixture
OUTPUT=$WORK/output
trap 'rm -rf -- "$WORK"' EXIT
# The gate's whole input surface: the kernel configurations, the worker
# profile and the gate itself.
mkdir -p "$PRISTINE/images/node-guest"
cp -a "$REPO_DIR/images/node-guest/kernel" "$REPO_DIR/images/node-guest/worker" \
      "$REPO_DIR/images/node-guest/tests" "$PRISTINE/images/node-guest/"
ln -s "$CONFOS_DIR" "$PRISTINE/confos"
WORKER=$FIXTURE/images/node-guest/worker
KERNEL=$FIXTURE/images/node-guest/kernel
UNITS=$WORKER/mkosi.extra/etc/systemd/system

restore() {
    rm -rf "$FIXTURE"
    mkdir -p "$FIXTURE"
    cp -a "$PRISTINE/." "$FIXTURE/"
}
restore

# baked REL — the fixture file the worker image bakes at REL.
baked() {
    [ -e "$WORKER/mkosi.extra/$1" ] || { echo "the worker image bakes no $1" >&2; exit 2; }
    echo "$WORKER/mkosi.extra/$1"
}

run_gate() {
    (cd "$FIXTURE" && CONFOS_DIR=$FIXTURE/confos bash images/node-guest/tests/worker-invariants.sh) \
        >"$OUTPUT" 2>&1
}
accepts() {
    CASE=$1
    local rc=0 before=$FAIL
    run_gate || rc=$?
    ok "$CASE is accepted" test "$rc" -eq 0
    (( FAIL == before )) || cat "$OUTPUT"
}
# refuses DESC RULE CMD... — CMD breaks one input of the fixture; the gate must
# refuse it, naming RULE. The fixture is restored before the assertions.
refuses() {
    CASE=$1
    local rule=$2 rc=0 before=$FAIL
    shift 2
    "$@"
    run_gate || rc=$?
    restore
    ok "$CASE is refused" test "$rc" -ne 0
    ok "the refusal names the $rule rule" grep -Fq "[$rule]" "$OUTPUT"
    (( FAIL == before )) || cat "$OUTPUT"
}

accepts "the production worker profile"

gpu_setting=$(grep -m1 -E '^CONFIG_|^# CONFIG_.* is not set$' "$CONFOS_DIR/kernel/gpu.config")
refuses "a fragment dropping a gpu.config setting" gpu-fragment \
    sed -i "\\|^$gpu_setting\$|d" "$KERNEL/c8s.config"

for config in c8s.config config-x86_64-c8s.snapshot; do
    refuses "$config enabling PCI hotplug" pci-hotplug \
        sed -i 's/^# CONFIG_HOTPLUG_PCI is not set$/CONFIG_HOTPLUG_PCI=y/' "$KERNEL/$config"
    # shellcheck disable=SC2016 # sed's last-line address, not a shell expansion.
    refuses "$config enabling a PCI hotplug driver" pci-hotplug \
        sed -i '$aCONFIG_HOTPLUG_PCI_PCIE=y' "$KERNEL/$config"
done

refuses "a latch leaving modules loadable" modules-latch \
    sed -i 's/modules_disabled=1/modules_disabled=0/' "$(baked etc/systemd/system/c8s-modules-latch.service)"
refuses "a preset leaving the latch disabled" modules-latch \
    sed -i '/^enable c8s-modules-latch.service$/d' "$(baked usr/lib/systemd/system-preset/50-worker.preset)"

KEY=kernel.apparmor_restrict_unprivileged_unconfined
refuses "a drop-in leaving the unconfined restriction on" apparmor-sysctl \
    sed -i 's/= 0$/= 1/' "$(baked etc/sysctl.d/20-apparmor.conf)"
refuses "a boot gate that stops asserting the key" apparmor-sysctl \
    sed -i "s|/proc/sys/${KEY//.//}|/proc/sys/kernel/other|" "$(baked usr/local/bin/apparmor-enforce.sh)"
refuses "a later sysctl.d file setting the key again" apparmor-sysctl-order \
    sed -i "\$a$KEY = 1" "$(baked etc/sysctl.d/90-rke2.conf)"

refuses "a second runtime in the image" baked-program \
    install -D -m 0755 /dev/null "$WORKER/mkosi.extra/usr/local/bin/crun"
refuses "a baked containerd shim" baked-program \
    install -D -m 0644 /dev/null "$WORKER/mkosi.extra/usr/lib/c8s/worker/containerd-shim-spin-v2"

# shellcheck disable=SC2016 # sed's last-line address, not a shell expansion.
refuses "a baked program shellcheck refuses" baked-program-lint \
    sed -i '$aecho "unterminated' "$(baked usr/local/bin/worker-stage.sh)"
refuses "a host unit unordered after staging" staging-dependency \
    sed -i '/^After=.*worker-stage.service/d' "$(baked etc/systemd/system/kubelet.service)"
refuses "staging that survives its own failure" staging-poweroff \
    sed -i '/^FailureAction=poweroff-force$/d' "$(baked etc/systemd/system/worker-stage.service)"
refuses "a runtime that stops waiting for a boot gate" boot-gate \
    sed -i 's/ scratch-enforce.service//g' "$(baked etc/systemd/system/containerd.service)"
refuses "a boot gate that is not a oneshot" boot-gate \
    sed -i 's/^Type=oneshot$/Type=simple/' "$(baked etc/systemd/system/scratch-enforce.service)"
refuses "a unit kind the staging rule does not cover" unit-kind \
    install -D -m 0644 /dev/null "$UNITS/models.mount"
refuses "an image without its attestation proxy" baked-units \
    rm "$(baked etc/systemd/system/attest-proxy.service)"

accepts "the restored profile"
summarize "worker image invariants"
