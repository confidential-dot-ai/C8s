#!/bin/bash
# Unit test for gpu-node-label.sh: the GPU-presence detection and, crucially,
# that it writes the label as a kubelet-arg (re-asserted every kubelet start)
# rather than an rke2 node-label (applied only at first registration, so it
# would silently vanish on any agent re-join). Root-free: fakes the PCI sysfs
# tree and the rke2 config dir under a temp root.
set -u

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$TESTS_DIR/lib.sh"
SCRIPT=${GPU_LABEL_SCRIPT:-"$TESTS_DIR/../c8s/mkosi.extra/usr/local/bin/gpu-node-label.sh"}
[[ -x "$SCRIPT" ]] || { echo "script not found: $SCRIPT"; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FRAGMENT="$WORK/etc/rancher/rke2/config.yaml.d/20-gpu-node-label.yaml"

# Run the production script verbatim with its two absolute paths rebased into
# $WORK — no edits to logic, only the roots it reads/writes.
run_label() {
    sed -e "s|/etc/rancher/rke2|$WORK/etc/rancher/rke2|g" \
        -e "s|/sys/bus/pci/devices|$WORK/sys/bus/pci/devices|g" \
        "$SCRIPT" | bash
}
set_vendor() { # set_vendor HEXID
    rm -rf "$WORK/sys/bus/pci/devices"
    mkdir -p "$WORK/sys/bus/pci/devices/0000:0b:00.0"
    printf '%s' "$1" > "$WORK/sys/bus/pci/devices/0000:0b:00.0/vendor"
}

CASE="nvidia present"
set_vendor 0x10de
run_label
ok "emits a fragment" test -f "$FRAGMENT"
ok "labels via kubelet-arg, not rke2 node-label" grep -q '^kubelet-arg+:' "$FRAGMENT"
ok "does NOT use node-label (the register-only key #486 replaced)" not grep -q 'node-label+:' "$FRAGMENT"
ok "sets the gpu label value" grep -q 'node-labels=confidential.ai/gpu=true' "$FRAGMENT"

CASE="non-nvidia device"
set_vendor 0x8086
run_label
ok "writes no fragment for a non-GPU device" not test -f "$FRAGMENT"

CASE="relaunch without gpu clears a stale label"
set_vendor 0x10de; run_label
ok "fragment present after a GPU boot" test -f "$FRAGMENT"
set_vendor 0x8086; run_label
ok "stale fragment removed when the GPU is gone" not test -f "$FRAGMENT"

summarize "gpu-node-label"
