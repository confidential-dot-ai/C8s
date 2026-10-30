#!/bin/bash
# Unit test for scratch-enforce.sh: passes only when a dm device named
# "scratch" exists, i.e. the initrd really backed the state overlays with the
# confai-scratch disk. Root-free: fakes the dm sysfs tree under a temp root.
set -u

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$TESTS_DIR/lib.sh"
SCRIPT=${SCRATCH_SCRIPT:-"$TESTS_DIR/../c8s/mkosi.extra/usr/local/bin/scratch-enforce.sh"}
[[ -x "$SCRIPT" ]] || { echo "script not found: $SCRIPT"; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

run_enforce() {
    SYS_BLOCK_ROOT="$WORK/sys/block" \
        PROVENANCE_FILE="$WORK/run/c8s/scratch-provenance.json" \
        BOOT_ID_FILE="$WORK/boot-id" \
        "$SCRIPT" 2>"$WORK/stderr"
}
set_dm() { # set_dm NAME... — one 80Gi dm-N per name; none = tmpfs fallback boot
    rm -rf "$WORK/sys/block"
    mkdir -p "$WORK/sys/block"
    local i=0 name
    for name in "$@"; do
        mkdir -p "$WORK/sys/block/dm-$i/dm"
        printf '%s' "$name" > "$WORK/sys/block/dm-$i/dm/name"
        printf '167772160' > "$WORK/sys/block/dm-$i/size"
        printf '253:%s' "$i" > "$WORK/sys/block/dm-$i/dev"
        printf 'CRYPT-PLAIN-%s' "$name" > "$WORK/sys/block/dm-$i/dm/uuid"
        if [[ "$name" == scratch ]]; then
            # virtio-blk exposes the serial on the block device.
            mkdir -p "$WORK/sys/block/vdb/device" "$WORK/sys/block/dm-$i/slaves"
            printf 'confai-scratch' > "$WORK/sys/block/vdb/serial"
            ln -s "$WORK/sys/block/vdb" "$WORK/sys/block/dm-$i/slaves/vdb"
        fi
        i=$((i + 1))
    done
    printf 'boot-test-id' > "$WORK/boot-id"
    rm -rf "$WORK/run"
}

CASE="scratch upper"
set_dm scratch
ok "passes" run_enforce
ok "writes boot provenance" grep -q '"boot_id":"boot-test-id"' "$WORK/run/c8s/scratch-provenance.json"

CASE="scratch among other dm devices"
set_dm containerd scratch
ok "passes" run_enforce

CASE="tmpfs fallback (no dm devices)"
set_dm
ok "fails" not run_enforce
ok "names the cause" stderr_has "tmpfs overlay"

CASE="other dm devices only"
set_dm containerd
ok "fails" not run_enforce

CASE="scratch too small"
set_dm scratch
printf '16777216' > "$WORK/sys/block/dm-0/size" # 8Gi
ok "fails" not run_enforce
ok "names the cause" stderr_has "too small"

CASE="scratch size unreadable"
set_dm scratch
: > "$WORK/sys/block/dm-0/size"
ok "fails closed" not run_enforce

CASE="scratch is not crypt"
set_dm scratch
printf 'DM-LINEAR-test' > "$WORK/sys/block/dm-0/dm/uuid"
ok "fails closed" not run_enforce

CASE="scratch has wrong backing serial"
set_dm scratch
printf 'confai-scratch' > "$WORK/sys/block/vdb/device/serial"
printf 'host-lookalike' > "$WORK/sys/block/vdb/serial"
ok "fails closed" not run_enforce

CASE="scratch has only a parent device serial"
set_dm scratch
printf 'confai-scratch' > "$WORK/sys/block/vdb/device/serial"
rm "$WORK/sys/block/vdb/serial"
ok "fails closed" not run_enforce

CASE="scratch has an empty block device serial"
set_dm scratch
printf 'confai-scratch' > "$WORK/sys/block/vdb/device/serial"
: > "$WORK/sys/block/vdb/serial"
ok "fails closed" not run_enforce

summarize "scratch-enforce"
