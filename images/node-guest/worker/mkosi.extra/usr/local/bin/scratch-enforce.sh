#!/bin/sh
# scratch-enforce: refuse to bring up a node CVM that booted without its
# confai-scratch write-storage disk — the initrd's silent fallback is a 2G
# tmpfs backing the state overlays, which the node later wedges on (see
# ../README.md "Launch requirements"). The unit running this fails the boot.
#
# The gate is what the initrd actually did, not disk presence: on success
# the state overlays sit on a plain-mode dm mapping named "scratch". Sysfs,
# not /dev/mapper — the dm state needs no udev.
set -eu

SYS_BLOCK_ROOT=${SYS_BLOCK_ROOT:-/sys/block}
PROVENANCE_FILE=${PROVENANCE_FILE:-/run/c8s/scratch-provenance.json}
BOOT_ID_FILE=${BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}

fail() {
    echo "scratch-enforce: $1 — refusing to start the node. Attach a virtio-blk disk with serial=confai-scratch, >=64G." >&2
    exit 1
}

# 64G in 512-byte sectors — decimal, so a 64GB or 64GiB disk both pass.
MIN_SECTORS=125000000

for d in "$SYS_BLOCK_ROOT"/dm-*; do
    [ -e "$d/dm/name" ] || continue
    [ "$(cat "$d/dm/name")" = "scratch" ] || continue
    # An unreadable or empty size must fail closed: a non-number would only
    # make [ complain, and set -e ignores a failed if condition.
    sectors=$(cat "$d/size" 2>/dev/null || true)
    case "$sectors" in ''|*[!0-9]*) sectors=0 ;; esac
    if [ "$sectors" -lt "$MIN_SECTORS" ]; then
        fail "scratch disk too small ($((sectors / 2048)) MiB, need >=64G)"
    fi
    uuid=$(cat "$d/dm/uuid" 2>/dev/null || true)
    case "$uuid" in CRYPT-*) ;; *) fail "scratch mapping is not a crypt target" ;; esac
    device=$(cat "$d/dev" 2>/dev/null || true)
    case "$device" in ''|*[!0-9:]*|:*|*:) fail "scratch mapping has no valid device number" ;; esac
    # virtio-blk publishes the disk serial as the block device's own attribute,
    # /sys/block/<dev>/serial, which is what the initrd matched to build this
    # mapping; the parent virtio device under <dev>/device carries no serial.
    scratch_slave=false
    for slave in "$d"/slaves/*; do
        [ -e "$slave" ] || continue
        if [ "$(cat "$slave/serial" 2>/dev/null || true)" = "confai-scratch" ]; then
            scratch_slave=true
        fi
    done
    [ "$scratch_slave" = true ] || fail "scratch mapping has no confai-scratch backing device"
    boot_id=$(cat "$BOOT_ID_FILE" 2>/dev/null || true)
    [ -n "$boot_id" ] || fail "cannot read the boot ID"
    mkdir -p "$(dirname "$PROVENANCE_FILE")"
    tmp="$PROVENANCE_FILE.tmp.$$"
    printf '{"version":1,"boot_id":"%s","device":"%s","name":"scratch","uuid":"%s"}\n' \
        "$boot_id" "$device" "$uuid" >"$tmp"
    chmod 0600 "$tmp"
    mv -f "$tmp" "$PROVENANCE_FILE"
    echo "scratch-enforce: writable state is on the encrypted scratch disk"
    exit 0
done
fail "initrd fell back to the tmpfs overlay (no dm device named scratch)"
