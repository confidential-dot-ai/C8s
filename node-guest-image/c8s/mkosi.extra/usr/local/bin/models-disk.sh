#!/bin/bash
# Mount the plain weights disk at /var/lib/models before rke2 starts, so large
# model weights (an HF cache of hundreds of GiB) survive a CVM relaunch instead
# of re-downloading. Run by models-disk.service.
#
# Unlike containerd-data-disk.sh this disk is NOT encrypted. Weights are public
# — the guarantee wanted is integrity, not secrecy, and integrity rests on the
# workload verifying model digests, not on dm-crypt. The host (L0) can read and
# rewrite the disk; that is fine because the content is public and verified.
#
# Default: a pre-populated disk, mounted read-only and never formatted. When the
# signed launch document sets models.writable, stage leaves
# /run/confos/launch/models-writable (holding models.rootOwner, possibly empty):
# a disk with no filesystem is formatted, and the disk is mounted read-write,
# so a workload can download weights into it inside the TEE.
#
# Absent disk → no-op (GPU-less / no-weights boots): the workload just downloads
# to its own store. No tmpfs fallback — a cold cache is acceptable, wasting guest
# RAM on it is not.
#
# Ordered Before rke2 so the mount exists when pods start. Always nodev, nosuid,
# noexec: nothing on a host-writable disk may execute in the guest — workloads
# read weights, not binaries.
set -u

DIR=/var/lib/models
WRITABLE=/run/confos/launch/models-writable
# Per probe/mkfs/mount step. A wedged device must not block boot past the
# unit's TimeoutStartSec (120s); mirrors containerd-data-disk.sh's step bound.
STEP_TIMEOUT=30

mkdir -p "$DIR"

# Already mounted (service re-run / RemainAfterExit) → nothing to do.
if mountpoint -q "$DIR"; then
    echo "models-disk: $DIR already mounted"
    exit 0
fi

# Find the models disk by serial=confai-models. virtio-scsi (KubeVirt Bus:
# scsi) surfaces the serial ONLY in /dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_
# <serial>, NOT in /sys/block/<dev>/serial (empty on SCSI) — same matching as
# containerd-data-disk.sh. Poll briefly (~10s) so a slow udev probe doesn't make
# us miss it. virtio-blk is scanned as a fallback via its sysfs serial.
DEV=""
for _ in $(seq 1 20); do
    for l in /dev/disk/by-id/*confai-models*; do
        [ -e "$l" ] || continue
        DEV="$(readlink -f "$l")"; break
    done
    [ -n "$DEV" ] && break
    for d in /dev/sd? /dev/vd?; do
        [ -b "$d" ] || continue
        if [ "$(cat "/sys/block/$(basename "$d")/serial" 2>/dev/null || true)" = "confai-models" ]; then
            DEV="$d"; break
        fi
    done
    [ -n "$DEV" ] && break
    sleep 0.5
done

if [ -z "$DEV" ]; then
    echo "models-disk: no serial=confai-models disk — skipping (workload will download weights)"
    exit 0
fi

if [ ! -e "$WRITABLE" ]; then
    echo "models-disk: found weights disk at $DEV — mounting read-only at $DIR"
    if timeout "$STEP_TIMEOUT" mount -o ro,nodev,nosuid,noexec "$DEV" "$DIR"; then
        echo "models-disk: mounted $DEV read-only at $DIR"
        exit 0
    fi
    echo "models-disk: mount of $DEV failed — skipping (workload will download weights)" >&2
    exit 0
fi

# blkid -p probes the device itself and exits 2 only when it finds no
# filesystem or partition table, so a disk with anything on it is never
# formatted. Lazy init and nodiscard keep mkfs to the metadata, whatever the
# disk size (see containerd-data-disk.sh); the journal stays, the cache does
# not start over after a crash.
timeout "$STEP_TIMEOUT" blkid -p "$DEV" >/dev/null 2>&1
probe=$?
if [ "$probe" = 2 ]; then
    owner=$(cat "$WRITABLE")
    echo "models-disk: $DEV is blank — creating ext4${owner:+ owned by $owner}"
    if ! timeout "$STEP_TIMEOUT" mkfs.ext4 -q -m0 \
            -E "lazy_itable_init=1,lazy_journal_init=1,nodiscard${owner:+,root_owner=$owner}" "$DEV"; then
        echo "models-disk: mkfs of $DEV failed — skipping (workload will download weights)" >&2
        exit 0
    fi
elif [ "$probe" != 0 ]; then
    echo "models-disk: probing $DEV failed — skipping (workload will download weights)" >&2
    exit 0
fi

if timeout "$STEP_TIMEOUT" mount -o rw,nodev,nosuid,noexec "$DEV" "$DIR"; then
    echo "models-disk: mounted $DEV read-write at $DIR"
    exit 0
fi

echo "models-disk: mount of $DEV failed — skipping (workload will download weights)" >&2
exit 0
