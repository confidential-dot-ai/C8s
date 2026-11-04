#!/bin/bash
# Back /var/lib/rancher/rke2/agent/containerd with a real (non-overlay) FS before
# rke2 starts. Run by containerd-data-disk.service. See that unit for the why.
#
# A LABEL=containerd block device → ephemeral encrypted ext4 (random per-boot key,
# never persisted). No such device, or any failure on the encrypted path → tmpfs
# (the historical RAM-backed default). Either way the dir ends up on a filesystem
# containerd's overlay snapshotter can use as an upperdir.
#
# THREAT MODEL: the host (L0) is untrusted and can read/write the backing block
# device. The aes-xts-plain64 encryption gives CONFIDENTIALITY only — the host
# cannot read which image layers are cached or their content. It does NOT give
# integrity: plain-mode dm-crypt has no MAC, so the host can tamper with
# ciphertext and the guest will decrypt attacker-chosen plaintext silently.
# Image-content integrity instead rests on containerd's content-addressed store:
# layer blobs are sha256-verified on pull/unpack, so a tampered cached blob fails
# its digest check before use. (Caveat: an already-EXTRACTED snapshot rootfs is
# not re-verified per read — out of scope here; the cache is ephemeral and
# re-pullable.) Mirrors the initrd's confai-scratch overlay, same plain-mode
# stance.
#
# This unit is Before=local-fs.target, so it must NEVER hang or hard-fail: every
# risky step is wrapped in `timeout`, and the function always returns. The final
# guarantee (ensure_tmpfs) makes the dir usable even if the disk path fell over.
set -u

DIR=/var/lib/rancher/rke2/agent/containerd
SIZE_TMPFS=32G
# Per cryptsetup/mkfs/mount step. Three steps + the tmpfs fallback must finish
# under the unit's TimeoutStartSec (180s), or systemd SIGKILLs the script before
# the fallback runs and the dir is left on overlay. 30s × 3 = 90s leaves ample
# headroom. (A step in uninterruptible D-state ignores the SIGTERM `timeout`
# sends — the real defense is the fast mkfs below, which removes the only step
# observed to hang; this bound is the backstop.)
STEP_TIMEOUT=30

mkdir -p "$DIR"

ensure_tmpfs() {
    mountpoint -q "$DIR" && return 0
    echo "containerd-data-disk: backing $DIR with tmpfs (size=$SIZE_TMPFS)"
    mount -t tmpfs -o "size=$SIZE_TMPFS,nodev,nosuid,mode=0700" tmpfs "$DIR"
}

# Already mounted (service re-run / RemainAfterExit) → nothing to do.
if mountpoint -q "$DIR"; then
    echo "containerd-data-disk: $DIR already mounted"
    exit 0
fi

# Find the containerd data disk. vda is the verity rootfs. Prefer the SCSI bus
# (sd*): under SEV-SNP/KubeVirt a secondary virtio-blk disk wedges on every I/O
# (raw dd hangs in uninterruptible D-state — iommu=on is forced on all virtio
# devices and the virtio-blk DMA path is broken for hot-attached data disks;
# virtio-scsi works). Scan sd* first, then vd* as a fallback for launches
# without that quirk. Poll briefly (~10s) so a slow udev probe doesn't make us
# miss it.
#
# Two ways a device qualifies:
#   1. filesystem LABEL=containerd — a host-prepared, pre-labelled disk.
#   2. device SERIAL=confai-containerd — a BLANK disk confai attaches with that
#      serial (mirrors the confai-scratch datadisk). This is the confai path:
#      the disk carries no filesystem, so the encrypted mkfs below lays one down
#      per boot. `blkid -p` probes the device directly (not the stale udev
#      cache); the serial comes from sysfs.
DEV=""
for _ in $(seq 1 20); do
    # by-id first: virtio-scsi (KubeVirt Bus: scsi) surfaces the serial ONLY in
    # /dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_<serial>, NOT in
    # /sys/block/<dev>/serial (empty on SCSI). This is the confai path
    # (--containerd-disk-gi attaches a scsi disk serial=confai-containerd).
    for l in /dev/disk/by-id/*confai-containerd*; do
        [ -e "$l" ] || continue
        DEV="$(readlink -f "$l")"; break
    done
    [ -n "$DEV" ] && break
    for d in /dev/sd? /dev/vd?; do
        [ -b "$d" ] || continue
        # virtio-blk surfaces the serial in sysfs (SCSI does not — see above).
        # Checked first: a sysfs read cannot wedge, a device probe can.
        if [ "$(cat "/sys/block/$(basename "$d")/serial" 2>/dev/null || true)" = "confai-containerd" ]; then
            DEV="$d"; break
        fi
        # host-prepared disk with a real filesystem LABEL. The probe reads the
        # device itself, so timeout-bound it: this unit is Before=local-fs.target
        # and must not hang on a wedged disk (SEV-SNP virtio-blk reads have
        # gone D-state before; the bound is best-effort, D-state ignores it).
        if [ "$(timeout 5 blkid -p -s LABEL -o value "$d" 2>/dev/null || true)" = "containerd" ]; then
            DEV="$d"; break
        fi
    done
    [ -n "$DEV" ] && break
    sleep 0.5
done

if [ -z "$DEV" ]; then
    echo "containerd-data-disk: no LABEL=containerd disk — using tmpfs (image cache counts against guest RAM)"
    ensure_tmpfs
    exit $?
fi

echo "containerd-data-disk: found LABEL=containerd at $DEV — encrypted ephemeral overlay backing"
# Random per-boot key, kept only in (TEE-encrypted) RAM, never persisted.
KEY=/run/containerd-data.key
( umask 077; head -c 64 /dev/urandom > "$KEY" )

# Encrypted path, fully guarded: every step is `timeout`-wrapped (incl. mount —
# a wedged dm device must not block boot to the unit-level TimeoutStartSec), so
# any timeout/failure (e.g. a kernel missing dm-crypt/XTS) degrades to tmpfs
# rather than hanging or aborting the boot.
#
# The per-boot random key means last boot's ext4 is unreadable noise this boot,
# so we mkfs the freshly-opened mapper every boot. That mkfs MUST be near-instant
# regardless of device size: a full mkfs across a multi-GiB device writes the
# whole inode table, and in a CVM every guest I/O page is encrypted onto a
# sparse host-backed disk — slow enough to block in uninterruptible D-state past
# both the step `timeout` and the unit's TimeoutStartSec, killing the unit and
# leaving the dir on overlay (containerd snapshotter then loops "not supported
# as upperdir"). lazy_itable_init/lazy_journal_init defer the table writes to
# the kernel, ^has_journal drops the journal (ephemeral re-pullable cache needs
# no crash-consistency), and nodiscard skips a full-device TRIM — so mkfs
# touches only the superblock + group descriptors.
MKFS_OPTS="-F -q -m0 -O ^has_journal -E lazy_itable_init=1,lazy_journal_init=1,nodiscard"
if timeout "$STEP_TIMEOUT" cryptsetup open --batch-mode --type plain \
        --cipher aes-xts-plain64 --key-size 512 -d "$KEY" "$DEV" containerd \
   && timeout "$STEP_TIMEOUT" mkfs.ext4 $MKFS_OPTS /dev/mapper/containerd \
   && timeout "$STEP_TIMEOUT" mount -o nodev,nosuid /dev/mapper/containerd "$DIR"; then
    rm -f "$KEY"
    echo "containerd-data-disk: mounted encrypted $DEV at $DIR"
    exit 0
fi

rm -f "$KEY"
echo "containerd-data-disk: encrypted path failed (kernel missing dm-crypt/XTS?) — falling back to tmpfs" >&2
cryptsetup close containerd 2>/dev/null || true
ensure_tmpfs
exit $?
