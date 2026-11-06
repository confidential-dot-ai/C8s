#!/bin/bash
# Stage the measured worker document and the launch disk's bootstrap token.
set -euo pipefail

mkdir -p /run/confos
mount_dir=$(mktemp -d /run/confos/launch-disk.XXXXXX)
mounted=0
cleanup() {
    if [ "$mounted" = 1 ]; then umount "$mount_dir" || true; fi
    rmdir "$mount_dir" || true
}
trap cleanup EXIT

udevadm settle --timeout=10 || true
# The launch CD can appear after udev settles on a first boot.
for attempt in $(seq 30); do
    device=$(blkid -L opkeydata) && break
    echo "worker-stage: no opkeydata disk yet (attempt $attempt/30)" >&2
    sleep 1
done
if [ -z "${device:-}" ]; then
    echo "worker-stage: the opkeydata disk with the bootstrap token is required" >&2
    exit 1
fi
timeout 10 mount -t iso9660 -o ro,nodev,nosuid,noexec "$device" "$mount_dir"
mounted=1
# Stage is retried inside this one start job: once the unit fails, systemd
# fails every queued dependent for good.
attempts=5
retry_delay=5
for attempt in $(seq "$attempts"); do
    rc=0
    c8s worker stage --bootstrap-token-file="$mount_dir/bootstrap-token" || rc=$?
    if [ "$rc" -eq 0 ]; then
        exit 0
    fi
    if [ "$attempt" -eq "$attempts" ]; then
        echo "worker-stage: c8s worker stage failed $attempts times (last exit $rc); giving up" >&2
        exit "$rc"
    fi
    echo "worker-stage: c8s worker stage failed (attempt $attempt/$attempts, exit $rc); retrying in ${retry_delay}s" >&2
    sleep "$retry_delay"
    retry_delay=$((retry_delay * 2))
done
