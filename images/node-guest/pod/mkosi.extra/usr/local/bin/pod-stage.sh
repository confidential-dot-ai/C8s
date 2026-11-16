#!/bin/bash
# Stage the pod launch document signed with this boot's measured pod launch
# key, then the pod's network and kubelet inputs.
set -euo pipefail

case "${CRED_PLATFORM:-}" in
    tdx) ;;
    *) echo "pod-stage: missing baked TEE platform" >&2; exit 1 ;;
esac

mkdir -p /run/confos
mount_dir=$(mktemp -d /run/confos/launch-disk.XXXXXX)
mounted=0
complete=0
cleanup() {
    if [ "$complete" != 1 ]; then rm -f /run/confos/role-pod; fi
    if [ "$mounted" = 1 ]; then umount "$mount_dir" || true; fi
    rmdir "$mount_dir" || true
}
trap cleanup EXIT

udevadm settle --timeout=10 || true
# The launch CD can appear after udev settles on a first boot.
for attempt in $(seq 30); do
    device=$(blkid -L opkeydata) && break
    echo "pod-stage: no opkeydata disk yet (attempt $attempt/30)" >&2
    sleep 1
done
if [ -z "${device:-}" ]; then
    echo "pod-stage: the opkeydata disk with the signed launch.yaml is required" >&2
    exit 1
fi
timeout 10 mount -t iso9660 -o ro,nodev,nosuid,noexec "$device" "$mount_dir"
mounted=1
# Only verification is retried, and inside this one start job: once the unit
# fails, systemd fails every queued dependent for good.
attempts=5
retry_delay=5
for attempt in $(seq "$attempts"); do
    rc=0
    c8s launch-config stage --platform="$CRED_PLATFORM" \
        --config="$mount_dir/launch.yaml" --signature="$mount_dir/launch.yaml.sig" || rc=$?
    if [ "$rc" -eq 0 ]; then
        break
    fi
    if [ "$attempt" -eq "$attempts" ]; then
        echo "pod-stage: c8s launch-config stage failed $attempts times (last exit $rc); giving up" >&2
        exit "$rc"
    fi
    echo "pod-stage: c8s launch-config stage failed (attempt $attempt/$attempts, exit $rc); retrying in ${retry_delay}s" >&2
    sleep "$retry_delay"
    retry_delay=$((retry_delay * 2))
done
c8s node-services prepare
complete=1
