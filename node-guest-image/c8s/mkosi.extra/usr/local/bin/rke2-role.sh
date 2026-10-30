#!/bin/bash
# The image is identical for every role. Only a launch document signed by
# this boot's measured operator key may select services and join credentials.
set -euo pipefail

case "${CRED_PLATFORM:-}" in
    tdx|snp) ;;
    *) echo "rke2-role: missing baked TEE platform" >&2; exit 1 ;;
esac

mkdir -p /run/confos
mount_dir=$(mktemp -d /run/confos/launch-disk.XXXXXX)
mounted=0
complete=0
cleanup() {
    if [ "$complete" != 1 ]; then
        rm -f /run/confos/role-server /run/confos/role-agent /run/confos/role-pod
    fi
    if [ "$mounted" = 1 ]; then umount "$mount_dir"; fi
    rmdir "$mount_dir"
}
trap cleanup EXIT

udevadm settle --timeout=10
# The launch CD can appear after udev settles on a first boot.
for attempt in $(seq 30); do
    device=$(blkid -L opkeydata) && break
    echo "rke2-role: no opkeydata disk yet (attempt $attempt/30)" >&2
    sleep 1
done
if [ -z "${device:-}" ]; then
    echo "rke2-role: opkeydata containing signed launch.yaml is required" >&2
    exit 1
fi
timeout 10 mount -t iso9660 -o ro,nodev,nosuid,noexec "$device" "$mount_dir"
mounted=1
# C8s authenticates the exact bytes before strict parsing and writes the
# selected role marker only after every launch output has been staged.
# Only verification is retried, and inside this one start job: once this unit
# fails, systemd fails every queued dependent for good.
verify_launch() {
    c8s launch-config stage --platform="$CRED_PLATFORM" \
        --config="$mount_dir/launch.yaml" --signature="$mount_dir/launch.yaml.sig"
}

verification_attempts=5
retry_delay=5
for attempt in $(seq "$verification_attempts"); do
    rc=0
    verify_launch || rc=$?
    if [ "$rc" -eq 0 ]; then
        break
    fi
    if [ "$attempt" -eq "$verification_attempts" ]; then
        echo "rke2-role: launch verification (c8s launch-config stage) failed $verification_attempts times (last exit $rc); giving up" >&2
        exit "$rc"
    fi
    echo "rke2-role: launch verification (c8s launch-config stage) failed (attempt $attempt/$verification_attempts, exit $rc); retrying in ${retry_delay}s" >&2
    sleep "$retry_delay"
    retry_delay=$((retry_delay * 2))
done
c8s node-services prepare
complete=1
