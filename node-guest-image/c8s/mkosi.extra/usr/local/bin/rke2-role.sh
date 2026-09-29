#!/bin/bash
# The image is identical for both roles. Only a launch document signed by
# this boot's measured operator key may select services and membership policy.
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
        rm -f /run/confos/role-server /run/confos/role-agent
    fi
    if [ "$mounted" = 1 ]; then umount "$mount_dir"; fi
    rmdir "$mount_dir"
}
trap cleanup EXIT

udevadm settle --timeout=10
device=$(blkid -L opkeydata) || {
    echo "rke2-role: opkeydata containing signed launch.yaml is required" >&2
    exit 1
}
timeout 10 mount -t iso9660 -o ro,nodev,nosuid,noexec "$device" "$mount_dir"
mounted=1
# c8s authenticates the exact bytes before strict parsing and writes the
# selected role marker only after every launch output has been staged.
c8s launch-config stage --platform="$CRED_PLATFORM" \
    --config="$mount_dir/launch.yaml" --signature="$mount_dir/launch.yaml.sig"
c8s node-services prepare
complete=1
