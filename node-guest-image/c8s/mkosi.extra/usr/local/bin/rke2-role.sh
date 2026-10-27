#!/bin/bash
# The image is identical for both roles. Only a launch document signed by
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
        rm -f /run/confos/role-server /run/confos/role-agent
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
# Verification needs this boot's first quote and, on SNP, collateral from AMD
# KDS; either can fail once (a platform SVN update, nodes booting together).
# The retry must stay inside this one start job: once this unit fails, systemd
# fails every queued dependent (rke2, cred-release, ...) for good. Stage
# clears its outputs first, so a retry is idempotent. Worst case, with the
# verifier's 90 s readiness wait and 15 s report per attempt, plus jittered
# backoff: 5 * 105 s + 150 s, well inside TimeoutStartSec.
attempts=5
delay=5
for attempt in $(seq "$attempts"); do
    rc=0
    c8s launch-config stage --platform="$CRED_PLATFORM" \
        --config="$mount_dir/launch.yaml" --signature="$mount_dir/launch.yaml.sig" || rc=$?
    [ "$rc" = 0 ] && break
    if [ "$attempt" = "$attempts" ]; then
        echo "rke2-role: launch verification (c8s launch-config stage) failed $attempts times (last exit $rc); giving up: the node will power off" >&2
        exit 1
    fi
    wait=$((delay + RANDOM % delay))
    echo "rke2-role: launch verification (c8s launch-config stage) failed (attempt $attempt/$attempts, exit $rc); retrying in ${wait}s" >&2
    sleep "$wait"
    delay=$((delay * 2))
done
c8s node-services prepare
complete=1
