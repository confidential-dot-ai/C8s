#!/usr/bin/env bash
set -euo pipefail
# Private mount namespace; detach only the loop devices this invocation created.
if [[ "${RECOVERY_MOUNT_NAMESPACE:-}" != 1 ]]; then
    exec unshare --mount --propagation private env RECOVERY_MOUNT_NAMESPACE=1 bash "$0" "$@"
fi
old=$1 new=$2 fixture=$3 work=$4
loops=()
mounts=()
cleanup() {
    local m l
    for m in "${mounts[@]}"; do umount "$m" || true; done
    for l in "${loops[@]}"; do losetup -d "$l" || true; done
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
for side in old new; do
    disk=$old
    [[ "$side" != new ]] || disk=$new
    loop=$(losetup -Pfr --show "$disk")
    loops+=("$loop")
    m="$work/mount-$side"
    mkdir -p "$m"
    found=false
    for part in "$loop"p*; do
        [[ "$(blkid -o value -s TYPE "$part" || true)" = erofs ]] || continue
        mount -o ro "$part" "$m"
        if [[ -f "$m/usr/local/bin/c8s" ]]; then found=true; mounts+=("$m"); break; fi
        umount "$m"
    done
    [[ "$found" == true ]]
done
python3 "$fixture/verify-roots.py" "$work/mount-old" "$work/mount-new" "$work"
