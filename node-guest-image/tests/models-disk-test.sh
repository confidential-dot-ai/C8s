#!/bin/bash
# Unit test for models-disk.sh: a read-only, never-formatted mount by default,
# and with the staged models-writable marker a blank disk formatted (with the
# signed root owner) and mounted read-write, never a disk that carries
# anything. Root-free: the production script runs verbatim with its absolute
# paths rebased into a temp root, and mount/blkid/mkfs are stubs that log.
set -u

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$TESTS_DIR/lib.sh"
SCRIPT=${MODELS_DISK_SCRIPT:-"$TESTS_DIR/../c8s/mkosi.extra/usr/local/bin/models-disk.sh"}
[[ -x "$SCRIPT" ]] || { echo "script not found: $SCRIPT"; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
LOG="$WORK/calls"
MARKER="$WORK/run/confos/launch/models-writable"
mkdir -p "$WORK/bin" "$WORK/by-id" "$WORK/run/confos/launch"

stub() { printf '#!/bin/bash\n%s\n' "$2" > "$WORK/bin/$1"; chmod +x "$WORK/bin/$1"; }
stub mountpoint 'exit 1'
stub sleep 'exit 0'
stub timeout 'shift; exec "$@"'
stub mount 'echo "mount $*" >> "'"$LOG"'"'
stub mkfs.ext4 'echo "mkfs.ext4 $*" >> "'"$LOG"'"'
# BLKID_RC: 0 found a signature, 2 found nothing, anything else a probe error.
# shellcheck disable=SC2016 # expanded by the stub, not here
stub blkid 'echo "blkid $*" >> "'"$LOG"'"; exit "${BLKID_RC:-0}"'

run_disk() { # run_disk [BLKID_RC]
    : > "$LOG"
    sed -e "s|/var/lib/models|$WORK/models|g" \
        -e "s|/run/confos/launch|$WORK/run/confos/launch|g" \
        -e "s|/dev/disk/by-id|$WORK/by-id|g" \
        -e "s|/dev/sd? /dev/vd?|$WORK/none|g" \
        "$SCRIPT" | BLKID_RC="${1:-0}" PATH="$WORK/bin:$PATH" bash >/dev/null 2>"$WORK/stderr"
}
attach() { : > "$WORK/disk"; ln -sf "$WORK/disk" "$WORK/by-id/scsi-0QEMU_QEMU_HARDDISK_confai-models"; }
logged() { grep -q -- "$1" "$LOG"; }

CASE="no disk"
run_disk
ok "mounts nothing" not test -s "$LOG"

attach

CASE="default"
run_disk 2
ok "mounts read-only, noexec" logged "mount -o ro,nodev,nosuid,noexec $WORK/disk $WORK/models"
ok "never probes or formats, even a blank disk" not logged "blkid\|mkfs"

CASE="writable, blank disk"
printf '65532:65532' > "$MARKER"
run_disk 2
ok "formats with the signed root owner" logged "mkfs.ext4 .*root_owner=65532:65532 $WORK/disk"
ok "mounts read-write, noexec" logged "mount -o rw,nodev,nosuid,noexec $WORK/disk $WORK/models"

CASE="writable, blank disk, no owner"
: > "$MARKER"
run_disk 2
ok "formats without a root owner" logged "mkfs.ext4 .*nodiscard $WORK/disk"
ok "no empty root_owner" not logged "root_owner"

CASE="writable, disk carries a filesystem"
run_disk 0
ok "does not format" not logged "mkfs"
ok "mounts read-write" logged "mount -o rw,nodev,nosuid,noexec"

CASE="writable, probe fails"
run_disk 1
ok "neither formats nor mounts" not logged "mkfs\|mount"
ok "says why" stderr_has "probing"

summarize "models-disk"
