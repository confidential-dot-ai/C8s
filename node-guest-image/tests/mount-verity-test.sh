#!/usr/bin/env bash
# Disposable kernel integration test; pass a build-host-compiled NRI test binary.
# Requires root, loop devices, mkfs.ext4, veritysetup and fs-verity support.
set -euo pipefail
if [[ $# -lt 1 || $# -gt 2 || $(id -u) != 0 ]]; then
  echo "usage: sudo bash $0 /absolute/path/to/nri-verity.test [coverage-directory]" >&2
  exit 1
fi
binary=$(realpath "$1")
# Comparing with PID 1's namespace misses a namespace shared with other
# processes, so always enter a fresh one.
if [[ -z ${C8S_VERITY_NS:-} ]]; then
  C8S_VERITY_NS=1 exec unshare --mount bash "$0" "$@"
fi
fs_coverage=()
dm_coverage=()
if [[ $# == 2 ]]; then
  coverage_dir=$(realpath "$2")
  [[ -d "$coverage_dir" ]] || { echo "coverage directory must exist" >&2; exit 1; }
  fs_coverage=(-test.coverprofile="$coverage_dir/fs-verity.out")
  dm_coverage=(-test.coverprofile="$coverage_dir/dm-verity.out")
fi
work=$(mktemp -d /tmp/c8s-verity-kernel.XXXXXX)
mapper="c8s-test-verity-$$"
cleanup() {
 umount "$work/verity/mnt" 2>/dev/null || true
 umount "$work/verity" 2>/dev/null || true
 veritysetup close "$mapper" 2>/dev/null || true
 umount "$work/fs" 2>/dev/null || true
 umount -R "$work/fsv" 2>/dev/null || true
 rm -rf "$work"
}
trap cleanup EXIT
mount --make-rprivate /
# The fs-verity leg gets its own filesystem, shared like systemd's /run, so the
# staging root must make itself private. A leaked staging bind fails this
# leg's unmount, not the dm-verity leg's.
truncate -s 32M "$work/fsv-image"
mkfs.ext4 -q -F -O verity "$work/fsv-image"
mkdir "$work/fsv"
mount -o loop "$work/fsv-image" "$work/fsv"
mount --make-shared "$work/fsv"
C8S_TEST_FS_VERITY_DIR="$work/fsv" "$binary" -test.run '^TestFSVerityPinnedInodeIntegration$' -test.v "${fs_coverage[@]}"
umount "$work/fsv" || { echo "fs-verity staging left mounts on its test filesystem" >&2; exit 1; }
truncate -s 128M "$work/image"
mkfs.ext4 -q -F "$work/image"
mkdir "$work/fs" "$work/verity"
mount -o loop "$work/image" "$work/fs"
printf 'approved executable' > "$work/fs/binary"
mkdir "$work/fs/mnt"
umount "$work/fs"
truncate -s 8M "$work/hash"
veritysetup format "$work/image" "$work/hash" > "$work/format"
root_hash=$(awk '/Root hash:/ {print $3}' "$work/format")
veritysetup open "$work/image" "$mapper" "$work/hash" "$root_hash"
mount -o ro /dev/mapper/"$mapper" "$work/verity"
mount -t tmpfs tmpfs "$work/verity/mnt"
printf 'unmeasured' > "$work/verity/mnt/binary"
C8S_TEST_DM_VERITY_ROOT="$work/verity" C8S_TEST_DM_VERITY_HASH="$root_hash" "$binary" -test.run '^TestDMVerityMountedRootIntegration$' -test.v "${dm_coverage[@]}"
