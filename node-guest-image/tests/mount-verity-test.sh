#!/usr/bin/env bash
# Disposable kernel integration test; pass a build-host-compiled NRI test binary.
# Requires root, loop devices, mkfs.ext4, veritysetup and fs-verity support.
set -euo pipefail
if [[ $# -lt 1 || $# -gt 2 || $(id -u) != 0 ]]; then
  echo "usage: sudo bash $0 /absolute/path/to/nri-verity.test [coverage-directory]" >&2
  exit 1
fi
binary=$(realpath "$1")
if [[ $(readlink /proc/self/ns/mnt) == $(readlink /proc/1/ns/mnt) ]]; then
  exec unshare --mount bash "$0" "$@"
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
 umount "$work/verity" 2>/dev/null || true
 veritysetup close "$mapper" 2>/dev/null || true
 umount "$work/fs" 2>/dev/null || true
 rm -rf "$work"
}
trap cleanup EXIT
mount --make-rprivate /
truncate -s 128M "$work/image"
mkfs.ext4 -q -F -O verity "$work/image"
mkdir "$work/fs" "$work/verity"
mount -o loop "$work/image" "$work/fs"
C8S_TEST_FS_VERITY_DIR="$work/fs" "$binary" -test.run '^TestFSVerityPinnedInodeIntegration$' -test.v "${fs_coverage[@]}"
printf 'approved executable' > "$work/fs/binary"
umount "$work/fs"
truncate -s 8M "$work/hash"
veritysetup format "$work/image" "$work/hash" > "$work/format"
root_hash=$(awk '/Root hash:/ {print $3}' "$work/format")
veritysetup open "$work/image" "$mapper" "$work/hash" "$root_hash"
mount -o ro /dev/mapper/"$mapper" "$work/verity"
C8S_TEST_DM_VERITY_ROOT="$work/verity" C8S_TEST_DM_VERITY_HASH="$root_hash" "$binary" -test.run '^TestDMVerityMountedRootIntegration$' -test.v "${dm_coverage[@]}"
