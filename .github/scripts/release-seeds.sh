#!/usr/bin/env bash
# The allowlist seed of each node-image platform as a release asset
# (docs/releases.md). semver-tag.yml renders the assets before it signs the
# release statement that lists them; c8s-image.yml checks each built image
# against them before it publishes. Both formats of a platform (rke2-<p> and
# rke2-<p>-cdi) are one disk, so they bake one seed.
#
#   render <c8s> <out-dir> <operator-digest> <cds-digest> <mesh-digest> <platform>...
#       Write allowlist-seed-<platform>.json (tdx or snp) as
#       node-guest-image/c8s/mkosi.sync renders the seed it bakes.
#   baked <disk.raw> <out-file>
#       Copy the seed a built image bakes. Needs root.
#   check <release-dir> <platform> <baked-seed>
#       Require the baked seed to equal the platform's asset and the sha256
#       the release statement lists. The caller verifies the statement first.
set -euo pipefail

fail() { echo "release-seeds: $*" >&2; exit 1; }
seed_path=usr/lib/c8s/allowlist-seed.json

render() {
    local c8s=$1 out=$2 operator=$3 cds=$4 mesh=$5 registry=ghcr.io/confidential-dot-ai kube platform tmp
    shift 5
    kube=$(sed -n 's/^RKE2_VERSION="\(v[^+"]*\)+[^"]*"$/\1/p' \
        "$(dirname "${BASH_SOURCE[0]}")/../../node-guest-image/c8s/mkosi.sync")
    [ -n "$kube" ] || fail "no RKE2_VERSION in mkosi.sync"
    tmp=$(mktemp -d)
    mkdir -p "$out"
    for platform in "$@"; do
        "$c8s" node-image render \
            --hardware-platform "$([ "$platform" = snp ] && echo sev-snp || echo "$platform")" \
            --kube-version "$kube" \
            --image-repository "$registry/c8s-operator" --image-digest "$operator" \
            --cds-image-repository "$registry/cds" --cds-image-digest "$cds" \
            --armtls-mesh-image-repository "$registry/armtls-mesh" --armtls-mesh-image-digest "$mesh" \
            --output-dir "$tmp/$platform"
        cp "$tmp/$platform/allowlist-seed.json" "$out/allowlist-seed-$platform.json"
    done
    rm -rf -- "$tmp"
}

baked() {
    local part
    loop=$(losetup -Pfr --show "$1")
    mnt=$(mktemp -d)
    trap 'umount -q "$mnt" || true; losetup -d "$loop"; rmdir "$mnt"' EXIT
    for part in "$loop"p*; do
        [ "$(blkid -o value -s TYPE "$part" || true)" = erofs ] || continue
        mount -o ro "$part" "$mnt"
        if [ -f "$mnt/$seed_path" ]; then
            cp "$mnt/$seed_path" "$2"
            return
        fi
        umount "$mnt"
    done
    fail "$1 bakes no /$seed_path"
}

check() {
    local asset="allowlist-seed-$2.json" listed actual
    listed=$(jq -er --arg p "$2" --arg a "$asset" \
        '.allowlistSeeds[$p] | select(.asset == $a) | .sha256 | select(test("^[0-9a-f]{64}$"))' \
        "$1/release-statement.json") || fail "release statement lists no $asset"
    actual=$(sha256sum < "$1/$asset")
    [ "${actual%% *}" = "$listed" ] || fail "$asset is not the seed the release statement lists"
    cmp -s "$3" "$1/$asset" || fail "the image bakes a seed other than release asset $asset"
    echo "image bakes release asset $asset (sha256 $listed)"
}

case "${1:-}" in
    render | baked | check) "$@" ;;
    *) fail "usage: release-seeds.sh render|baked|check ..." ;;
esac
