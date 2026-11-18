#!/usr/bin/env bash
# release-seeds.sh <c8s> <out-dir> <operator-digest> <mesh-digest> <platform>...:
# render the allowlist seed a release publishes for each CPU TEE (tdx or
# sev-snp) as <out-dir>/allowlist-seed-<platform>.json, and its component set
# as <out-dir>/component-set-<platform>.json, with the c8s binary <c8s>, the release's
# c8s-operator and armtls-mesh digests, and the kubelet version
# images/node-guest/worker/mkosi.sync pins; helm on PATH must be the Helm
# version it pins. See docs/releases.md.
set -euo pipefail

[ $# -ge 5 ] || { echo "usage: $0 <c8s> <out-dir> <operator-digest> <mesh-digest> <platform>..." >&2; exit 2; }
c8s=$1
out=$2
operator=$3
mesh=$4
shift 4

worker="$(dirname "${BASH_SOURCE[0]}")/../../images/node-guest/worker"
kube_version="$(sed -n 's/^KUBERNETES_VERSION="\(v[0-9.]*\)"$/\1/p' "$worker/mkosi.sync")"
[ -n "$kube_version" ] || { echo "$0: $worker/mkosi.sync pins no KUBERNETES_VERSION" >&2; exit 1; }

render="$(mktemp -d)"
trap 'rm -rf -- "$render"' EXIT
mkdir -p "$out"
for platform in "$@"; do
  "$c8s" node-image render \
    --hardware-platform "$platform" \
    --kube-version "$kube_version" \
    --image-digest "$operator" \
    --armtls-mesh-image-digest "$mesh" \
    --floor-template "$worker/image-policy.yaml.in" \
    --output-dir "$render/$platform"
  cp "$render/$platform/allowlist-seed.json" "$out/allowlist-seed-$platform.json"
  cp "$render/$platform/component-set.json" "$out/component-set-$platform.json"
done
