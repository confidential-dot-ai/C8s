#!/usr/bin/env bash
# Render the release's core allowlist entries with the worker build's tools.
# release-seeds.sh RELEASE_CLI RELEASE_DIGESTS_TSV OUTPUT_DIR
set -euo pipefail

[[ $# -eq 3 ]] || { echo "usage: $0 RELEASE_CLI RELEASE_DIGESTS_TSV OUTPUT_DIR" >&2; exit 2; }
cli=$(realpath "$1")
digests=$(realpath "$2")
mkdir -p "$3"
out=$(realpath "$3")
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
profile=images/node-guest/worker/mkosi.sync
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

pin() {
  local value
  value=$(sed -n "s/^$1=\"\([^\"]*\)\"$/\1/p" "$profile")
  [[ -n "$value" && "$value" != *$'\n'* ]] || { echo "missing or repeated worker pin: $1" >&2; exit 1; }
  printf '%s' "$value"
}
digest() {
  local count value
  read -r count value < <(awk -F'\t' -v repo="$1" '$1 == repo { n++; d = $2 } END { print n + 0, d }' "$digests")
  [[ "$count" -eq 1 && "$value" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "expected one release digest for $1" >&2; exit 1; }
  printf '%s' "$value"
}

helm_version=$(pin HELM_VERSION)
helm_sha=$(pin HELM_LINUX_AMD64_SHA256)
kube_version=$(pin KUBERNETES_VERSION)
operator=ghcr.io/confidential-dot-ai/c8s-operator
mesh=ghcr.io/confidential-dot-ai/armtls-mesh
operator_digest=$(digest "$operator")
mesh_digest=$(digest "$mesh")
curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 120 \
  --retry 3 --retry-max-time 300 --output "$work/helm.tar.gz" \
  "https://get.helm.sh/helm-${helm_version}-linux-amd64.tar.gz"
printf '%s  %s\n' "$helm_sha" "$work/helm.tar.gz" | sha256sum --check --status
tar -xzf "$work/helm.tar.gz" -C "$work" linux-amd64/helm
chmod +x "$cli"
for platform in tdx snp; do
  hardware=$platform
  [[ "$platform" != snp ]] || hardware=sev-snp
  PATH="$work/linux-amd64:$PATH" "$cli" node-image render \
    --hardware-platform "$hardware" --kube-version "$kube_version" \
    --image-repository "$operator" --image-digest "$operator_digest" \
    --armtls-mesh-image-repository "$mesh" --armtls-mesh-image-digest "$mesh_digest" \
    --output-dir "$work/$platform"
  jq -e '.schema == "c8s.allowlist/v1" and (.workloads | type == "object" and length > 0)' \
    "$work/$platform/allowlist-seed.json" > /dev/null
  cp "$work/$platform/allowlist-seed.json" "$out/allowlist-seed-$platform.json"
done
