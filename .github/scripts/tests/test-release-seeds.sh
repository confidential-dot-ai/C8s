#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/repo/.github/scripts" "$work/repo/images/node-guest/worker" "$work/bin" "$work/archive/linux-amd64"
cp "$script_dir/../release-seeds.sh" "$work/repo/.github/scripts/"
script="$work/repo/.github/scripts/release-seeds.sh"
profile="$work/repo/images/node-guest/worker/mkosi.sync"
cat > "$work/archive/linux-amd64/helm" <<'HELM'
#!/usr/bin/env bash
printf '%s\n' pinned-helm
HELM
chmod +x "$work/archive/linux-amd64/helm"
tar -czf "$work/helm.tar.gz" -C "$work/archive" linux-amd64/helm
sha=$(sha256sum < "$work/helm.tar.gz")
printf 'HELM_VERSION="v8.7.6"\nHELM_LINUX_AMD64_SHA256="%s"\nKUBERNETES_VERSION="v1.98.2"\n' "${sha%% *}" > "$profile"
cat > "$work/bin/curl" <<'CURL'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FETCH_LOG"
while [[ $# -gt 0 ]]; do
  if [[ "$1" == --output ]]; then cp "$HELM_ARCHIVE" "$2"; exit; fi
  shift
done
exit 1
CURL
cat > "$work/c8s" <<'CLI'
#!/usr/bin/env bash
[[ "$(helm version)" == pinned-helm ]] || exit 1
printf '%s\n' "$*" >> "$RENDER_LOG"
platform=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --hardware-platform) platform=$2; shift ;;
    --output-dir) out=$2; shift ;;
  esac
  shift
done
mkdir -p "$out"
if [[ "${EMPTY_SEED:-}" == 1 ]]; then
  echo '{"schema":"c8s.allowlist/v1","workloads":{}}' > "$out/allowlist-seed.json"
else
  printf '{"schema":"c8s.allowlist/v1","workloads":{"%s":{}}}\n' "$platform" > "$out/allowlist-seed.json"
fi
CLI
chmod +x "$work/bin/curl" "$work/c8s"
export PATH="$work/bin:$PATH" HELM_ARCHIVE="$work/helm.tar.gz" FETCH_LOG="$work/fetch.log" RENDER_LOG="$work/render.log"
operator="sha256:$(printf 'a%.0s' {1..64})"
mesh="sha256:$(printf 'b%.0s' {1..64})"
printf 'ghcr.io/confidential-dot-ai/c8s-operator\t%s\nghcr.io/confidential-dot-ai/armtls-mesh\t%s\n' "$operator" "$mesh" > "$work/digests"
bash "$script" "$work/c8s" "$work/digests" "$work/out"
for platform in tdx sev-snp; do
  grep -F -- "node-image render --hardware-platform $platform --kube-version v1.98.2" "$RENDER_LOG" \
    | grep -F -- "--image-repository ghcr.io/confidential-dot-ai/c8s-operator --image-digest $operator" \
    | grep -F -- "--armtls-mesh-image-repository ghcr.io/confidential-dot-ai/armtls-mesh --armtls-mesh-image-digest $mesh" > /dev/null
done
grep -q 'https://get.helm.sh/helm-v8.7.6-linux-amd64.tar.gz' "$FETCH_LOG"
jq -e '.workloads.tdx != null' "$work/out/allowlist-seed-tdx.json" > /dev/null
jq -e '.workloads["sev-snp"] != null' "$work/out/allowlist-seed-snp.json" > /dev/null
cp -r "$work/out" "$work/first"
bash "$script" "$work/c8s" "$work/digests" "$work/out"
diff -r "$work/first" "$work/out"

expect_failure() {
  if "$@" > "$work/stdout" 2> "$work/stderr"; then
    echo "unexpected success: $*" >&2; exit 1
  fi
}
cp "$work/digests" "$work/bad"
cat "$work/digests" >> "$work/bad"
expect_failure bash "$script" "$work/c8s" "$work/bad" "$work/out"
grep -q 'expected one release digest' "$work/stderr"
sed '/armtls-mesh/d' "$work/digests" > "$work/bad"
expect_failure bash "$script" "$work/c8s" "$work/bad" "$work/out"
EMPTY_SEED=1 expect_failure bash "$script" "$work/c8s" "$work/digests" "$work/out"
sed -i 's/HELM_LINUX_AMD64_SHA256=.*/HELM_LINUX_AMD64_SHA256="0000000000000000000000000000000000000000000000000000000000000000"/' "$profile"
expect_failure bash "$script" "$work/c8s" "$work/digests" "$work/out"
echo 'release-seeds: pinned rendering, repeatability, missing/repeated digests, empty seeds and corrupt Helm checks passed'
