#!/usr/bin/env bash
# chart-stamp.sh stamps a copy of the cloud chart with release digests and
# checks a packaged chart against them; the production chart is read, never
# written.
set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "$test_dir/../../.." && pwd)
script="$repo_dir/.github/scripts/chart-stamp.sh"
chart="$repo_dir/internal/helmchart/cloud"
table="$chart/charts/c8s-lib/files/components.yaml"
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
tests=0
cp "$chart/values.yaml" "$fixture/values.before"

fail() { echo "FAIL: $*" >&2; exit 1; }
expect_failure_naming() {
  local needle=$1
  shift
  if "$@" >"$fixture/unexpected.stdout" 2>"$fixture/unexpected.stderr"; then
    fail "command unexpectedly succeeded: $*"
  fi
  grep -qF -- "$needle" "$fixture/unexpected.stderr" || fail "expected \"$needle\" in: $(cat "$fixture/unexpected.stderr")"
}
digest() { printf 'sha256:%064d' "$1"; }
fresh_chart() {
  rm -rf "$fixture/cloud"
  cp -rL "$chart" "$fixture/cloud"
}
# image_config NAME VALUE_PATH: the config the table declares for VALUE_PATH,
# served by the fake crane for repository NAME.
image_config() {
  yq -o=json -I0 ".components[] | select(.valuePath == \"$2\") | {\"config\": {\"Entrypoint\": .entrypoint, \"Env\": (.imageEnv | to_entries | map(.key + \"=\" + (.value | tostring)))}}" "$table" >"$fixture/configs/$1.json"
}
# without_digests VALUES: VALUES as JSON with every digest emptied.
without_digests() { yq -o=json '(.. | select(key == "digest")) = ""' "$1"; }

# A fake crane serving each component image the config its block declares.
mkdir -p "$fixture/bin" "$fixture/configs"
cat >"$fixture/bin/crane" <<'EOF'
#!/usr/bin/env bash
[[ "$1 $2 $3" == "config --platform linux/amd64" && $# -eq 4 ]] || { echo "unexpected crane call: $*" >&2; exit 1; }
cat "$CRANE_CONFIGS/$(basename "${4%@*}").json"
EOF
chmod +x "$fixture/bin/crane"
export PATH="$fixture/bin:$PATH" CRANE_CONFIGS="$fixture/configs"
image_config armtls-mesh armtlsMesh.image
image_config attestation-api attestationApi.image
image_config c8s-operator image
image_config volumed volumed.image

# What the images job uploads: every release image, the CDS included.
digests="$fixture/digests.tsv"
{
  printf 'ghcr.io/confidential-dot-ai/c8s-operator\t%s\n' "$(digest 1)"
  printf 'ghcr.io/confidential-dot-ai/armtls-mesh\t%s\n' "$(digest 2)"
  printf 'ghcr.io/confidential-dot-ai/nri-image-policy\t%s\n' "$(digest 3)"
  printf 'ghcr.io/confidential-dot-ai/volumed\t%s\n' "$(digest 4)"
  printf 'ghcr.io/confidential-dot-ai/cds\t%s\n' "$(digest 5)"
} >"$digests"
pinned=$(bash "$repo_dir/.github/scripts/chart-attestation-api-digest.sh" get)

# stamp writes each component's digest, the attestation-api's from its pin,
# and no other value.
fresh_chart
bash "$script" stamp "$fixture/cloud" "$digests"
values="$fixture/cloud/values.yaml"
for want in "image $(digest 1)" "armtlsMesh.image $(digest 2)" "nriImagePolicy.image $(digest 3)" "volumed.image $(digest 4)" "attestationApi.image $pinned"; do
  got=$(yq -r ".${want% *}.digest" "$values")
  [[ "$got" == "${want#* }" ]] || fail "${want% *}.digest = $got, want ${want#* }"
done
unstamped=$(without_digests "$chart/values.yaml")
[[ "$(without_digests "$values")" == "$unstamped" ]] || fail "stamp changed a value other than a digest"
tests=$((tests + 1))

# check accepts the stamped chart and refuses an unstamped one or other digests.
bash "$script" check "$fixture/cloud" "$digests"
sed "s|$(digest 2)|$(digest 9)|" "$digests" >"$fixture/other.tsv"
expect_failure_naming "armtlsMesh.image.digest is $(digest 2), want $(digest 9)" bash "$script" check "$fixture/cloud" "$fixture/other.tsv"
cp -r "$fixture/cloud" "$fixture/stamped"
fresh_chart
expect_failure_naming 'image.digest is , want' bash "$script" check "$fixture/cloud" "$digests"
tests=$((tests + 1))

# stamp refuses: the tracked chart, a stamped chart, a chart without its
# vendored component table, a repository on no line or on two, and an image
# whose config differs from its block.
expect_failure_naming "is inside $repo_dir" bash "$script" stamp "$chart" "$digests"
expect_failure_naming "has no empty image.digest" bash "$script" stamp "$fixture/stamped" "$digests"
cp -r "$chart" "$fixture/unvendored"
expect_failure_naming "vendor the chart's c8s-lib dependency" bash "$script" stamp "$fixture/unvendored" "$digests"
grep -v volumed "$digests" >"$fixture/partial.tsv"
expect_failure_naming "0 lines for volumed.image's repository ghcr.io/confidential-dot-ai/volumed" bash "$script" stamp "$fixture/cloud" "$fixture/partial.tsv"
{ cat "$digests"; printf 'ghcr.io/confidential-dot-ai/volumed\t%s\n' "$(digest 6)"; } >"$fixture/twice.tsv"
expect_failure_naming "2 lines for volumed.image's repository" bash "$script" stamp "$fixture/cloud" "$fixture/twice.tsv"
printf '{"config":{"Entrypoint":["/app/c8s","volumed"],"Env":["PATH=/bin"]}}' >"$fixture/configs/volumed.json"
expect_failure_naming "volumed@$(digest 4) sets env" bash "$script" stamp "$fixture/cloud" "$digests"
cmp -s "$chart/values.yaml" "$fixture/values.before" || fail "the production values.yaml changed"
tests=$((tests + 1))

# The stamped package is c8s-cloud and renders every component by digest.
helm package "$fixture/stamped" --version 0.0.0-test --destination "$fixture/dist" >/dev/null
printf '{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"cds","measurement":"%096d","launch_file":"clusterID: test\\n"}]}' 1 >"$fixture/pin.json"
rendered=$(helm template c8s "$fixture/dist/c8s-cloud-0.0.0-test.tgz" \
  --kube-version v1.30.0 \
  --namespace c8s-system \
  -f "$fixture/stamped/values-aks-snp.yaml" \
  --set volumed.enabled=true \
  --set-string cds.address=10.9.9.9:8443 \
  --set-file cds.measurementsConfig="$fixture/pin.json" \
  --set-string nriImagePolicy.mesh.resolver=10.96.0.10 \
  --set 'nriImagePolicy.mesh.clusterRanges={10.244.0.0/16}')
for image in "c8s-operator@$(digest 1)" "armtls-mesh@$(digest 2)" "nri-image-policy@$(digest 3)" "volumed@$(digest 4)" "attestation-api@$pinned"; do
  grep -qF "ghcr.io/confidential-dot-ai/$image" <<<"$rendered" || fail "the stamped package does not render $image"
done
tests=$((tests + 1))

echo "chart-stamp: $tests tests passed"
