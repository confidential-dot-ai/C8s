#!/usr/bin/env bash
# Run the SNP node image helper over local publication data.
set -euo pipefail
test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$test_dir/../snp-node-image.sh"
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
tests=0
pass() { tests=$((tests + 1)); }
fail() { echo "FAIL: $*" >&2; exit 1; }
reject() {
  if "$@" >"$fixture/stdout" 2>"$fixture/stderr"; then
    fail "unexpected success: $*"
  fi
  pass
}

repo=ghcr.io/confidential-dot-ai/node-guest-base
cdi=sha256:$(printf 'c%.0s' {1..64})
igvm_hex=$(printf 'd%.0s' {1..64})
other_hex=$(printf 'e%.0s' {1..64})
launch=$(printf '%096d' 7)
layer() { jq -n --arg t "$1" --arg d "sha256:$2" '{mediaType: "application/vnd.oci.image.layer.v1.tar", digest: $d, size: 1, annotations: {"org.opencontainers.image.title": $t}}'; }
jq -n --argjson l "$(layer manifest.json "$other_hex")" --argjson i "$(layer guest-smp4.igvm "$igvm_hex")" \
  --argjson j "$(layer guest-smp2.igvm "$other_hex")" '{layers: [$j, $i, $l]}' > "$fixture/oras.json"
jq -n --arg d "$igvm_hex" --arg o "$other_hex" --arg m "$launch" '{
  version: 3, build: {platform: "snp"},
  snp_variants: [
    {smp: 2, igvm: {path: "guest-smp2.igvm", sha256: $o}, measurement: {algorithm: "sha384", snp_launch_digest: $m}},
    {smp: 4, igvm: {path: "guest-smp4.igvm", sha256: $d}, measurement: {algorithm: "sha384", snp_launch_digest: $m}}]}' > "$fixture/manifest.json"

output=$(bash "$script" env "$fixture/oras.json" "$fixture/manifest.json" "$cdi" 4)
expected="image=$repo@$cdi
rootPvc=c8s-snp-root-cccccccccccc
igvmPvc=c8s-snp-igvm-dddddddddddd
igvmFile=guest-smp4.igvm
igvmDigest=sha256:$igvm_hex
snpLaunchDigest=$launch"
[[ $output == "$expected" ]] || fail "unexpected environment: $output"
pass

# The variant must exist once, measure with sha384, and name the published IGVM.
for mutation in \
  '.build.platform = "tdx"' \
  '.version = 2' \
  'del(.snp_variants[1])' \
  '.snp_variants += [.snp_variants[1]]' \
  '.snp_variants[1].measurement.algorithm = "sha256"' \
  '.snp_variants[1].measurement.snp_launch_digest = "abc"' \
  '.snp_variants[1].igvm.path = "guest-smp2.igvm"' \
  ".snp_variants[1].igvm.sha256 = \"$other_hex\"" \
  'del(.snp_variants[1].igvm)'; do
  jq "$mutation" "$fixture/manifest.json" > "$fixture/mutated.json"
  reject bash "$script" env "$fixture/oras.json" "$fixture/mutated.json" "$cdi" 4
done
# The artifact must carry exactly one IGVM for the count and one manifest.json.
for mutation in \
  'del(.layers[1])' \
  '.layers += [.layers[1]]' \
  '.layers[1].digest = "sha256:short"' \
  '{}'; do
  jq "$mutation" "$fixture/oras.json" > "$fixture/mutated.json"
  reject bash "$script" env "$fixture/mutated.json" "$fixture/manifest.json" "$cdi" 4
done
reject bash "$script" env "$fixture/oras.json" "$fixture/manifest.json" "$cdi" 8
reject bash "$script" env "$fixture/oras.json" "$fixture/manifest.json" "$repo@$cdi" 4
reject bash "$script" env "$fixture/oras.json" "$fixture/manifest.json" "sha256:$igvm_hex" x

[[ $(bash "$script" manifest-layer "$fixture/oras.json") == "sha256:$other_hex" ]] || fail 'manifest.json layer'
pass
for mutation in 'del(.layers[2])' '.layers += [.layers[2]]' '.layers[2].digest = "sha256:short"' '{}'; do
  jq "$mutation" "$fixture/oras.json" > "$fixture/mutated.json"
  reject bash "$script" manifest-layer "$fixture/mutated.json"
done

image="$repo@$cdi"
pvc=$(bash "$script" root-pvc "$image" confai-images)
jq -e --arg image "$image" '
  .kind == "PersistentVolumeClaim" and .metadata.name == "c8s-snp-root-cccccccccccc" and
  .metadata.namespace == "confai-images" and
  .metadata.labels["ci.confidential.ai/resource"] == "snp-node-root" and
  .metadata.annotations["cdi.kubevirt.io/storage.import.endpoint"] == ("docker://" + $image) and
  .metadata.annotations["cdi.kubevirt.io/storage.import.secretName"] == "ghcr-pull" and
  .spec.storageClassName == "local-path"' <<<"$pvc" >/dev/null || fail 'root PVC manifest'
pass
bash "$script" check-root-pvc "$image" <<<"$pvc"
pass
reject bash "$script" root-pvc "ghcr.io/untrusted/image@$cdi" confai-images
reject bash "$script" root-pvc "$repo:rke2-snp-cdi" confai-images
# Adopting a claim that imported another image, or that no run owns, is refused.
reject bash "$script" check-root-pvc "$repo@sha256:$other_hex" <<<"$pvc"
reject bash "$script" check-root-pvc "$image" <<<"$(jq 'del(.metadata.labels)' <<<"$pvc")"

igvm=$(bash "$script" igvm-pvc confai-images "sha256:$igvm_hex")
jq -e --arg d "sha256:$igvm_hex" '
  .metadata.name == "c8s-snp-igvm-dddddddddddd" and
  .metadata.labels["ci.confidential.ai/resource"] == "snp-node-igvm" and
  .metadata.annotations["confai.confidential.ai/igvm-digest"] == $d' <<<"$igvm" >/dev/null || fail 'IGVM PVC manifest'
pass
bash "$script" check-igvm-pvc "sha256:$igvm_hex" <<<"$igvm"
pass
reject bash "$script" igvm-pvc confai-images "$igvm_hex"
reject bash "$script" check-igvm-pvc "sha256:$other_hex" <<<"$igvm"

pod=$(bash "$script" igvm-pod c8s-snp-123-1-igvm confai-images c8s-snp-igvm-dddddddddddd guest-smp4.igvm "sha256:$igvm_hex" 123 confidential-dot-ai/C8s)
jq -e --arg d "$igvm_hex" '
  .kind == "Pod" and .metadata.name == "c8s-snp-123-1-igvm" and .spec.restartPolicy == "Never" and
  .metadata.labels["ci.confidential.ai/run-id"] == "123" and
  .metadata.annotations["ci.confidential.ai/repo"] == "confidential-dot-ai/C8s" and
  .spec.volumes[0].persistentVolumeClaim.claimName == "c8s-snp-igvm-dddddddddddd" and
  (.spec.activeDeadlineSeconds | type == "number") and
  (.spec.containers[0].image | test("^docker[.]io/curlimages/curl@sha256:[0-9a-f]{64}$")) and
  (.spec.containers[0].env | map({(.name): .value}) | add) ==
    {IGVM_FILE: "guest-smp4.igvm", IGVM_SHA256: $d, OCI_REPO: "confidential-dot-ai/node-guest-base",
     FETCH_MAX_TIME: ((.spec.activeDeadlineSeconds - 60) | tostring)} and
  (.spec.containers[0].command[2] | contains($d) | not) and
  .spec.securityContext.runAsNonRoot == true and
  .spec.containers[0].securityContext.allowPrivilegeEscalation == false' <<<"$pod" >/dev/null || fail 'IGVM fetch pod manifest'
pass
# The fetch script is fixed text; every input reaches it through the environment.
jq -r '.spec.containers[0].command[2]' <<<"$pod" > "$fixture/fetch.sh"
if command -v shellcheck >/dev/null; then shellcheck -s sh "$fixture/fetch.sh"; pass; fi
reject bash "$script" igvm-pod 'c8s-snp-123-1-igvm;rm' confai-images c8s-snp-igvm-dddddddddddd guest-smp4.igvm "sha256:$igvm_hex" 123 confidential-dot-ai/C8s
reject bash "$script" igvm-pod c8s-snp-123-1-igvm confai-images c8s-snp-igvm-dddddddddddd ../etc/passwd "sha256:$igvm_hex" 123 confidential-dot-ai/C8s
reject bash "$script" igvm-pod c8s-snp-123-1-igvm confai-images c8s-snp-igvm-dddddddddddd guest-smp4.igvm "$igvm_hex" 123 confidential-dot-ai/C8s
reject bash "$script" igvm-pod c8s-snp-123-1-igvm confai-images c8s-snp-igvm-dddddddddddd guest-smp4.igvm "sha256:$igvm_hex" abc confidential-dot-ai/C8s
reject bash "$script" bogus

echo "ok: $tests checks"
