#!/usr/bin/env bash
# The SNP lane's node image, resolved from the commit under test: validation
# of the published artifacts and the manifests that stage them on the
# launcher. Pure functions over files and arguments, so the lane's trust
# decisions are testable without hardware (tests/test-snp-node-image.sh).
#
# The measurements come from the publication's manifest.json, never from a
# running guest, and the IGVM the guest boots must hash to the digest that
# manifest pairs with its launch digest.
set -euo pipefail

REGISTRY=ghcr.io
IMAGE_REPO=$REGISTRY/confidential-dot-ai/node-guest-base
CDS_IMAGE_REPO=$REGISTRY/confidential-dot-ai/cds-guest-base
# Ships curl and busybox sha256sum; the IGVM fetch runs inside the launcher
# cluster, where the runner's tools are not.
FETCH_IMAGE=docker.io/curlimages/curl@sha256:9a1ed35addb45476afa911696297f8e115993df459278ed036182dd2cd22b67b
# The fetch pod bounds itself; the lane's poll loop only reports.
FETCH_DEADLINE_SECONDS=600

fail() { echo "snp-node-image: $*" >&2; exit 1; }

name_ok() { [[ $1 =~ ^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$ ]]; }
digest_ok() { [[ $1 =~ ^sha256:[0-9a-f]{64}$ ]]; }

# claim_name KIND PREFIX DIGEST: the shared claim for one artifact of one guest
# image, keyed by digest.
claim_name() { printf 'c8s-snp-%s-%s-%.12s\n' "$2" "$1" "${3#sha256:}"; }

# guest IMAGE: the published guest image an artifact belongs to, as "<prefix>
# <registry path>": the node image's or the CDS image's. The prefix names its
# claims and labels them, so a claim of one is never adopted for the other.
guest() {
  case "${1%@*}" in
    "$IMAGE_REPO") printf 'node %s\n' "${IMAGE_REPO#"$REGISTRY"/}" ;;
    "$CDS_IMAGE_REPO") printf 'cds %s\n' "${CDS_IMAGE_REPO#"$REGISTRY"/}" ;;
    *) fail "not a published guest image: $1" ;;
  esac
}

# layer ORAS_MANIFEST TITLE: the digest of the one layer with that title.
layer() {
  local oras=$1 title=$2 digest
  digest=$(jq -er --arg t "$title" '
    [.layers[]? | select(.annotations["org.opencontainers.image.title"] == $t)]
    | if length == 1 then .[0].digest else error("expected one \($t) layer") end' "$oras") \
    || fail "the published artifact does not carry exactly one $title"
  digest_ok "$digest" || fail "invalid $title layer digest"
  printf '%s\n' "$digest"
}

# env PREFIX ORAS_MANIFEST MANIFEST_JSON CDI_DIGEST SMP: the lane's environment
# for one published image, or a refusal. ORAS_MANIFEST is the <variant>-<ref>
# artifact's OCI manifest, MANIFEST_JSON its manifest.json layer, CDI_DIGEST
# the <variant>-cdi-<ref> image's. The node image is built per platform and
# names it; one CDS image serves both TEE families, so its manifest carries the
# SNP variants beside the TDX block and names no platform at all.
env_lines() {
  local prefix=$1 oras=$2 manifest=$3 cdi=$4 smp=$5 repo platform variant file igvm_digest launch
  digest_ok "$cdi" || fail 'invalid CDI image digest'
  case "$prefix" in
    node) repo=$IMAGE_REPO platform='"snp"' ;;
    # One image serves both TEE families (images/cds-guest/build --platform
    # both, #1156), so the cds manifest names "multi", not a single platform.
    cds) repo=$CDS_IMAGE_REPO platform='"multi"' ;;
    *) fail "no guest image '$prefix'" ;;
  esac
  jq -e --argjson platform "$platform" '.version == 3 and .build.platform == $platform' "$manifest" >/dev/null \
    || fail "manifest.json is not a version-3 manifest of the $prefix image"
  variant=$(snp_variant "$oras" "$manifest" "$smp") || exit 1
  read -r file igvm_digest launch <<<"$variant"
  printf '%sImage=%s@%s\n' "$prefix" "$repo" "$cdi"
  printf '%sRootPvc=%s\n' "$prefix" "$(claim_name root "$prefix" "$cdi")"
  printf '%sIgvmPvc=%s\n' "$prefix" "$(claim_name igvm "$prefix" "$igvm_digest")"
  printf '%sIgvmFile=%s\n' "$prefix" "$file"
  printf '%sIgvmDigest=%s\n' "$prefix" "$igvm_digest"
  printf '%sLaunchDigest=%s\n' "$prefix" "$launch"
}

# snp_variant ORAS_MANIFEST MANIFEST_JSON SMP: the IGVM file, its digest and
# the launch digest of one vCPU count, or a refusal. The guest must measure to
# that launch digest, and the IGVM it boots must be the published layer the
# manifest pairs with it.
snp_variant() {
  local oras=$1 manifest=$2 smp=$3 file igvm_digest
  [[ $smp =~ ^[1-9][0-9]*$ ]] || fail 'invalid SMP count'
  file="guest-smp${smp}.igvm"
  igvm_digest=$(layer "$oras" "$file")
  jq -e --argjson smp "$smp" --arg f "$file" --arg d "${igvm_digest#sha256:}" '
    ([.snp_variants[] | select(.smp == $smp)] | length == 1) and
    (.snp_variants[] | select(.smp == $smp) |
      .measurement.algorithm == "sha384" and
      (.measurement.snp_launch_digest | type == "string" and test("^[0-9a-f]{96}$")) and
      .igvm.path == $f and .igvm.sha256 == $d)' "$manifest" >/dev/null \
    || fail "manifest.json has no one smp=$smp variant whose IGVM is the published $file"
  printf '%s %s %s\n' "$file" "$igvm_digest" \
    "$(jq -er --argjson smp "$smp" '.snp_variants[] | select(.smp == $smp) | .measurement.snp_launch_digest' "$manifest")"
}

# A CDI registry import into a claim named by image digest, shared read-only
# by every run of this image (the rootdisk is dm-verity, never written).
root_pvc() {
  local image=$1 ns=$2 prefix
  digest_ok "${image#*@}" || fail 'root image is not digest-pinned'
  prefix=$(guest "$image") || exit 1
  prefix=${prefix%% *}
  jq -n --arg name "$(claim_name root "$prefix" "${image#*@}")" --arg ns "$ns" --arg image "$image" \
    --arg resource "snp-$prefix-root" '{
    apiVersion: "v1", kind: "PersistentVolumeClaim",
    metadata: {name: $name, namespace: $ns,
      labels: {"ci.confidential.ai/managed": "true", "ci.confidential.ai/resource": $resource},
      annotations: {
        "cdi.kubevirt.io/storage.bind.immediate.requested": "true",
        "cdi.kubevirt.io/storage.import.source": "registry",
        "cdi.kubevirt.io/storage.import.endpoint": ("docker://" + $image),
        "cdi.kubevirt.io/storage.import.secretName": "ghcr-pull",
        "cdi.kubevirt.io/storage.contentType": "kubevirt"}},
    spec: {accessModes: ["ReadWriteOnce"], storageClassName: "local-path", volumeMode: "Filesystem",
      resources: {requests: {storage: "4Gi"}}}}'
}

# The IGVM, named by its digest and shared the same way; filled by igvm_pod.
igvm_pvc() {
  local ns=$1 digest=$2 image=$3 prefix
  digest_ok "$digest" || fail 'invalid IGVM digest'
  prefix=$(guest "$image") || exit 1
  prefix=${prefix%% *}
  jq -n --arg name "$(claim_name igvm "$prefix" "$digest")" --arg ns "$ns" --arg digest "$digest" \
    --arg resource "snp-$prefix-igvm" '{
    apiVersion: "v1", kind: "PersistentVolumeClaim",
    metadata: {name: $name, namespace: $ns,
      labels: {"ci.confidential.ai/managed": "true", "ci.confidential.ai/resource": $resource},
      annotations: {"confai.confidential.ai/igvm-digest": $digest}},
    spec: {accessModes: ["ReadWriteOnce"], storageClassName: "local-path", volumeMode: "Filesystem",
      resources: {requests: {storage: "1Gi"}}}}'
}

# check_pvc RESOURCE ANNOTATION VALUE < pvc.json: an existing claim is adopted
# only when a run of this lane made it for this exact artifact; sharing a
# shortened name is not enough.
check_pvc() {
  jq -e --arg resource "$1" --arg key "$2" --arg value "$3" '
    .metadata.labels["ci.confidential.ai/managed"] == "true" and
    .metadata.labels["ci.confidential.ai/resource"] == $resource and
    .metadata.annotations[$key] == $value' >/dev/null \
    || fail "existing $1 claim does not match the selected image"
}

# A run-owned pod that fetches the IGVM layer anonymously (the artifact is
# public) into the PVC and verifies its digest before it is named; a second
# run finds the file and exits. The lane's concurrency group does not span
# repositories, so callers elsewhere can stage the same digest at once: each
# pod writes its own temporary file and only the rename is shared. Inputs reach
# the script as environment, never as shell text.
igvm_pod() {
  local name=$1 ns=$2 pvc=$3 file=$4 digest=$5 run=$6 repo=$7 image=$8 prefix oci
  name_ok "$name" || fail 'invalid pod name'
  name_ok "$pvc" || fail 'invalid IGVM PVC name'
  [[ $file =~ ^guest-smp[0-9]+[.]igvm$ ]] || fail 'invalid IGVM file name'
  digest_ok "$digest" || fail 'invalid IGVM digest'
  [[ $run =~ ^[0-9]+$ ]] || fail 'invalid run id'
  prefix=$(guest "$image") || exit 1
  read -r prefix oci <<<"$prefix"
  local script
  script=$(cat <<'SH'
set -eu
f=/igvm/$IGVM_FILE; t=$f.$FETCH_POD.tmp
trap 'rm -f "$t"' EXIT
if [ -f "$f" ] && [ "$(sha256sum "$f" | cut -d' ' -f1)" = "$IGVM_SHA256" ]; then echo "already staged: $f"; exit 0; fi
tok=$(curl -fsSL --retry 3 --max-time 20 "https://ghcr.io/token?scope=repository:$OCI_REPO:pull" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$tok" ] || { echo "no registry token"; exit 1; }
curl -fsSL --retry 3 --max-time "$FETCH_MAX_TIME" -H "Authorization: Bearer $tok" -o "$t" "https://ghcr.io/v2/$OCI_REPO/blobs/sha256:$IGVM_SHA256"
[ "$(sha256sum "$t" | cut -d' ' -f1)" = "$IGVM_SHA256" ] || { echo "fetched IGVM does not hash to the published digest"; exit 1; }
chmod 0444 "$t"; mv -f "$t" "$f"; echo "staged: $f"
SH
)
  jq -n --arg name "$name" --arg ns "$ns" --arg pvc "$pvc" --arg file "$file" --arg digest "${digest#sha256:}" \
    --arg run "$run" --arg repo "$repo" --arg fetcher "$FETCH_IMAGE" --arg oci "$oci" --arg script "$script" \
    --arg resource "snp-$prefix-igvm-fetch" \
    --argjson deadline "$FETCH_DEADLINE_SECONDS" '{
    apiVersion: "v1", kind: "Pod",
    metadata: {name: $name, namespace: $ns,
      labels: {"ci.confidential.ai/managed": "true", "ci.confidential.ai/resource": $resource,
        "ci.confidential.ai/run-id": $run},
      annotations: {"ci.confidential.ai/repo": $repo}},
    spec: {restartPolicy: "Never", activeDeadlineSeconds: $deadline,
      securityContext: {runAsNonRoot: true, runAsUser: 100, runAsGroup: 101, fsGroup: 101, seccompProfile: {type: "RuntimeDefault"}},
      containers: [{name: "fetch", image: $fetcher, command: ["/bin/sh", "-c", $script],
        env: [{name: "IGVM_FILE", value: $file}, {name: "FETCH_POD", value: $name}, {name: "IGVM_SHA256", value: $digest}, {name: "OCI_REPO", value: $oci},
          {name: "FETCH_MAX_TIME", value: (($deadline - 60) | tostring)}],
        securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}},
        resources: {requests: {cpu: "100m", memory: "64Mi"}, limits: {memory: "256Mi"}},
        volumeMounts: [{name: "igvm", mountPath: "/igvm"}]}],
      volumes: [{name: "igvm", persistentVolumeClaim: {claimName: $pvc}}]}}'
}

case ${1:-} in
  manifest-layer)
    [[ $# == 2 ]] || fail 'usage: manifest-layer ORAS_MANIFEST'
    layer "$2" manifest.json ;;
  env)
    [[ $# == 6 ]] || fail 'usage: env PREFIX ORAS_MANIFEST MANIFEST_JSON CDI_DIGEST SMP'
    env_lines "$2" "$3" "$4" "$5" "$6" ;;
  root-pvc)
    [[ $# == 3 ]] || fail 'usage: root-pvc IMAGE NAMESPACE'
    root_pvc "$2" "$3" ;;
  check-root-pvc)
    [[ $# == 2 ]] || fail 'usage: check-root-pvc IMAGE < pvc.json'
    prefix=$(guest "$2") || exit 1
    check_pvc "snp-${prefix%% *}-root" cdi.kubevirt.io/storage.import.endpoint "docker://$2" ;;
  igvm-pvc)
    [[ $# == 4 ]] || fail 'usage: igvm-pvc NAMESPACE DIGEST IMAGE'
    igvm_pvc "$2" "$3" "$4" ;;
  check-igvm-pvc)
    [[ $# == 3 ]] || fail 'usage: check-igvm-pvc DIGEST IMAGE < pvc.json'
    prefix=$(guest "$3") || exit 1
    check_pvc "snp-${prefix%% *}-igvm" confai.confidential.ai/igvm-digest "$2" ;;
  igvm-pod)
    [[ $# == 9 ]] || fail 'usage: igvm-pod NAME NAMESPACE PVC FILE DIGEST RUN_ID REPOSITORY IMAGE'
    igvm_pod "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" ;;
  *) fail 'usage: manifest-layer | env | root-pvc | check-root-pvc | igvm-pvc | check-igvm-pvc | igvm-pod' ;;
esac
