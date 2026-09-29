#!/usr/bin/env bash
# Run the unchanged acceptance helper with local data and PATH command fixtures.
set -euo pipefail
test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$test_dir/../tdx-image-acceptance.sh"
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/evidence" "$fixture/bin"
tests=0
pass() { tests=$((tests + 1)); }
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_deletes() {
  [[ $(cat "$FIXTURE_DELETES") == "$1" ]] || fail "unexpected deletion sequence; expected: $1"
}
reject() {
  if "$@" >"$fixture/stdout" 2>"$fixture/stderr"; then
    fail "unexpected success: $*"
  fi
  pass
}
export GITHUB_RUN_ATTEMPT=2
source_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
run=123
vm=c8s-tdx-123-2
repo=confidential-dot-ai/c8s
ns=confai-images
digest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
image="ghcr.io/confidential-dot-ai/node-guest-base@sha256:$digest"
measurement=$(printf '%096d' 0)
jq -n --arg m "$measurement" '{tdx: {mrtd: $m, rtmr1: $m, rtmr2: $m}}' > "$fixture/evidence/manifest.json"
manifest_sha=$(sha256sum "$fixture/evidence/manifest.json" | cut -d ' ' -f1)
jq -n --arg source "$source_sha" --arg run "$run" --arg image "$image" --arg hash "$manifest_sha" \
  '{schema: 1, source_sha: $source, run_id: $run, build_attempt: "2", c8s_ref: $source[0:7],
    variant: "rke2-tdx", launch_config_version: "c8s-launch/v2", image: $image, artifact: $image, manifest_sha256: $hash}' > "$fixture/good.json"
cp "$fixture/good.json" "$fixture/evidence/acceptance.json"
output=$(bash "$script" validate "$fixture/evidence" "$source_sha" "$run")
[[ $output == *"image=$image"* && $output == *'c8sRef=aaaaaaa'* && $output == *'launchConfigVersion=c8s-launch/v2'* && $output == *"rtmr2=$measurement"* ]] || fail 'missing validated environment'
pass
for mutation in \
  '.source_sha = "cccccccccccccccccccccccccccccccccccccccc"' \
  '.run_id = "456"' \
  '.build_attempt = "1"' \
  'del(.build_attempt)' \
  '.schema = 2' \
  '.launch_config_version = "legacy"' \
  '.launch_config_version = "c8s-launch/v1"' \
  'del(.launch_config_version)' \
  '.variant = "rke2-tdx-dev"' \
  '.variant = "rke2-snp"' \
  '.c8s_ref = "main"' \
  '.image = "ghcr.io/confidential-dot-ai/node-guest-base:rke2-tdx-cdi"' \
  '.image = "ghcr.io/untrusted/image@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
  '.image = "ghcrXio/confidential-dot-ai/node-guest-base@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
  '.artifact = "invalid"' \
  '.manifest_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
  '.image = ("x\nINJECTED=yes")' \
  'del(.manifest_sha256)'; do
  jq "$mutation" "$fixture/good.json" > "$fixture/evidence/acceptance.json"
  reject bash "$script" validate "$fixture/evidence" "$source_sha" "$run"
done
cp "$fixture/good.json" "$fixture/evidence/acceptance.json"
reject bash "$script" validate "$fixture/evidence" main "$run"
reject bash "$script" validate "$fixture/evidence" "$source_sha" invalid
reject env GITHUB_RUN_ATTEMPT= bash "$script" validate "$fixture/evidence" "$source_sha" "$run"
cp "$fixture/evidence/manifest.json" "$fixture/manifest-good.json"
jq 'del(.tdx.rtmr2)' "$fixture/manifest-good.json" > "$fixture/evidence/manifest.json"
bad_hash=$(sha256sum "$fixture/evidence/manifest.json" | cut -d ' ' -f1)
jq --arg hash "$bad_hash" '.manifest_sha256 = $hash' "$fixture/good.json" > "$fixture/evidence/acceptance.json"
reject bash "$script" validate "$fixture/evidence" "$source_sha" "$run"
cp "$fixture/good.json" "$fixture/evidence/acceptance.json"
cp "$fixture/manifest-good.json" "$fixture/evidence/manifest.json"
bash "$script" pvc "$fixture/evidence" "$source_sha" "$run" "$vm" "$ns" "$repo" > "$fixture/pvc-good.json"
jq -e '
  .metadata.name == "c8s-tdx-123-2-root" and
  .metadata.annotations["cdi.kubevirt.io/storage.import.endpoint"] == null and
  .metadata.annotations["cdi.kubevirt.io/storage.bind.immediate.requested"] == null and
  .metadata.labels["ci.confidential.ai/run-id"] == "123" and
  .spec.storageClassName == "local-path"
' "$fixture/pvc-good.json" >/dev/null || fail 'private PVC contract mismatch'
pass
reject bash "$script" pvc "$fixture/evidence" "$source_sha" "$run" staged-root "$ns" "$repo"
reject bash "$script" pvc "$fixture/evidence" "$source_sha" "$run" "$vm" default "$repo"
reject bash "$script" pvc "$fixture/evidence" "$source_sha" "$run" "$vm" "$ns" another/repo
reject bash "$script" pvc "$fixture/evidence" "$source_sha" "$run" c8s-tdx-456-2 "$ns" "$repo"
bash "$script" binder "$vm" "$ns" "$run" "$repo" > "$fixture/binder-good.json"
jq -e '.spec.automountServiceAccountToken == false and
  .spec.nodeSelector["kubevirt.io/tdx"] == "true" and
  .spec.securityContext.runAsNonRoot == true and
  .spec.containers[0].volumeMounts == null and
  (.spec.containers[0].image | contains("@sha256:")) and
  .spec.volumes[0].persistentVolumeClaim.claimName == "c8s-tdx-123-2-root"' "$fixture/binder-good.json" >/dev/null || fail 'unsafe binder'
pass

# No production text rewriting: only external tools are replaced on PATH.
cat > "$fixture/bin/kubectl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FIXTURE_LOG"
record_delete() {
  while [[ $# -gt 0 && $1 != delete ]]; do shift; done
  [[ $# -ge 3 ]] || exit 1
  printf '%s/%s\n' "$2" "$3" >> "$FIXTURE_DELETES"
}
case " $* " in
  *' get pvc -l '*) cat "$FIXTURE_ROOTS" ;;
  *' get pvc '*) cat "$FIXTURE_PVC" ;;
  *' get pod '*) cat "$FIXTURE_BINDER" ;;
  *' get vm '*) printf '%s' "${FIXTURE_VM:-}" ;;
  *' annotate pvc '*) printf '%s\n' "$*" >> "$FIXTURE_ANNOTATIONS" ;;
  *' delete pod '*|*' delete pvc '*) record_delete "$@" ;;
  *) exit 1 ;;
esac
SH
cat > "$fixture/bin/gh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "${FIXTURE_RUN_STATUS:-}"
SH
cat > "$fixture/bin/sleep" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat > "$fixture/bin/date" <<'SH'
#!/usr/bin/env bash
case " $* " in
  *' -d '*) echo 100000 ;;
  *) echo 120000 ;;
esac
SH
chmod +x "$fixture/bin/"*
export PATH="$fixture/bin:$PATH"
export FIXTURE_LOG="$fixture/calls" FIXTURE_PVC="$fixture/pvc.json"
export FIXTURE_DELETES="$fixture/deletes" FIXTURE_ROOTS="$fixture/roots.json"
export FIXTURE_BINDER="$fixture/binder.json" FIXTURE_ANNOTATIONS="$fixture/annotations"
: > "$FIXTURE_BINDER"
: > "$FIXTURE_ANNOTATIONS"
: > "$FIXTURE_DELETES"
jq '.metadata.annotations["cdi.kubevirt.io/storage.pod.phase"] = "Succeeded"' "$fixture/pvc-good.json" > "$FIXTURE_PVC"
bash "$script" wait "$vm" "$ns" "$run" "$repo"
pass
jq '.metadata.annotations["cdi.kubevirt.io/storage.pod.phase"] = "Failed"' "$fixture/pvc-good.json" > "$FIXTURE_PVC"
reject bash "$script" wait "$vm" "$ns" "$run" "$repo"
cp "$fixture/pvc-good.json" "$FIXTURE_PVC"
reject bash "$script" wait "$vm" "$ns" "$run" "$repo" 1
reject bash "$script" wait "$vm" "$ns" "$run" "$repo" 0
jq '.metadata.labels["ci.confidential.ai/run-id"] = "456"' "$fixture/pvc-good.json" > "$FIXTURE_PVC"
reject bash "$script" wait "$vm" "$ns" "$run" "$repo"
reject bash "$script" cleanup "$vm" "$ns" "$run" "$repo"
[[ ! -s $FIXTURE_DELETES ]] || fail 'deleted another run resource'
cp "$fixture/pvc-good.json" "$FIXTURE_PVC"
bash "$script" cleanup "$vm" "$ns" "$run" "$repo"
expect_deletes "pvc/$vm-root"
pass
: > "$FIXTURE_PVC"
bash "$script" cleanup "$vm" "$ns" "$run" "$repo"
expect_deletes "pvc/$vm-root"
pass
cp "$fixture/pvc-good.json" "$FIXTURE_PVC"
jq -n --slurpfile pvc "$fixture/pvc-good.json" '{items: $pvc}' > "$FIXTURE_ROOTS"
export FIXTURE_RUN_STATUS=in_progress
bash "$script" reap "$ns" 456 "$repo"
expect_deletes "pvc/$vm-root"
pass
export FIXTURE_RUN_STATUS=completed FIXTURE_VM=virtualmachine.kubevirt.io/c8s-tdx-123-2
bash "$script" reap "$ns" 456 "$repo"
expect_deletes "pvc/$vm-root"
pass
export FIXTURE_VM=''
bash "$script" reap "$ns" 456 "$repo"
expect_deletes "pvc/$vm-root"$'\n'"pvc/$vm-root"
pass
bash "$script" reap "$ns" 123 "$repo"
expect_deletes "pvc/$vm-root"$'\n'"pvc/$vm-root"
pass
# Unknown status plus a positively old creation time follows existing 3h policy.
export FIXTURE_RUN_STATUS=''
bash "$script" reap "$ns" 456 "$repo"
expect_deletes "pvc/$vm-root"$'\n'"pvc/$vm-root"$'\n'"pvc/$vm-root"
pass
# Import annotations are added only to an owned PVC bound to the owned TDX consumer.
jq '.spec.nodeName = "tdx-node-1" | .status.conditions = [{type: "PodScheduled", status: "True"}]' \
  "$fixture/binder-good.json" > "$FIXTURE_BINDER"
jq '.status.phase = "Bound" | .metadata.annotations["volume.kubernetes.io/selected-node"] = "tdx-node-1"' \
  "$fixture/pvc-good.json" > "$FIXTURE_PVC"
bash "$script" start-import "$fixture/evidence" "$source_sha" "$run" "$vm" "$ns" "$repo"
grep -Fq "cdi.kubevirt.io/storage.import.endpoint=docker://$image" "$FIXTURE_ANNOTATIONS" || fail 'missing digest-pinned import'
pass
cp "$FIXTURE_PVC" "$fixture/pvc-bound.json"
jq '.metadata.annotations["volume.kubernetes.io/selected-node"] = "other-node"' "$fixture/pvc-bound.json" > "$FIXTURE_PVC"
reject bash "$script" start-import "$fixture/evidence" "$source_sha" "$run" "$vm" "$ns" "$repo"
cp "$fixture/pvc-bound.json" "$FIXTURE_PVC"
jq '.metadata.labels["ci.confidential.ai/run-id"] = "456"' "$fixture/binder-good.json" > "$FIXTURE_BINDER"
reject bash "$script" start-import "$fixture/evidence" "$source_sha" "$run" "$vm" "$ns" "$repo"
reject bash "$script" cleanup-binder "$vm" "$ns" "$run" "$repo"
expect_deletes "pvc/$vm-root"$'\n'"pvc/$vm-root"$'\n'"pvc/$vm-root"
# Combined cleanup removes precisely the owned binder first, then its disk.
: > "$FIXTURE_DELETES"
cp "$fixture/binder-good.json" "$FIXTURE_BINDER"
cp "$fixture/pvc-good.json" "$FIXTURE_PVC"
bash "$script" cleanup "$vm" "$ns" "$run" "$repo"
expect_deletes "pod/$vm-binder"$'\n'"pvc/$vm-root"
pass
# A foreign binder prevents deletion of either resource.
: > "$FIXTURE_DELETES"
jq '.metadata.labels["ci.confidential.ai/run-id"] = "456"' "$fixture/binder-good.json" > "$FIXTURE_BINDER"
reject bash "$script" cleanup "$vm" "$ns" "$run" "$repo"
expect_deletes ''
echo "$tests exact-image acceptance assertions passed"
