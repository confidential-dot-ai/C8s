#!/usr/bin/env bash
# Exact-image evidence is supplied by the trusted publisher in this workflow run.
set -euo pipefail
# The launcher runner reaches the outer cluster with in-cluster credentials.
# kubectl only falls back to those when the flag-merged config equals its
# built-in default, and --request-timeout breaks that equality, so it would
# dial localhost:8080 instead. Bound each call with coreutils timeout.

fail() { echo "tdx-image-acceptance: $*" >&2; exit 1; }

validate() {
  local evidence=$1 source_sha=$2 run_id=$3 actual
  [[ $source_sha =~ ^[0-9a-f]{40}$ && $run_id =~ ^[0-9]+$ ]] || fail 'invalid expected build identity'
  [[ ${GITHUB_RUN_ATTEMPT:-} =~ ^[1-9][0-9]*$ ]] || fail 'invalid expected workflow attempt'
  jq -e --arg source "$source_sha" --arg run "$run_id" --arg attempt "$GITHUB_RUN_ATTEMPT" '
    .schema == 1 and .source_sha == $source and .run_id == $run and
    .build_attempt == $attempt and .launch_config_version == "c8s-launch/v2" and
    .c8s_ref == $source[0:7] and .variant == "rke2-tdx" and
    (.image | type == "string" and test("^ghcr[.]io/confidential-dot-ai/node-guest-base@sha256:[0-9a-f]{64}$")) and
    (.artifact | type == "string" and test("^ghcr[.]io/confidential-dot-ai/node-guest-base@sha256:[0-9a-f]{64}$")) and
    (.manifest_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
  ' "$evidence/acceptance.json" >/dev/null || fail 'image evidence does not match this production build/run'
  actual=$(sha256sum "$evidence/manifest.json")
  [[ ${actual%% *} == "$(jq -r .manifest_sha256 "$evidence/acceptance.json")" ]] || fail 'manifest digest mismatch'
  jq -e '.tdx | [.mrtd, .rtmr1, .rtmr2] | all(.[]; type == "string" and test("^[0-9a-f]{96}$"))' \
    "$evidence/manifest.json" >/dev/null || fail 'invalid TDX measurement tuple'
}

identity() {
  local vm=$1 ns=$2 run=$3 repo=$4
  [[ $run =~ ^[0-9]+$ && $vm =~ ^c8s-tdx-${run}-[0-9]+$ ]] || fail 'invalid run-owned VM name'
  [[ $ns == confai-images && $repo == confidential-dot-ai/c8s ]] || fail 'unexpected acceptance resource scope'
}

owned_root() {
  local object=$1 vm=$2 run=$3 repo=$4 kind=${5:-root}
  jq -e --arg vm "$vm" --arg run "$run" --arg repo "$repo" --arg kind "$kind" '
    .metadata.name == ($vm + "-" + $kind) and
    .metadata.labels["ci.confidential.ai/managed"] == "true" and
    .metadata.labels["ci.confidential.ai/resource"] == ("acceptance-" + $kind) and
    .metadata.labels["ci.confidential.ai/run-id"] == $run and
    .metadata.annotations["ci.confidential.ai/repo"] == $repo
  ' <<<"$object" >/dev/null
}

case ${1:-} in
  validate)
    [[ $# == 4 ]] || fail 'usage: validate EVIDENCE SOURCE_SHA RUN_ID'
    validate "$2" "$3" "$4"
    jq -r '"image=" + .image, "c8sRef=" + .c8s_ref, "launchConfigVersion=" + .launch_config_version' "$2/acceptance.json"
    jq -r '.tdx | "mrtd=" + .mrtd, "rtmr1=" + .rtmr1, "rtmr2=" + .rtmr2' "$2/manifest.json"
    ;;
  pvc)
    [[ $# == 7 ]] || fail 'usage: pvc EVIDENCE SOURCE_SHA RUN_ID VM NAMESPACE REPOSITORY'
    validate "$2" "$3" "$4"
    identity "$5" "$6" "$4" "$7"
    # Deliberately no import annotations yet: bind to the TDX consumer first.
    jq -n --arg vm "$5" --arg ns "$6" --arg run "$4" --arg repo "$7" '{
      apiVersion: "v1", kind: "PersistentVolumeClaim",
      metadata: {name: ($vm + "-root"), namespace: $ns,
        labels: {"ci.confidential.ai/managed": "true", "ci.confidential.ai/resource": "acceptance-root", "ci.confidential.ai/run-id": $run},
        annotations: {"ci.confidential.ai/repo": $repo}},
      spec: {accessModes: ["ReadWriteOnce"], storageClassName: "local-path",
        resources: {requests: {storage: "80Gi"}}}}
    '
    ;;
  binder)
    [[ $# == 5 ]] || fail 'usage: binder VM NAMESPACE RUN_ID REPOSITORY'
    identity "$2" "$3" "$4" "$5"
    jq -n --arg vm "$2" --arg ns "$3" --arg run "$4" --arg repo "$5" '{
      apiVersion: "v1", kind: "Pod",
      metadata: {name: ($vm + "-binder"), namespace: $ns,
        labels: {"ci.confidential.ai/managed": "true", "ci.confidential.ai/resource": "acceptance-binder", "ci.confidential.ai/run-id": $run},
        annotations: {"ci.confidential.ai/repo": $repo}},
      spec: {restartPolicy: "Never", activeDeadlineSeconds: 1500, automountServiceAccountToken: false,
        nodeSelector: {"kubevirt.io/tdx": "true"},
        securityContext: {runAsNonRoot: true, runAsUser: 65534, seccompProfile: {type: "RuntimeDefault"}},
        containers: [{name: "pause",
          # The airgap-imported node pause: admitted by the baked floor,
          # present on every node. Bump with RKE2_VERSION (mkosi.sync).
          image: "docker.io/rancher/mirrored-pause:3.10.2@sha256:f548e0e8e3dc1896ca956272154dde3314e8cc4fde0a57577ee9fa1c63f5baf4",
          resources: {requests: {cpu: "4", memory: "16Gi"}, limits: {cpu: "4", memory: "16Gi"}},
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}}],
        volumes: [{name: "root", persistentVolumeClaim: {claimName: ($vm + "-root"), readOnly: true}}]}}
    '
    ;;
  start-import)
    [[ $# == 7 ]] || fail 'usage: start-import EVIDENCE SOURCE_SHA RUN_ID VM NAMESPACE REPOSITORY'
    validate "$2" "$3" "$4"
    identity "$5" "$6" "$4" "$7"
    object=$(timeout 30 kubectl -n "$6" get pvc "$5-root" -o json)
    owned_root "$object" "$5" "$4" "$7" || fail 'refusing an unowned root PVC'
    binder=$(timeout 30 kubectl -n "$6" get pod "$5-binder" -o json)
    owned_root "$binder" "$5" "$4" "$7" binder || fail 'refusing an unowned binder Pod'
    node=$(jq -er '.spec.nodeName | select(type == "string" and length > 0)' <<<"$binder")
    jq -e --arg node "$node" '.status.phase == "Bound" and
      .metadata.annotations["volume.kubernetes.io/selected-node"] == $node' <<<"$object" >/dev/null ||
      fail 'root PVC is not bound to the TDX binder node'
    jq -e '.spec.nodeSelector["kubevirt.io/tdx"] == "true" and
      any(.status.conditions[]; .type == "PodScheduled" and .status == "True")' <<<"$binder" >/dev/null ||
      fail 'TDX binder is not scheduled'
    image=$(jq -r .image "$2/acceptance.json")
    timeout 30 kubectl -n "$6" annotate pvc "$5-root" \
      cdi.kubevirt.io/storage.import.source=registry \
      "cdi.kubevirt.io/storage.import.endpoint=docker://$image" \
      cdi.kubevirt.io/storage.contentType=kubevirt --overwrite=false
    ;;
  wait)
    [[ $# == 5 || $# == 6 ]] || fail 'usage: wait VM NAMESPACE RUN_ID REPOSITORY [TIMEOUT_SECONDS]'
    identity "$2" "$3" "$4" "$5"
    timeout_seconds=${6:-1200}
    [[ $timeout_seconds =~ ^[1-9][0-9]{0,3}$ && $timeout_seconds -le 1200 ]] || fail 'timeout must be 1..1200 seconds'
    deadline=$((SECONDS + timeout_seconds))
    while (( SECONDS < deadline )); do
      remaining=$((deadline - SECONDS))
      request_timeout=$((remaining < 30 ? remaining : 30))
      object=$(timeout "$request_timeout" kubectl -n "$3" get pvc "$2-root" -o json)
      owned_root "$object" "$2" "$4" "$5" || fail 'refusing an unowned root PVC'
      phase=$(jq -r '.metadata.annotations["cdi.kubevirt.io/storage.pod.phase"] // "Pending"' <<<"$object")
      case $phase in
        Succeeded) exit 0 ;;
        Failed) fail 'CDI root disk import failed' ;;
      esac
      remaining=$((deadline - SECONDS))
      ((remaining > 0)) || break
      sleep_seconds=$((remaining < 10 ? remaining : 10))
      sleep "$sleep_seconds"
    done
    fail 'CDI root disk import timed out'
    ;;
  cleanup|cleanup-binder)
    [[ $# == 5 ]] || fail 'usage: cleanup VM NAMESPACE RUN_ID REPOSITORY'
    identity "$2" "$3" "$4" "$5"
    kind=root
    resource=pvc
    if [[ $1 == cleanup-binder ]]; then
      kind=binder
      resource=pod
    else
      bash "$0" cleanup-binder "$2" "$3" "$4" "$5"
    fi
    object=$(timeout 30 kubectl -n "$3" get "$resource" "$2-$kind" --ignore-not-found -o json)
    [[ -n $object ]] || exit 0
    owned_root "$object" "$2" "$4" "$5" "$kind" || fail 'refusing to delete an unowned acceptance resource'
    timeout 130 kubectl -n "$3" delete "$resource" "$2-$kind" --ignore-not-found --wait=true --timeout=120s
    ;;
  reap)
    [[ $# == 4 ]] || fail 'usage: reap NAMESPACE CURRENT_RUN_ID REPOSITORY'
    [[ $3 =~ ^[0-9]+$ ]] || fail 'invalid current run'
    roots=$(timeout 30 kubectl -n "$2" get pvc \
      -l ci.confidential.ai/resource=acceptance-root -o json)
    now=$(date -u +%s)
    while IFS= read -r object; do
      name=$(jq -r .metadata.name <<<"$object")
      run=$(jq -r '.metadata.labels["ci.confidential.ai/run-id"]' <<<"$object")
      [[ $run =~ ^[0-9]+$ && $run != "$3" && $name =~ ^c8s-tdx-${run}-[0-9]+-root$ ]] || continue
      vm=${name%-root}
      owned_root "$object" "$vm" "$run" "$4" || continue
      # Root imports can outlive a cancelled run before its VM even exists.
      # Never delete a PVC while any matching VM is still present.
      existing=$(timeout 30 kubectl -n "$2" get vm "$vm" --ignore-not-found -o name) || continue
      [[ -z $existing ]] || continue
      status=$(gh api "repos/$4/actions/runs/$run" --jq .status 2>/dev/null || true)
      created=$(jq -r .metadata.creationTimestamp <<<"$object")
      created_epoch=$(date -u -d "$created" +%s 2>/dev/null) || continue
      if [[ $status == completed ]] || [[ -z $status && $((now - created_epoch)) -gt 10800 ]]; then
        bash "$0" cleanup "$vm" "$2" "$run" "$4"
      fi
    done < <(jq -c '.items[]' <<<"$roots")
    ;;
  *) fail 'expected validate, pvc, binder, start-import, wait, cleanup, cleanup-binder or reap' ;;
esac
