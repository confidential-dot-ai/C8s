#!/usr/bin/env bash
# Live-cluster check that a confidential workload runs bound to CDS: the sample
# cw deployment reaches Ready and carries the injected c8s-cert sidecar.
#
# Needs kubectl pointed at a cluster with C8s installed. Under fail-closed image
# admission the workload digest must be allowlisted first: set C8S_OPERATOR_KEY
# with C8S_ALLOWLIST_URL and C8S_MEASUREMENTS_CONFIG (or C8S_MEASUREMENTS)
# and this applies an entry for it.
# Audit mode admits it without them.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

manifest="$(dirname "$0")/../../samples/nginx-confidential-pod.yaml"
[ -f "$manifest" ] || fail "sample manifest not found at $manifest"

ns=c8s-e2e-cw
deploy=demo-nginx

# A failed workload is left standing for the caller to diagnose.
cleanup() {
  local rc=$?
  [ "$rc" -eq 0 ] || return 0
  if cw_namespace_owned "$ns"; then
    kubectl delete namespace "$ns" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
cw_namespace "$ns"

image=$(grep -oE '[[:graph:]]+@sha256:[0-9a-f]{64}' "$manifest" | head -1)
[ -n "$image" ] || fail "no digest-pinned image in $manifest"

if [ -n "${C8S_OPERATOR_KEY:-}" ]; then
  : "${C8S_ALLOWLIST_URL:?needed alongside C8S_OPERATOR_KEY}"
  cds_measurement_args
  c8s allowlist add "${image#*@}" "$image" \
    --url "$C8S_ALLOWLIST_URL" "${measurement_args[@]}" >/dev/null \
    || fail "signed allowlist write rejected for the workload digest"
  echo "ok: workload digest admitted"
fi

kubectl -n "$ns" apply -f "$manifest" >/dev/null

ready=""
for _ in $(seq 1 60); do
  have=$(kubectl -n "$ns" get deploy "$deploy" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)
  if [ "${have:-0}" -ge 1 ]; then ready=1; break; fi
  sleep 10
done
if [ -z "$ready" ]; then
  kubectl -n "$ns" describe pods -l "app=$deploy" | tail -30
  fail "$deploy never became Ready"
fi
echo "ok: $deploy Ready"

names=$(kubectl -n "$ns" get pods -l "app=$deploy" \
  -o jsonpath='{.items[0].spec.initContainers[*].name}' 2>/dev/null || true)
case "$names" in
  *c8s-cert*) ;;
  *) fail "the webhook did not inject the c8s-cert sidecar (init containers: ${names:-none})" ;;
esac
echo "ok: c8s-cert sidecar injected"

echo "PASS: confidential workload runs with a CDS-issued cert"
