#!/usr/bin/env bash
# Live-cluster check that image admission is fail-closed and that a signed
# allowlist write opens it: a non-allowlisted image is denied at container
# creation, and the same image runs once its digest is on the floor.
#
# Needs kubectl pointed at a cluster with C8s installed, `c8s` and `crane` on
# PATH, and:
#   C8S_ALLOWLIST_URL  armTLS router or direct CDS base URL
#   C8S_MEASUREMENTS_CONFIG complete endpoint image/operator policy (preferred)
#   C8S_MEASUREMENTS   legacy launch-only pin, when no policy file is supplied
#   C8S_OPERATOR_KEY   path to the operator EC key PEM pinned on CDS
set -euo pipefail
. "$(dirname "$0")/lib.sh"

: "${C8S_ALLOWLIST_URL:?names the armTLS CDS or router endpoint}"
cds_measurement_args
: "${C8S_OPERATOR_KEY:?path to the operator EC key PEM}"

# The node image enforces the restricted PodSecurity standard in `default`,
# so the probe declares a restricted-compliant securityContext and a denial
# here is the image floor and not PodSecurity.
ns=default
pod=allowlist-probe
image=busybox:1.36

al() { c8s allowlist "$@" --url "$C8S_ALLOWLIST_URL" "${measurement_args[@]}"; }

probe() {
  kubectl -n "$ns" run "$pod" --image="$image" --restart=Never \
    --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65534,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"'"$pod"'","image":"'"$image"'","command":["sleep","300"],"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}' \
    >/dev/null
}

digest=""
cleanup() {
  kubectl -n "$ns" delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  # `allowlist add` names the entry "<basename>-<first 12 hex of digest>".
  [ -n "$digest" ] && al delete "busybox-$(printf '%s' "${digest#sha256:}" | cut -c1-12)" >/dev/null 2>&1
  return 0
}
trap cleanup EXIT

digest=$(c8s allowlist inspect-image "$image" | awk '$1 == "digest:" { print $2 }')
[ -n "$digest" ] || fail "no digest resolved for $image"

probe
denied=""
for _ in $(seq 1 60); do
  msg=$(kubectl -n "$ns" get pod "$pod" \
    -o jsonpath='{.status.containerStatuses[0].state.waiting.message}' 2>/dev/null || true)
  case "$msg" in *"image not in allowlist"*) denied=1; break ;; esac
  sleep 2
done
if [ -z "$denied" ]; then
  kubectl -n "$ns" describe pod "$pod" | tail -20
  fail "SECURITY REGRESSION: $image was admitted without being allowlisted;" \
       "the image floor is not fail-closed (waiting message: ${msg:-none})"
fi
echo "ok: $image denied at container creation"

al add "$digest" "$image" >/dev/null || fail "signed floor write rejected for $digest"
echo "ok: signed floor write accepted"

# Recreated rather than waited out: the plugin re-pulls every 5s, while
# kubelet's CreateContainerError backoff reaches minutes.
kubectl -n "$ns" delete pod "$pod" --wait=true --timeout=60s >/dev/null
probe
if ! kubectl -n "$ns" wait --for=condition=Ready "pod/$pod" --timeout=120s >/dev/null; then
  kubectl -n "$ns" describe pod "$pod" | tail -20
  fail "$image still blocked after its digest was allowlisted"
fi
echo "ok: allowlisted image admitted"

echo "PASS: image floor is fail-closed and a signed write opens it"
