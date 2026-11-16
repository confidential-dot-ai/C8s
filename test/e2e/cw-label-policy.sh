#!/usr/bin/env bash
# Live-cluster verification of the pod validator's cw-label check
# (internal/webhook). Proves on a real API server what the unit tests cannot:
# the fail-closed webhook actually answers (a broken one would deny ALL pod
# writes in covered namespaces), a label without its annotation is denied on
# CREATE and on UPDATE, and ordinary pods are unaffected.
#
# Needs: kubectl pointed at a cluster with the C8s chart installed.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ns="cw-label-policy-check-$$"
pod=probe
pause_image=registry.k8s.io/pause:3.9

# kubectl run's generated pod is otherwise root/default-seccomp, which the
# Restricted policy correctly rejects. Keep every probe compliant so only the
# intended guard decides it.
restricted_overrides() {
  local name=$1 image=$2
  printf '{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65534,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"%s","image":"%s","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}' "$name" "$image"
}

cleanup() {
  if cw_namespace_owned "$ns"; then
    kubectl delete namespace "$ns" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# expect_deny <description> <expected-substring> -- <command...>
# Runs the command, requires it to be denied, and requires the denial message
# to contain <expected-substring> so the check proves which invariant fired,
# not merely that some admission plugin objected.
expect_deny() {
  (( $# >= 3 )) || fail "expect_deny: usage: expect_deny <description> <expected-substring> -- <command...>"
  [[ $3 == -- ]] || fail "expect_deny: expected '--' before the command, got '$3'"
  local what=$1 want=$2
  shift 3
  (( $# > 0 )) || fail "expect_deny: missing command after '--'"
  local out
  if out=$("$@" 2>&1); then
    fail "$what was admitted; want denial matching '$want'. output: $out"
  fi
  grep -q "$want" <<<"$out" \
    || fail "$what was denied, but not by the expected guard (want '$want'): $out"
  echo "ok: $what denied"
}

cw_namespace "$ns"

# Ordinary pod admission must be unaffected. This is also the canary for a
# broken CEL expression: failurePolicy=Fail turns one into a deny-all.
# Report the admission error verbatim: this control cannot tell which admitter
# refused, and guessing sent one investigation after a healthy CEL.
if ! err=$(kubectl run "$pod" --namespace "$ns" --image="$pause_image" \
  --restart=Never --overrides="$(restricted_overrides "$pod" "$pause_image")" 2>&1); then
  fail "plain pod creation was denied: ${err}"
fi
echo "ok: plain pod admitted"

# Out-of-band writes on a running pod: the validating webhook covers UPDATE,
# so a label that no longer matches its annotation is refused there too.
expect_deny "post-create cw label" "must match" -- \
  kubectl label pod "$pod" --namespace "$ns" confidential.ai/cw=spoof

# CREATE with the label but no matching annotation: the validating webhook
# refuses it. --dry-run=server still runs admission.
expect_deny "pod created with cw label but no annotation" \
  "must match the confidential.ai/cw annotation" -- \
  kubectl run spoof --namespace "$ns" --image="$pause_image" \
    --restart=Never --labels=confidential.ai/cw=spoof --dry-run=server \
    --overrides="$(restricted_overrides spoof "$pause_image")"

# A pod that smuggles its own container under the reserved c8s-cert name to
# shadow the injected sidecar is denied by the webhook's reserved-name guard
# (rejectReservedResources), before the pod is ever mutated.
reserved_manifest=$(mktemp)
cat >"$reserved_manifest" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: reserved-name
  namespace: $ns
  annotations:
    confidential.ai/cw: spoof
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: $pause_image
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
    - name: c8s-cert
      image: $pause_image
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
YAML
expect_deny "cw pod smuggling a reserved c8s-cert container" \
  "reserved" -- \
  kubectl apply --dry-run=server -f "$reserved_manifest"
rm -f "$reserved_manifest"

# Canary: a legitimate cw pod created through the webhook is admitted — the
# webhook injects the c8s-cert sidecar and the matching label, satisfying the
# sidecar-presence VAP rule. A broken hasCertSidecar CEL would deny every cw
# pod, so this proves the new rule does not over-deny.
kubectl run cw-ok --namespace "$ns" --image="$pause_image" \
  --restart=Never --annotations=confidential.ai/cw=cwok --dry-run=server \
  --overrides="$(restricted_overrides cw-ok "$pause_image")" >/dev/null \
  || fail "a webhook-injected cw pod was denied; the sidecar-presence VAP or webhook is misfiring"
echo "ok: webhook-injected cw pod admitted"

echo "PASS: cw-label integrity policy enforced"
