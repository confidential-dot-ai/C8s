#!/bin/sh
# Gate attested credential release on the live guards: the PodSecurity
# invariant, the operator-scope policy that keeps cred-release credentials
# away from the guards themselves, the pod-exec policy, and the two RBAC
# bindings the issued groups rely on. RKE2 reconciles server/manifests
# asynchronously after kube-apiserver is ready, so object presence is not
# enough: prove that every live guard equals its reference copy on the
# read-only root (server/manifests is on the writable overlay), then prove
# the allow and deny paths through the real admission chain, before
# cred-release starts listening.
set -eu

KUBECTL=${KUBECTL:-/var/lib/rancher/rke2/bin/kubectl}
KUBECONFIG=${KUBECONFIG:-/etc/rancher/rke2/rke2.yaml}
KUBECTL_CACHE_DIR=${KUBECTL_CACHE_DIR:-/run/cred-release/kubecache}
CLIENT_CA_KEY=${CLIENT_CA_KEY:-/var/lib/rancher/rke2/server/tls/client-ca.key}
# Reference copies of the guard AddOns, staged by mkosi.sync onto the
# read-only root. This directory is the single statement of what must be
# live: every file here is waited for and compared against the live objects
# (the C8S_DEV=1 build leaves the skipped pod-exec AddOn out of it).
GUARDS_DIR=${GUARDS_DIR:-/usr/lib/confai/guards}
PSA_WAIT_ATTEMPTS=${PSA_WAIT_ATTEMPTS:-120}
PSA_WAIT_SECONDS=${PSA_WAIT_SECONDS:-5}

policy=confos-psa-level
scope_policy=confos-operator-scope
operator_group=c8s:node-operators
probe=confos-psa-readiness-probe
probe_user=confos:psa-readiness-probe
expected_message='pod-security.kubernetes.io/enforce may not be set below restricted'
expected_scope_message='may not write in the privileged namespaces'

fail() {
    echo "psa-ready: $1" >&2
    exit 1
}

case "$PSA_WAIT_ATTEMPTS" in
    ''|*[!0-9]*|0) fail "PSA_WAIT_ATTEMPTS must be a positive integer" ;;
esac
case "$PSA_WAIT_SECONDS" in
    ''|*[!0-9]*) fail "PSA_WAIT_SECONDS must be a non-negative integer" ;;
esac

mkdir -p "$KUBECTL_CACHE_DIR"
k() {
    "$KUBECTL" --kubeconfig "$KUBECONFIG" --cache-dir "$KUBECTL_CACHE_DIR" "$@"
}

cleanup() {
    k delete clusterrolebinding "$probe" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    k delete clusterrole "$probe" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

rbac_installed=
install_probe_rbac() {
    [ -n "$rbac_installed" ] && return 0
    k apply -f - >/dev/null <<EOT && rbac_installed=1
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: $probe
rules:
  - apiGroups: [""]
    resources: ["namespaces", "configmaps"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: $probe
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: $probe
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: $probe_user
EOT
}

# The fields that make a guard a guard, rendered identically for a live
# object and for the reference file: the spec (VAP and binding), rules,
# roleRef and subjects (RBAC); absent fields print the same placeholder on
# both sides. `get -f` fetches the objects the file names (a missing one
# fails the get) and, for a multi-document file, prints them as one v1 List,
# while `replace --dry-run=server` returns the file exactly as the apiserver
# would store it (defaults applied, nothing retained from the live object)
# and prints each object on its own — so the template walks .items when
# present. The two sides then differ only when a live object differs from
# the file. Presence is checked first because replace reports an absent
# object as NotFound too, which would read as a rejected reference copy.
# stderr stays out of the compared strings: warnings (admission Warn
# actions, deprecations) reach only the write path.
guard_fields='{{define "g"}}{{.spec}}{{.rules}}{{.roleRef}}{{.subjects}}{{"\n"}}{{end}}{{if .items}}{{range .items}}{{template "g" .}}{{end}}{{else}}{{template "g" .}}{{end}}'
guard_err=$KUBECTL_CACHE_DIR/psa-ready-guard.err
guards_match() {
    for file in "$GUARDS_DIR"/*.yaml; do
        [ -e "$file" ] || { last_error="no guard reference copies in $GUARDS_DIR"; return 1; }
        name=$(basename "$file" .yaml)
        if ! live=$(k get -f "$file" -o go-template="$guard_fields" 2>"$guard_err"); then
            last_error="guard $name: live objects are not all present: $(cat "$guard_err")"
            return 1
        fi
        if ! expected=$(k replace --dry-run=server -f "$file" -o go-template="$guard_fields" 2>"$guard_err"); then
            last_error="guard $name: reference copy is not admitted by the apiserver: $(cat "$guard_err")"
            return 1
        fi
        if [ "$live" != "$expected" ]; then
            last_error="guard $name: live objects differ from the read-only reference copy (live: $live; reference: $expected)"
            return 1
        fi
    done
    return 0
}

probe_namespace() {
    level=$1
    k --as="$probe_user" create --dry-run=server -f - <<EOT
apiVersion: v1
kind: Namespace
metadata:
  name: $probe-$level
  labels:
    pod-security.kubernetes.io/enforce: $level
    pod-security.kubernetes.io/enforce-version: latest
EOT
}

# The PodSecurity floor through the real admission chain: a restricted
# namespace is admitted and a privileged one is denied by $policy with its
# own validation message, never by some other guard.
psa_enforcing() {
    if ! restricted_out=$(probe_namespace restricted 2>&1); then
        last_error="restricted namespace dry-run was denied: $restricted_out"
        return 1
    fi
    if privileged_out=$(probe_namespace privileged 2>&1); then
        last_error="privileged namespace dry-run was admitted"
        return 1
    fi
    case "$privileged_out" in
        *"$policy"*"$expected_message"*) return 0 ;;
        *"$policy"*) last_error="privileged namespace was denied by $policy without its expected validation message" ;;
        *) last_error="privileged namespace was denied by a different guard: $privileged_out" ;;
    esac
    return 1
}

# A ConfigMap create in the given namespace, as the probe user carrying the
# operator group: RBAC admits it (the probe role above), so a denial can only
# come from admission.
probe_scope() {
    ns=$1
    k --as="$probe_user" --as-group="$operator_group" -n "$ns" create --dry-run=server -f - <<EOT
apiVersion: v1
kind: ConfigMap
metadata:
  name: $probe
EOT
}

# The operator scope through the real admission chain: the operator group
# may write in a tenant namespace and is denied in a privileged one
# by $scope_policy with its own message.
scope_enforcing() {
    if ! scope_allow_out=$(probe_scope default 2>&1); then
        last_error="operator-scoped configmap dry-run in default was denied: $scope_allow_out"
        return 1
    fi
    if scope_deny_out=$(probe_scope kube-system 2>&1); then
        last_error="operator-scoped configmap dry-run in kube-system was admitted"
        return 1
    fi
    case "$scope_deny_out" in
        *"$scope_policy"*"$expected_scope_message"*) return 0 ;;
        *) last_error="operator-scoped configmap dry-run in kube-system was denied by a different guard: $scope_deny_out" ;;
    esac
    return 1
}

last_error='the API server is not ready'
attempt=1
while [ "$attempt" -le "$PSA_WAIT_ATTEMPTS" ]; do
    if [ ! -r "$CLIENT_CA_KEY" ]; then
        last_error="client CA key is not readable"
    elif ! guards_match; then
        : # last_error set by guards_match
    elif ! install_probe_rbac; then
        last_error="could not install the temporary readiness-probe RBAC"
    elif ! psa_enforcing; then
        : # last_error set by psa_enforcing
    elif ! scope_enforcing; then
        : # last_error set by scope_enforcing
    else
        echo "psa-ready: $policy is enforcing the restricted namespace floor; $scope_policy is enforcing the operator scope; live guards match $GUARDS_DIR"
        exit 0
    fi

    if [ "$attempt" -lt "$PSA_WAIT_ATTEMPTS" ]; then
        sleep "$PSA_WAIT_SECONDS"
    fi
    attempt=$((attempt + 1))
done

fail "timed out waiting for enforced PodSecurity admission: $last_error"
