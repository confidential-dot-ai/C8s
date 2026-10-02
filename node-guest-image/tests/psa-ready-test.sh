#!/bin/bash
# Root-free tests for the exact production psa-ready.sh. A fake kubectl models
# RKE2 AddOn readiness and admission outcomes; the gate itself is not copied or
# sourced, so changes to its control flow are exercised byte-for-byte.
set -u

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$TESTS_DIR/lib.sh"
SCRIPT=${PSA_READY_SCRIPT:-"$TESTS_DIR/../c8s/mkosi.extra/usr/local/bin/psa-ready.sh"}
[[ -x "$SCRIPT" ]] || { echo "script not found: $SCRIPT"; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAKE_KUBECTL="$WORK/kubectl"
CA_KEY="$WORK/client-ca.key"
KUBECONFIG_FILE="$WORK/rke2.yaml"
touch "$CA_KEY" "$KUBECONFIG_FILE"

cat >"$FAKE_KUBECTL" <<'EOF'
#!/bin/bash
set -u
: "${FAKE_MODE:?}"
: "${FAKE_LOG:?}"

positional=()
ns=
while (( $# > 0 )); do
    case "$1" in
        --kubeconfig|--cache-dir) shift 2 ;;
        --as=*|--as-group=*) shift ;;
        -n) ns=$2; shift 2 ;;
        *) positional+=("$1"); shift ;;
    esac
done
set -- "${positional[@]}"
printf '%s\n' "$*" >>"$FAKE_LOG"

# Guard comparison: replace --dry-run renders the reference copy, get -f the
# live objects. They agree unless a drift mode says otherwise. These are the
# only gets the gate makes: the guards directory is what must be live.
if [[ ${1:-} == replace ]]; then
    [[ $FAKE_MODE == guard-rejected ]] && { echo "error: reference copy rejected" >&2; exit 1; }
    # The write path can carry apiserver warnings; they must not enter the comparison.
    echo "Warning: dry-run warning from admission" >&2
    echo "fields-of-$(basename "$4")"
    exit 0
fi
if [[ ${1:-} == get && ${2:-} == -f ]]; then
    case "$FAKE_MODE:$(basename "$3")" in
        guard-missing:psa-level-policy.yaml) echo "Error from server (NotFound): validatingadmissionpolicies.admissionregistration.k8s.io \"confos-psa-level\" not found" >&2; exit 1 ;;
        guard-drift:operator-scope-policy.yaml) echo "fields-of-tampered"; exit 0 ;;
    esac
    echo "fields-of-$(basename "$3")"
    exit 0
fi

if [[ ${1:-} == get && ${2:-} == felixconfigurations.crd.projectcalico.org ]]; then
    case "$FAKE_MODE" in
        felix-unreadable) echo "error: the server doesn't have a resource type \"felixconfigurations\"" >&2; exit 1 ;;
        felix-missing) printf 'node.n1=\n' ;;
        felix-insert) printf 'default=Insert\n' ;;
        felix-node-override) printf 'default=Append\nnode.n1=Insert\n' ;;
        *) printf 'default=Append\nnode.n1=\n' ;;
    esac
    exit 0
fi

if [[ ${1:-} == apply ]]; then
    cat >/dev/null
    [[ $FAKE_MODE != rbac-failure ]]
    exit
fi

if [[ ${1:-} == create ]]; then
    body=$(cat)
    if grep -q 'kind: ConfigMap' <<<"$body"; then
        scope_denial="Error from server (Invalid): ValidatingAdmissionPolicy 'confos-operator-scope' denied the request: c8s credentials may not write in the privileged namespaces (kube-system, local-path-storage, c8s-system)"
        case "$FAKE_MODE:$ns" in
            scope-fail-open:*) exit 0 ;;
            scope-over-denied:default) echo "$scope_denial" >&2; exit 1 ;;
            scope-wrong-denial:kube-system) echo "Error from server (Forbidden): denied by some-other-policy" >&2; exit 1 ;;
            *:kube-system) echo "$scope_denial" >&2; exit 1 ;;
            *) exit 0 ;;
        esac
    fi
    if grep -q 'enforce: privileged' <<<"$body"; then
        case "$FAKE_MODE" in
            wrong-denial)
                echo "Error from server (Forbidden): denied by some-other-policy" >&2
                exit 1
                ;;
            fail-open) exit 0 ;;
            *)
                echo "Error from server (Invalid): ValidatingAdmissionPolicy 'confos-psa-level' denied the request: pod-security.kubernetes.io/enforce may not be set below restricted" >&2
                exit 1
                ;;
        esac
    fi
    if [[ $FAKE_MODE == restricted-denied ]]; then
        echo "Error from server (Forbidden): restricted probe denied" >&2
        exit 1
    fi
    exit 0
fi

# Cleanup deletes are deliberately successful and logged.
if [[ ${1:-} == delete ]]; then
    exit 0
fi
exit 2
EOF
chmod +x "$FAKE_KUBECTL"

# The reference copies psa-ready.sh waits for and compares: the locked
# build's five guards, the dev build's four (mkosi.sync leaves the skipped
# pod-exec AddOn out), and an empty directory.
GUARDS="$WORK/guards"
DEV_GUARDS="$WORK/guards-dev"
EMPTY_GUARDS="$WORK/guards-empty"
mkdir -p "$GUARDS" "$DEV_GUARDS" "$EMPTY_GUARDS"
for g in psa-level-policy pod-exec-policy operator-scope-policy cred-release-rbac log-reader-rbac; do
    echo "kind: reference" >"$GUARDS/$g.yaml"
    [[ $g == pod-exec-policy ]] || echo "kind: reference" >"$DEV_GUARDS/$g.yaml"
done
guard_count=$(ls "$GUARDS"/*.yaml | wc -l | tr -d ' ')

run_gate() {
    local mode=$1 guards=$GUARDS
    [[ $mode == *-dev ]] && guards=$DEV_GUARDS
    [[ $mode == guard-none ]] && guards=$EMPTY_GUARDS
    : >"$WORK/log"
    : >"$WORK/stdout"
    : >"$WORK/stderr"
    FAKE_MODE="$mode" FAKE_LOG="$WORK/log" \
        KUBECTL="$FAKE_KUBECTL" KUBECONFIG="$KUBECONFIG_FILE" \
        KUBECTL_CACHE_DIR="$WORK/cache" CLIENT_CA_KEY="$CA_KEY" \
        GUARDS_DIR="$guards" \
        PSA_WAIT_ATTEMPTS=2 PSA_WAIT_SECONDS=0 \
        "$SCRIPT" >"$WORK/stdout" 2>"$WORK/stderr"
}

CASE="enforced policy"
ok "passes both live probes" run_gate enforced
ok "reports enforcement" grep -q 'is enforcing the restricted namespace floor' "$WORK/stdout"
ok "reports operator scope" grep -q 'confos-operator-scope is enforcing the operator scope' "$WORK/stdout"
ok "reports guard match" grep -q 'live guards match' "$WORK/stdout"
ok "renders every reference copy server-side" [ "$(grep -c '^replace --dry-run=server -f ' "$WORK/log")" = "$guard_count" ]
ok "fetches the live objects of every guard" [ "$(grep -c '^get -f ' "$WORK/log")" = "$guard_count" ]
ok "waits on nothing but the guards and Felix's chain mode" not grep -Ev '^get (-f|felixconfigurations\.crd\.projectcalico\.org) ' <(grep '^get ' "$WORK/log")
ok "reports Felix append mode" grep -q 'Felix appends behind ratls-mesh' "$WORK/stdout"
ok "cleans the probe binding" grep -q '^delete clusterrolebinding confos-psa-readiness-probe ' "$WORK/log"
ok "cleans the probe role" grep -q '^delete clusterrole confos-psa-readiness-probe ' "$WORK/log"

CASE="a live guard differs from its read-only copy"
ok "fails closed" not run_gate guard-drift
ok "names the drifted guard and both renderings" stderr_has 'guard operator-scope-policy: live objects differ from the read-only reference copy (live: fields-of-tampered; reference: fields-of-operator-scope-policy.yaml)'

CASE="AddOn absent"
ok "fails closed" not run_gate guard-missing
ok "names the guard and the missing object" stderr_has 'guard psa-level-policy: live objects are not all present: .*confos-psa-level.*not found'
ok "checks presence before rendering the reference copy" not grep -q '^replace --dry-run=server -f .*psa-level-policy.yaml' "$WORK/log"
ok "never probes admission" not grep -q '^create ' "$WORK/log"

CASE="the reference copy is not admitted"
ok "fails closed" not run_gate guard-rejected
ok "names the rejected copy" stderr_has 'reference copy is not admitted by the apiserver'

CASE="no reference copies at all"
ok "fails closed" not run_gate guard-none
ok "names the empty directory" stderr_has 'no guard reference copies in'

CASE="pod-exec guard left out by the dev build"
ok "passes without it" run_gate enforced-dev
ok "never renders it" not grep -q 'pod-exec-policy.yaml' "$WORK/log"

CASE="operator-scope policy fail-open"
ok "fails closed" not run_gate scope-fail-open
ok "names the admitted kube-system write" stderr_has 'dry-run in kube-system was admitted'

CASE="operator-scope over-denies tenant namespaces"
ok "fails closed" not run_gate scope-over-denied
ok "names the broken allow path" stderr_has 'dry-run in default was denied'

CASE="operator-scope denied by the wrong guard"
ok "fails closed" not run_gate scope-wrong-denial
ok "does not mistake an arbitrary denial for readiness" stderr_has 'kube-system was denied by a different guard'

CASE="binding present but policy fail-open"
ok "fails closed" not run_gate fail-open
ok "names the admitted privileged probe" stderr_has 'privileged namespace dry-run was admitted'

CASE="denied by the wrong guard"
ok "fails closed" not run_gate wrong-denial
ok "does not mistake an arbitrary denial for readiness" stderr_has 'denied by a different guard'

CASE="restricted request is over-denied"
ok "fails closed" not run_gate restricted-denied
ok "names the broken allow path" stderr_has 'restricted namespace dry-run was denied'

CASE="temporary RBAC cannot be installed"
ok "fails closed" not run_gate rbac-failure
ok "names the RBAC failure" stderr_has 'could not install the temporary readiness-probe RBAC'

CASE="FelixConfiguration CRD not installed yet"
ok "fails closed" not run_gate felix-unreadable
ok "names the unreadable configs" stderr_has 'FelixConfigurations are not readable'

CASE="no global FelixConfiguration"
ok "fails closed" not run_gate felix-missing
ok "names the missing Append" stderr_has 'default does not set chainInsertMode: Append'

CASE="Felix still inserting"
ok "fails closed" not run_gate felix-insert
ok "names the live mode" stderr_has 'live: default=Insert'

CASE="a per-node FelixConfiguration overrides the mode"
ok "fails closed" not run_gate felix-node-override
ok "names the override" stderr_has 'overrides chainInsertMode: node.n1=Insert'

summarize "psa-ready"
