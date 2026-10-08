#!/usr/bin/env bash
# kind backend: the single-node cluster the kind harness leaves up with
#   C8S_IT_KEEP=1 C8S_IT_SETUP_ONLY=1 C8S_IT_WORKDIR=... test/integration/cluster/run.sh
# Everything below delegates to that harness's lib.sh. No TEE: attestation is
# mocked, so a scenario that needs hardware evidence must not pick this backend.
# Interface: common.sh.

: "${C8S_IT_WORKDIR:?the WORKDIR the kept kind cluster wrote}"
PLATFORM="kind (mock attestation)"
# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
# shellcheck disable=SC1091  # written by the harness at run time
. "$C8S_IT_WORKDIR/env"

# The harness provides everything the scenarios assume.
setup() { :; }

# Each function runs in its own process, so the CDS port-forward lib.sh shares
# through WORKDIR outlives the call that opened it.
teardown() { cds_pf_stop; }

node_name() {
    case "$1" in
        one) echo "$NODE" ;;
        *) return $UNSUPPORTED ;;
    esac
}

store_digest() { store_digests | awk -F'\t' -v ref="$1" '$2 == ref {print $1; exit}'; }

# The digest the node's store holds for ref, pulling only when it has none.
image_digest() {
    local digest
    digest="$(store_digest "$1")"
    if [ -z "$digest" ]; then
        node_exec ctr -n k8s.io images pull "$1" >/dev/null
        digest="$(store_digest "$1")"
    fi
    echo "$digest"
}

image_alias() {
    node_exec ctr -n k8s.io images pull "$1" >/dev/null
    node_exec ctr -n k8s.io images tag --force "$1" "$2" >/dev/null
}

served_allowlist() {
    cds_pf_start
    curl -sSfk "https://127.0.0.1:$CDS_LOCAL_PORT/allowlist"
}

enforcer_ready() {
    kubectl -n "$NS" rollout status ds/c8s-nri-image-policy-worker --timeout=120s >/dev/null &&
        node_exec test -S /var/run/nri-image-policy/workload-claims.sock
}

node_containers() { node_exec crictl ps -a -q --image "$2"; }

dispatch "$@"
