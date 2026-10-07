#!/usr/bin/env bash
# Shared state and helpers for the kind cluster harness. run.sh sources it,
# and so can anything driving a cluster run.sh left up (C8S_IT_KEEP=1): source
# this file, then "$C8S_IT_WORKDIR/env" (which exports its KUBECONFIG), and
# the helpers below address that cluster. Callers set WORKDIR, and NODE / NODE_IP once the cluster exists.

CLUSTER_HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CLUSTER="${C8S_IT_CLUSTER:-c8s-it}"
# kind v0.33.0's Kubernetes 1.34 image, pinned by digest. Its containerd
# includes NRI adjustment validation, required for env enforcement.
NODE_IMAGE="${C8S_IT_NODE_IMAGE:-kindest/node:v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d}"
IMAGE_TAG=it
NS=c8s-system
CDS_LOCAL_PORT=18443
# The mock attestation-api's synthetic launch digest (all zero). Pinned into
# cds.measurements / ratlsMesh.measurements so every RA-TLS hop is verified
# against it, exactly as a pinned production measurement.
MOCK_MEASUREMENT="000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
# Test-client and workload images. The workload image joins the install-time
# floor; the test-client image stays out of it so the admission test can
# drive a deny-then-allow transition through the signed CDS API.
CURL_IMAGE=curlimages/curl:8.10.1
WORKLOAD_IMAGE=nginxinc/nginx-unprivileged@sha256:3af0c10d960cc2502427fe1219c52989d309e7d65596869c60a34fd2fa2406f0

# Keep live client Pods and the admission regression tests on the same renderer.
pod_fixture() {
    local mode="$1" name="$2" ns="$3"
    shift 3
    python3 "$CLUSTER_HARNESS_DIR/pod-fixture.py" "$mode" "$name" "$ns" "$CURL_IMAGE" -- "$@"
}

NODE="${NODE:-}"  # kind node container name, resolved after cluster creation
NODE_IP="${NODE_IP:-}"

log() { echo ""; echo "=== $* ==="; }

diagnostics() {
    echo "--- cluster state (diagnostics) ---"
    kubectl get pods -A -o wide 2>&1 || true
    kubectl -n "$NS" logs deploy/c8s-cds --tail=40 2>&1 || true
    kubectl -n "$NS" logs deploy/c8s-operator --tail=40 2>&1 || true
    kubectl -n "$NS" logs ds/c8s-nri-image-policy-worker -c install --tail=80 2>&1 || true
    if [ -n "$NODE" ]; then
        node_exec journalctl -u containerd --no-pager -n 100 2>&1 || true
    fi
    mesh_diagnostics
}

# The mesh assertions are counter and membership claims, and neither survives
# into the log otherwise: a failed one leaves no way to tell a stale ipset from
# a rule that never fired from a workload reached in plaintext.
mesh_pod() { kubectl -n "$NS" get pod -l app=c8s-ratls-mesh -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true; }

mesh_diagnostics() {
    local pod
    pod="$(mesh_pod)"
    [ -n "$pod" ] || return 0
    echo "--- ratls-mesh counters ---"
    kubectl -n "$NS" exec "$pod" -c iptables-sync -- \
        sh -c 'cat /tmp/ratls-iptables-metrics.json' 2>&1 || true
    echo "--- cw guard chains and ipsets ---"
    for chain in RATLS-MESH-CW RATLS-MESH-CW-EGRESS; do
        kubectl -n "$NS" exec "$pod" -c iptables-sync -- iptables -L "$chain" -n -v -x 2>&1 || true
    done
    kubectl -n "$NS" exec "$pod" -c iptables-sync -- iptables -L FORWARD -n --line-numbers 2>&1 | head -12 || true
    for set in RATLS-MESH-CW-PODS RATLS-MESH-PODS RATLS-MESH-LOCAL-PODS; do
        kubectl -n "$NS" exec "$pod" -c iptables-sync -- ipset list "$set" 2>&1 | head -20 || true
    done
}

fail() {
    echo "FAIL: $*" >&2
    diagnostics
    exit 1
}

CHECKS=0
pass() {
    CHECKS=$((CHECKS + 1))
    echo "PASS: $*"
}

node_exec() { docker exec "$NODE" "$@"; }

# store_digests prints "digest<TAB>ref" for every real image reference in the
# node containerd's k8s.io store, one per (digest, ref) pair.
store_digests() {
    node_exec ctr -n k8s.io images ls | awk 'NR > 1 && $1 !~ /^sha256:/ {print $3 "\t" $1}'
}

# --- CDS API helpers ---

cds_healthy() { curl -sSk "https://127.0.0.1:$CDS_LOCAL_PORT/healthz" >/dev/null 2>&1; }

# cds_pf_start opens the CDS port-forward, or reuses the one this WORKDIR
# opened (its pid file), so drivers running each helper in its own process
# share one.
cds_pf_start() {
    local pid
    pid="$(cat "$WORKDIR/cds-pf.pid" 2>/dev/null || true)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && cds_healthy && return 0
    kubectl -n "$NS" port-forward svc/c8s-cds "$CDS_LOCAL_PORT:8443" >/dev/null 2>&1 &
    echo "$!" > "$WORKDIR/cds-pf.pid"
    for _ in $(seq 1 30); do
        cds_healthy && return 0
        sleep 1
    done
    fail "CDS port-forward never came up"
}

cds_pf_stop() {
    local pid
    pid="$(cat "$WORKDIR/cds-pf.pid" 2>/dev/null || true)"
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    rm -f "$WORKDIR/cds-pf.pid"
}

# any_workload <digest> <image>: print a workload entry that admits the digest
# under any command line and mounts, the body of PUT /allowlist/workloads/<name>.
any_workload() {
    printf '{"label":"%s","initContainers":[],"containers":[{"digest":"%s","image":"%s","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"}}]}' \
        "$2" "$1" "$2"
}

# cds_write <method> <path> <body-file> -> http code; signed with the operator key.
cds_write() {
    local method="$1" path="$2" bodyfile="$3" token
    cds_pf_start
    token="$("$WORKDIR/optoken" "$WORKDIR/operator.key" "$method" "$path" "$bodyfile")"
    # Always exit 0: curl prints 000 on transport failure, and callers assert
    # on the code itself.
    curl -sSk -o /dev/null -w '%{http_code}' -X "$method" \
        -H "Authorization: $token" -H 'Content-Type: application/json' \
        --data-binary "@$bodyfile" "https://127.0.0.1:$CDS_LOCAL_PORT$path" || true
}

# run_pod <ns> <name> <shell command>: run a curl-image pod to completion and
# print its stdout. Exit status is swallowed; callers assert on the output, so
# reachable (200) and dropped (rc=28) outcomes are both observable. Only for
# calls whose routing does not depend on the caller's pod IP (metrics scrapes
# dial the node, which the mesh never intercepts).
run_pod() {
    local ns="$1" name="$2" cmd="$3" phase
    kubectl delete pod "$name" -n "$ns" --ignore-not-found >/dev/null 2>&1 || true
    pod_fixture client "$name" "$ns" sh -c "$cmd" | kubectl apply -f - >/dev/null
    for _ in $(seq 1 60); do
        phase="$(kubectl get pod "$name" -n "$ns" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
        case "$phase" in Succeeded|Failed) break ;; esac
        sleep 2
    done
    kubectl logs "$name" -n "$ns" 2>/dev/null || true
    kubectl delete pod "$name" -n "$ns" --ignore-not-found >/dev/null 2>&1 || true
}

# mesh_metric <pattern>: sum the matching series of the node's ratls-mesh
# /metrics (hostNetwork). A missing series reads as 0.
mesh_metric() {
    run_pod default it-mesh-metrics "curl -sf --max-time 10 http://$NODE_IP:15021/metrics" \
        | awk -v pat="$1" '$0 ~ pat {sum += $NF} END {print sum+0}'
}

# await_metric_above <pattern> <baseline> <what>
await_metric_above() {
    local pattern="$1" baseline="$2" what="$3" v
    for _ in $(seq 1 18); do
        v="$(mesh_metric "$pattern")"
        [ "${v:-0}" -gt "$baseline" ] && return 0
        sleep 5
    done
    fail "$what: no increase above baseline $baseline within 90s"
}

# await_ipset <set> <ip>: the mesh syncs pod IPs into its ipsets on a ~30s
# tick; dialing before the client pod lands in RATLS-MESH-LOCAL-PODS bypasses
# interception entirely, so gate every mesh assertion on membership. The kind
# node has no ipset CLI; the mesh's iptables-sync container does and shares
# the node's network namespace.
MESH_POD=""
await_ipset() {
    local set="$1" ip="$2"
    if [ -z "$MESH_POD" ]; then
        MESH_POD="$(mesh_pod)"
        [ -n "$MESH_POD" ] || fail "ratls-mesh pod not found"
    fi
    for _ in $(seq 1 18); do
        kubectl -n "$NS" exec "$MESH_POD" -c iptables-sync -- ipset test "$set" "$ip" 2>/dev/null && return 0
        sleep 5
    done
    fail "$ip never appeared in ipset $set"
}
