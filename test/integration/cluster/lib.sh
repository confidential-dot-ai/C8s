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
# The namespace whose pods serve the router's own ports. A fixed name: the
# measured mesh policy carries it (internal/helmchart.RouterNamespace).
ROUTER_NS=c8s-router
CDS_LOCAL_PORT=18443
ADOPTED_LOCAL_PORT=18445
# The router's default router.san, which `c8s install --upstream` makes the
# route manifest's host.
ROUTER_HOST="c8s-router.$ROUTER_NS.svc"
# The mock attestation-api's synthetic launch digest (all zero). Pinned into
# cds.measurements so every armTLS hop is verified
# against it, exactly as a pinned production measurement.
MOCK_MEASUREMENT="000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
# Its Deployment (manifests/mock-attestation.yaml) and the node address every
# component dials it at.
MOCK_ATTESTATION_NS=kube-system
MOCK_ATTESTATION_NAME=mock-attestation
mock_attestation_url() { echo "http://$NODE_IP:8400"; }
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

# front_door_pod <name> <namespace> <ca-configmap> <url>: a curl Pod that
# verifies the front door against the mesh CA in that ConfigMap.
front_door_pod() {
    python3 "$CLUSTER_HARNESS_DIR/pod-fixture.py" front-door "$1" "$2" "$CURL_IMAGE" \
        --ca-configmap "$3" -- curl -sS --cacert /ca/ca.pem "$4"
}

NODE="${NODE:-}"  # kind node container name, resolved after cluster creation
NODE_IP="${NODE_IP:-}"

log() { echo ""; echo "=== $* ==="; }

diagnostics() {
    echo "--- cluster state (diagnostics) ---"
    kubectl get pods -A -o wide 2>&1 || true
    kubectl get events -A --sort-by=.lastTimestamp 2>&1 | tail -40 || true
    kubectl -n "$ROUTER_NS" describe pods 2>&1 | tail -60 || true
    kubectl -n "$ROUTER_NS" get pods -o json 2>&1 || true
    kubectl -n "$ROUTER_NS" logs deploy/c8s-router -c cds-attest --tail=40 2>&1 || true
    kubectl -n "$NS" logs deploy/c8s-cds --tail=40 2>&1 || true
    kubectl -n "$NS" logs deploy/c8s-operator --tail=40 2>&1 || true
    kubectl -n "$NS" logs ds/c8s-nri-image-policy-worker -c install --tail=80 2>&1 || true
    if [ -n "$NODE" ]; then
        node_exec journalctl -u containerd --no-pager -n 100 2>&1 || true
        node_exec cat /etc/nri/conf.d/image-policy.yaml 2>&1 || true
        node_exec sh -c 'for id in $(crictl ps --name cds-attest -q); do crictl inspect "$id"; done' 2>&1 || true
        node_exec sh -c 'for p in /var/lib/kubelet/pods/*/volumes/*/*; do stat -f -c "%T %n" "$p"; done' 2>&1 || true
    fi
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
# share one. It forwards to the Deployment's pod rather than the Service: a
# CDS that is not ready has no Service endpoint, and some callers read one.
cds_pf_start() {
    local pid
    pid="$(cat "$WORKDIR/cds-pf.pid" 2>/dev/null || true)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && cds_healthy && return 0
    kubectl -n "$NS" port-forward deploy/c8s-cds "$CDS_LOCAL_PORT:8443" >/dev/null 2>&1 &
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
# A CDS without persistence refuses tokens for --jwt-clock-skew after it
# starts, so a 401 saying so is retried with a fresh token.
cds_write() {
    local method="$1" path="$2" bodyfile="$3" token code
    cds_pf_start
    for _ in $(seq 1 30); do
        token="$("$WORKDIR/optoken" "$WORKDIR/operator.key" "$method" "$path" "$bodyfile")"
        # Always exit 0: curl prints 000 on transport failure, and callers
        # assert on the code itself.
        code="$(curl -sSk -o "$WORKDIR/cds-write.out" -w '%{http_code}' -X "$method" \
            -H "Authorization: $token" -H 'Content-Type: application/json' \
            --data-binary "@$bodyfile" "https://127.0.0.1:$CDS_LOCAL_PORT$path" || true)"
        if [ "$code" != 401 ] || ! grep -q 'issued too early' "$WORKDIR/cds-write.out"; then
            break
        fi
        sleep 2
    done
    echo "$code"
}

# cds_get <path> <out-file> -> http code; the response body lands in out-file.
cds_get() {
    cds_pf_start
    curl -sSk -o "$2" -w '%{http_code}' "https://127.0.0.1:$CDS_LOCAL_PORT$1" || true
}

# route_manifest <revision> [<ca-pem-file>]: print a route manifest with one
# workload route, plus an address backend anchored on the CA file when given.
route_manifest() {
    python3 - "$@" <<'PY'
import json, sys
routes = [{"path": "/", "match": "prefix",
           "backend": {"address": "c8s-it.default.svc.cluster.local:8443", "workload": "it"}}]
if len(sys.argv) > 2:
    routes.append({"path": "/admin", "match": "prefix",
                   "backend": {"address": "admin.default.svc.cluster.local:8443",
                               "serverName": "admin.default.svc", "ca": open(sys.argv[2]).read()}})
print(json.dumps({"schema": "c8s.routes/v1", "revision": int(sys.argv[1]),
                  "notBefore": "2026-01-01T00:00:00Z", "maxAgeSeconds": 86400,
                  "hosts": {"it.example": {"routes": routes}}}))
PY
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
