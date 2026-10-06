#!/usr/bin/env bash
# Cluster integration harness for C8s.
#
# Installs the real C8s chart into a single-node kind cluster — no TEE
# hardware — and exercises the operational surface the unit tests and the
# docker-compose harness (test/integration) cannot: helm install via the C8s
# CLI, CRDs, the admission webhook and ValidatingAdmissionPolicies live in a
# real API server, the NRI image-admission plugin registered against a real
# containerd, workload-certificate issuance with sandbox-identity claims, the
# operator-signed allowlist loop into admission decisions, the RA-TLS mesh
# wrapping traffic, workload adoption, and uninstall.
#
# The TEE is replaced at exactly one point: evidence generation. A
# mock-attestation deployment (test/mock-attestation) serves synthetic SNP
# reports — launch digest all-zero — on the node IP :8400, the address
# cvmMode=bare-metal consumers dial for the node-baked api. Every stack component
# that delegates verification to the attestation-api (get-cert, CDS, the
# mesh, the NRI plugin) works unchanged. In-process hardware verification
# (`c8s verify`, the `c8s allowlist` CLI) cannot pass synthetic evidence, so
# allowlist writes here are signed with the production pkg/operatorauth
# signer (./optoken) and sent over plain curl; CDS still verifies the
# operator token server-side.
#
# What this deliberately is not: a confidential-cluster test. Nothing here
# asserts TEE properties — that is what the metal lanes (snp-metal-e2e,
# tdx-metal-e2e) are for. See docs/integration-tests.md.
#
# Prerequisites: docker (or podman via KIND_EXPERIMENTAL_PROVIDER=podman),
# kind, kubectl, helm, go, openssl, curl, python3. Run from the repo root via
# `make test-integration-cluster`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$REPO_ROOT"

. "$SCRIPT_DIR/lib.sh"

# C8S_IT_KEEP, C8S_IT_SETUP_ONLY, C8S_IT_WORKDIR: docs/integration-tests.md.
WORKDIR="${C8S_IT_WORKDIR:-$(mktemp -d)}"
mkdir -p "$WORKDIR"

cleanup() {
    cds_pf_stop
    if [ "${C8S_IT_KEEP:-}" = 1 ]; then
        echo "kept: kind cluster $CLUSTER, state in $WORKDIR"
        return
    fi
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

for tool in docker kind kubectl helm go openssl curl python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "FAIL: $tool not available" >&2; exit 1; }
done

# --- Build ---

log "Building component images"
# The component Dockerfiles copy a prebuilt build/c8s: build it for the
# docker host's Linux first, then the host's own below, for `c8s install`.
# On a Linux host of the same arch the second build is a cache hit.
DOCKER_ARCH="$(docker version --format '{{.Server.Arch}}')"
GOOS=linux GOARCH="$DOCKER_ARCH" make build-c8s >/dev/null
docker build -q -f cmd/c8s/Dockerfile               -t "ghcr.io/confidential-dot-ai/c8s-operator:$IMAGE_TAG"     . >/dev/null
docker build -q -f cmd/cds/Dockerfile               -t "ghcr.io/confidential-dot-ai/cds:$IMAGE_TAG"              . >/dev/null
docker build -q -f cmd/nri-image-policy/Dockerfile  -t "ghcr.io/confidential-dot-ai/nri-image-policy:$IMAGE_TAG" . >/dev/null
docker build -q -f cmd/ratls-mesh/Dockerfile        -t "ghcr.io/confidential-dot-ai/ratls-mesh:$IMAGE_TAG"       . >/dev/null
docker build -q -f test/mock-attestation/Dockerfile -t "ghcr.io/confidential-dot-ai/mock-attestation:$IMAGE_TAG" . >/dev/null

log "Building the c8s binary"
make build-c8s >/dev/null

go build -o "$WORKDIR/optoken" ./test/integration/cluster/optoken

# --- Cluster ---

log "Creating the kind cluster"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --wait 120s \
    || fail "kind cluster did not come up (node image: $NODE_IMAGE)"
NODE="$(kind get nodes --name "$CLUSTER" | head -1)"
[ -n "$NODE" ] || fail "kind reported no node"
NODE_IP="$(kubectl get node "$NODE" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
[ -n "$NODE_IP" ] || fail "could not resolve the node IP"

log "Loading images into the cluster"
# One at a time: the podman provider crosses images loaded in a single call.
for img in c8s-operator cds nri-image-policy ratls-mesh mock-attestation; do
    kind load docker-image "ghcr.io/confidential-dot-ai/$img:$IMAGE_TAG" --name "$CLUSTER" >/dev/null
done

# Test-client and workload images, pre-pulled so their store digests are
# known when the floor is written. The curl image is deliberately KEPT OUT of
# the floor: the admission test needs a digest the plugin has never seen, so
# denial is deterministic instead of racing the plugin's pull interval.
node_exec ctr -n k8s.io images pull "docker.io/$CURL_IMAGE" >/dev/null \
    || fail "could not pull $CURL_IMAGE into the node (registry rate limit?)"
node_exec ctr -n k8s.io images pull "docker.io/$WORKLOAD_IMAGE" >/dev/null \
    || fail "could not pull $WORKLOAD_IMAGE into the node (registry rate limit?)"
# router's nginx is pulled at install time — after the floor scan — so its
# chart-pinned digest is pulled by reference and seeded up front; otherwise
# the plugin's enforce-existing check kills the front door's own container.
ROUTER_NGINX_REF="$(helm show values internal/helmchart/c8s | python3 -c '
import sys, yaml
img = yaml.safe_load(sys.stdin)["router"]["nginx"]["image"]
repo = img["repository"]
# Bare docker-hub names (nginxinc/foo) need the registry made explicit for ctr.
if "/" not in repo or ("." not in repo.split("/")[0] and ":" not in repo.split("/")[0] and repo.split("/")[0] != "localhost"):
    repo = "docker.io/" + repo
print(repo + "@" + img["digest"])')"
node_exec ctr -n k8s.io images pull "$ROUTER_NGINX_REF" >/dev/null \
    || fail "could not pull $ROUTER_NGINX_REF into the node"

log "Writing the allowlist floor"
# Every image in the node's store (kind system images, the loaded C8s images,
# the pre-pulled fixtures) goes into the install-time floor: with
# enforceExisting the plugin checks already-running containers against CDS's
# served allowlist at startup, so anything missing is killed. These fixture
# entries explicitly allow mounts too: kind system pods require host mounts.
store_digests > "$WORKDIR/floor.tsv"
[ -s "$WORKDIR/floor.tsv" ] || fail "containerd store scan came back empty"
grep -Fq "docker.io/$WORKLOAD_IMAGE" "$WORKDIR/floor.tsv" || fail "workload image missing from the store scan"
# kind preloads its local-path helper image into the node, so the scan admits
# the provisioner's per-PVC helper pods (the provisioning test below).
HELPER_IMAGE="$(kubectl -n local-path-storage get configmap local-path-config \
    -o jsonpath='{.data.helperPod\.yaml}' \
    | python3 -c 'import sys, yaml; print(yaml.safe_load(sys.stdin)["spec"]["containers"][0]["image"])')"
grep -Fq "$HELPER_IMAGE" "$WORKDIR/floor.tsv" \
    || fail "kind local-path helper image $HELPER_IMAGE missing from the floor scan"
NRI_STORE_DIGEST="$(awk -F'\t' '$2 ~ /nri-image-policy:it$/ {print $1; exit}' "$WORKDIR/floor.tsv")"
CDS_STORE_DIGEST="$(awk -F'\t' '$2 ~ /\/cds:it$/ {print $1; exit}' "$WORKDIR/floor.tsv")"
[ -n "$NRI_STORE_DIGEST" ] && [ -n "$CDS_STORE_DIGEST" ] || fail "loaded-image digests missing from the floor scan"
# Client-side render: the chart's kubeVersion floor is checked against the
# live server version, not helm's compiled-in default.
KUBE_VERSION="$(kubectl version -o json \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["serverVersion"]["gitVersion"])')"
# nriImagePolicy.exemptNamespaces must stay empty in this lane: the sweep pod
# shares the installer's namespace and digest, so an exempt downgrade would
# re-admit it despite the argv pin and hide a regression.
python3 - "$WORKDIR/floor.tsv" "$WORKDIR/values.yaml" "docker.io/$CURL_IMAGE" "$NRI_STORE_DIGEST" <<'PYEOF'
import re, sys, yaml
floor = {}
for line in open(sys.argv[1]):
    digest, ref = line.rstrip("\n").split("\t")
    floor.setdefault(digest, ref)
# Kept out of the floor on purpose: the admission test's unseen digest (the
# curl ref), and the nri-image-policy digest — production admits that image
# only under the chart's argv-pinned entry, never by digest. The pinned entry
# is injected from the chart render below; leaving an any-argv row here would
# union-admit any argv and void the uninstall regression.
floor = {d: r for d, r in floor.items() if r != sys.argv[3] and d != sys.argv[4]}

def entry_name(digest, ref):
    # Mirrors pkg/allowlist DigestEntryName.
    base = ref.split("@", 1)[0].rsplit("/", 1)[-1].split(":", 1)[0][:50]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", base):
        base = "image"
    return base + "-" + digest[len("sha256:"):][:12]

workloads = {
    entry_name(d, r): {
        "label": r,
        "containers": [{"digest": d, "image": r, "command": {"policy": "any"}, "args": {"policy": "any"}, "mounts": {"policy": "any"}}],
    }
    for d, r in floor.items()
}
with open(sys.argv[2], "w") as f:
    yaml.safe_dump({
        "nriImagePolicy": {
            # The kind node bakes no plugin or boot config, so the chart's
            # installer stays off: its baked form would find no config to
            # patch. The full installer is applied out-of-band below.
            "enabled": False,
            "bootstrapAllowlist": {"workloads": workloads},
        },
    }, f)
print(f"floor: {len(workloads)} any-argv entries")
PYEOF

log "Rendering the NRI installer and its argv-pinned seed entry"
# One render feeds both the out-of-band installer DaemonSet and the pinned
# seed entry injected into the floor: two renders could drift their flags,
# and the plugin's enforce-existing check would kill the install init
# container over an argv mismatch.
helm template c8s internal/helmchart/c8s -n "$NS" \
    --kube-version "$KUBE_VERSION" \
    --set-string image.tag="$IMAGE_TAG" \
    --set-string attestationApi.cvmMode=bare-metal \
    --set attestationApi.enabled=false \
    --set nriImagePolicy.enabled=true \
    --set-string nriImagePolicy.image.tag="$IMAGE_TAG" \
    --set-string nriImagePolicy.image.digest="$NRI_STORE_DIGEST" \
    --set-string cds.image.digest="$CDS_STORE_DIGEST" \
    --set-string "cds.measurements[0]=$MOCK_MEASUREMENT" \
    --set router.enabled=false \
    --set volumed.enabled=false \
    --set ratlsMesh.enabled=false \
    -f "$WORKDIR/values.yaml" > "$WORKDIR/nri-render.yaml" \
    || fail "could not render the NRI installer chart documents"
python3 - "$WORKDIR/nri-render.yaml" "$WORKDIR/values.yaml" "$WORKDIR/nri-installer.yaml" <<'PYEOF'
import json, sys, yaml
render_path, values_path, ds_path = sys.argv[1:4]
docs = [d for d in yaml.safe_load_all(open(render_path)) if d]
seed_cm = next(d for d in docs if d.get("kind") == "ConfigMap" and d["metadata"]["name"].endswith("-allowlist-seed"))
seed = json.loads(seed_cm["data"]["allowlist-seed.json"])
pinned = {k: v for k, v in seed["workloads"].items() if k.startswith("nri-image-policy-")}
assert len(pinned) == 1, f"want exactly one pinned nri-image-policy entry, got {sorted(pinned)}"
values = yaml.safe_load(open(values_path))
values["nriImagePolicy"]["bootstrapAllowlist"]["workloads"].update(pinned)
with open(values_path, "w") as f:
    yaml.safe_dump(values, f)
installer = next(d for d in docs if d.get("kind") == "DaemonSet" and d["metadata"]["name"].endswith("-worker"))
with open(ds_path, "w") as f:
    yaml.safe_dump(installer, f)
print(f"pinned seed entry {next(iter(pinned))} injected into the floor values")
PYEOF

# Digest-alias the loaded C8s images: the NRI installer renders its pod image
# as repo@<store digest>; the alias makes containerd resolve that reference
# to the loaded image without a registry pull.
while IFS=$'\t' read -r digest ref; do
    case "$ref" in
        ghcr.io/confidential-dot-ai/*:*) node_exec ctr -n k8s.io images tag "$ref" "${ref%:*}@$digest" >/dev/null ;;
    esac
done < "$WORKDIR/floor.tsv"

log "Deploying the mock attestation-api"
kubectl apply -f test/integration/cluster/manifests/mock-attestation.yaml
kubectl -n kube-system rollout status deploy/mock-attestation --timeout=120s

openssl ecparam -genkey -name prime256v1 -noout -out "$WORKDIR/operator.key" 2>/dev/null
openssl ec -in "$WORKDIR/operator.key" -pubout -out "$WORKDIR/operator-pub.pem" 2>/dev/null

log "c8s install"
./build/c8s install --namespace "$NS" --cvm-mode=bare-metal --hardware-platform=sev-snp \
    --single-node --resolve-digests=false --image-tag="$IMAGE_TAG" \
    --operator-keys "$WORKDIR/operator-pub.pem" \
    --measurements "$MOCK_MEASUREMENT" \
    -f "$WORKDIR/values.yaml" --wait || fail "c8s install failed"

# --- NRI image-policy plugin ---

log "Installing the NRI image-policy plugin"
# Under --cvm-mode=bare-metal the chart renders the installer only in its baked
# pins-patching form, and the install above leaves even that off (values.yaml):
# the kind node bakes no plugin for it to pin. The harness renders the full
# installer from the chart source (above, before c8s install) and applies it
# out-of-band — same installer, same containerd patch, same plugin.
kubectl apply -f "$WORKDIR/nri-installer.yaml"
# The installer patches the node's containerd config and restarts it; the
# DaemonSet reports Ready once the plugin answers its health socket.
kubectl -n "$NS" rollout status ds/c8s-nri-image-policy-worker --timeout=300s \
    || fail "NRI plugin did not become healthy"
node_exec test -S /var/run/nri-image-policy/workload-claims.sock \
    || fail "admission inventory socket missing on the node"
pass "NRI plugin registered with containerd and serves the admission inventory"

kind get kubeconfig --name "$CLUSTER" > "$WORKDIR/kubeconfig"
cat > "$WORKDIR/env" <<EOF
export KUBECONFIG=$WORKDIR/kubeconfig
CLUSTER=$CLUSTER
NODE=$NODE
NODE_IP=$NODE_IP
WORKDIR=$WORKDIR
EOF
if [ "${C8S_IT_SETUP_ONLY:-}" = 1 ]; then
    echo "=== Stack installed; checks skipped (C8S_IT_SETUP_ONLY=1) ==="
    exit 0
fi

# --- Tests ---

log "Control plane"
for deploy in c8s-operator c8s-cds c8s-router; do
    kubectl -n "$NS" wait --for=condition=Available "deploy/$deploy" --timeout=180s \
        || fail "$deploy not Available"
done
kubectl -n "$NS" rollout status ds/c8s-ratls-mesh --timeout=240s || fail "ratls-mesh not ready"
pass "operator, CDS, router and ratls-mesh all Ready after c8s install"

kubectl get crd confidentialworkloads.confidential.ai >/dev/null || fail "ConfidentialWorkload CRD missing"
kubectl get mutatingwebhookconfiguration c8s-pod-injector >/dev/null || fail "pod-injector webhook config missing"
kubectl get validatingadmissionpolicy c8s-cw-label-integrity >/dev/null || fail "cw-label policy missing"
kubectl get validatingadmissionpolicy c8s-deny-host-namespaces >/dev/null || fail "host-namespace policy missing"
pass "CRD, mutating webhook, and both ValidatingAdmissionPolicies installed"

log "Allowlist API"
# Unsigned and wrongly-signed writes are refused; a write signed by the
# pinned operator key lands, is served, and deletes cleanly. Exercised on a
# throwaway digest so no assertion can pass on the seeded entries.
cds_pf_start
THROWAWAY_DIGEST="sha256:$(printf 'ab%.0s' {1..32})"
any_workload "$THROWAWAY_DIGEST" "example.com/harness/throwaway:1" > "$WORKDIR/add.json"
code="$(curl -sSk -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' \
    --data-binary @"$WORKDIR/add.json" "https://127.0.0.1:$CDS_LOCAL_PORT/allowlist/workloads/throwaway" || true)"
[ "$code" = "401" ] || fail "unsigned allowlist write: want HTTP 401, got $code"
pass "unsigned allowlist write rejected (401)"

openssl ecparam -genkey -name prime256v1 -noout -out "$WORKDIR/rogue.key" 2>/dev/null
rogue_token="$("$WORKDIR/optoken" "$WORKDIR/rogue.key" PUT /allowlist/workloads/throwaway "$WORKDIR/add.json")"
code="$(curl -sSk -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: $rogue_token" -H 'Content-Type: application/json' \
    --data-binary @"$WORKDIR/add.json" "https://127.0.0.1:$CDS_LOCAL_PORT/allowlist/workloads/throwaway" || true)"
[ "$code" = "401" ] || fail "wrong-key allowlist write: want HTTP 401, got $code"
pass "allowlist write signed by an unpinned key rejected (401)"

code="$(cds_write PUT /allowlist/workloads/throwaway "$WORKDIR/add.json")"
[ "$code" = "204" ] || fail "signed allowlist write: want HTTP 204, got $code"
curl -sSk "https://127.0.0.1:$CDS_LOCAL_PORT/allowlist" | grep -q "$THROWAWAY_DIGEST" \
    || fail "added digest not served from /allowlist"
: > "$WORKDIR/del.json"
code="$(cds_write DELETE /allowlist/workloads/throwaway "$WORKDIR/del.json")"
[ "$code" = "204" ] || fail "signed allowlist delete: want HTTP 204, got $code"
if curl -sSk "https://127.0.0.1:$CDS_LOCAL_PORT/allowlist" | grep -q "$THROWAWAY_DIGEST"; then
    fail "deleted digest still served from /allowlist"
fi
pass "signed allowlist write + delete round-trip through CDS"

log "Confidential workload"
kubectl apply -f test/integration/cluster/manifests/workload.yaml
# Webhook injection: the pod template gains the get-cert sidecar and the cw label.
for _ in $(seq 1 30); do
    POD="$(kubectl -n demo get pod -l app=serving -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)" && [ -n "$POD" ] && break
    sleep 1
done
[ -n "$POD" ] || fail "demo workload pod never appeared"
INIT_NAMES="$(kubectl -n demo get pod "$POD" -o jsonpath='{.spec.initContainers[*].name}')"
case "$INIT_NAMES" in
    *c8s-cert*c8s-cert-wait*) : ;;
    *) fail "webhook did not inject the get-cert containers (init: $INIT_NAMES)" ;;
esac
LABELS="$(kubectl -n demo get pod "$POD" --show-labels --no-headers | awk '{print $NF}')"
case "$LABELS" in
    *confidential.ai/cw=vllm*) : ;;
    *) fail "webhook did not stamp the cw label (labels: $LABELS)" ;;
esac
pass "webhook injected c8s-cert + c8s-cert-wait and stamped confidential.ai/cw=vllm"

# The operator provisions the workload's headless Service.
for _ in $(seq 1 30); do
    kubectl -n demo get svc c8s-vllm >/dev/null 2>&1 && break
    sleep 1
done
CLUSTERIP="$(kubectl -n demo get svc c8s-vllm -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
[ "$CLUSTERIP" = "None" ] || fail "c8s-vllm is not a headless Service (clusterIP: $CLUSTERIP)"
pass "operator provisioned headless Service c8s-vllm"

# get-cert redeems a sandbox token from the node inventory and CDS issues the
# workload's leaf — the workload-digest claims flow, fail-closed without the
# NRI plugin.
for _ in $(seq 1 60); do
    kubectl -n demo logs "$POD" -c c8s-cert 2>/dev/null | grep -q "certificate obtained" && break
    sleep 2
done
CERTLOG="$(kubectl -n demo logs "$POD" -c c8s-cert 2>/dev/null || true)"
echo "$CERTLOG" | grep -q "certificate obtained" || fail "get-cert never obtained a certificate: $CERTLOG"
echo "$CERTLOG" | grep -q "sandbox_token=true" || fail "get-cert issued without a sandbox token: $CERTLOG"
pass "workload leaf issued with a sandbox-identity token (NRI inventory + CDS callback)"

kubectl -n demo wait --for=condition=Ready "pod/$POD" --timeout=240s \
    || fail "workload pod never became Ready"
pass "workload pod Running behind the full injection + admission path"

# The issued leaf is bound to the workload's in-cluster DNS identity.
kubectl -n demo exec "$POD" -c app -- cat /etc/c8s/certs/tls.crt > "$WORKDIR/leaf.pem" 2>/dev/null \
    || fail "could not read the issued leaf from the workload pod"
SAN="$(openssl x509 -in "$WORKDIR/leaf.pem" -noout -ext subjectAltName 2>/dev/null || true)"
echo "$SAN" | grep -q "DNS:c8s-vllm.demo.svc" || fail "leaf SAN is not the workload identity: $SAN"
pass "issued leaf carries SAN c8s-vllm.demo.svc"

log "Admission rejections"
pod_fixture bad-label bad-label demo sleep 3600 > "$WORKDIR/bad-label.yaml"
OUT="$(kubectl apply -f "$WORKDIR/bad-label.yaml" 2>&1 || true)"
echo "$OUT" | grep -q "must match" || fail "cw label/annotation mismatch not rejected: $OUT"
pass "pod with an unmatching cw label rejected at admission"

pod_fixture bad-hostnet bad-hostnet demo sleep 3600 > "$WORKDIR/bad-hostnet.yaml"
OUT="$(kubectl apply -f "$WORKDIR/bad-hostnet.yaml" 2>&1 || true)"
echo "$OUT" | grep -q "c8s-deny-host-namespaces" || fail "hostNetwork tenant pod not rejected: $OUT"
pass "hostNetwork tenant pod rejected by the host-namespace policy"

log "Dynamic provisioning (issue #210)"
# kind's default class is local-path, the node cluster's shape: the provisioner's
# hostPath helper runs in VAP-exempt local-path-storage. If the exemption
# regresses, the helper is denied and this PVC stays Pending.
kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: prov-check, namespace: demo}
spec:
  accessModes: [ReadWriteOnce]
  resources: {requests: {storage: 16Mi}}
EOF
# WORKLOAD_IMAGE, not the floor-excluded curl fixture: the pod must clear NRI image admission.
python3 "$SCRIPT_DIR/pod-fixture.py" pvc prov-check demo "$WORKLOAD_IMAGE" -- \
    sh -c 'echo c8s > /data/probe && sleep 3600' > "$WORKDIR/prov-check.yaml"
kubectl apply -f "$WORKDIR/prov-check.yaml" >/dev/null
kubectl -n demo wait --for=condition=Ready pod/prov-check --timeout=120s \
    || fail "local-path PVC never bound — the provisioner's helper pod must admit in VAP-exempt local-path-storage (kubectl -n demo describe pvc prov-check)"
[ "$(kubectl -n demo exec prov-check -- cat /data/probe)" = "c8s" ] \
    || fail "read-back through the provisioned local-path volume failed"
kubectl -n demo delete pod prov-check --wait=false >/dev/null
kubectl -n demo delete pvc prov-check --wait=false >/dev/null
pass "PVC on the default class dynamically provisioned and writable"

log "Image admission (NRI fail-closed)"
pod_fixture client denied demo sleep 3600 > "$WORKDIR/denied.yaml"
# The curl image was never seeded into the floor, so the plugin denies it
# from the start — no delete, no pull-interval race.
CURL_DIGEST="$(awk -F'\t' -v ref="docker.io/$CURL_IMAGE" '$2 == ref {print $1; exit}' "$WORKDIR/floor.tsv")"
[ -n "$CURL_DIGEST" ] || fail "curl image digest not resolved"
kubectl apply -f "$WORKDIR/denied.yaml"
DENIED=""
for _ in $(seq 1 45); do
    if kubectl -n demo get events --field-selector involvedObject.name=denied -o jsonpath='{.items[*].message}' 2>/dev/null | grep -q "image not in allowlist"; then
        DENIED=1
        break
    fi
    sleep 2
done
[ -n "$DENIED" ] || fail "non-allowlisted image was not NRI-denied"
pass "non-allowlisted image denied at container creation (fail-closed)"

# Allow, and the same pod proceeds.
any_workload "$CURL_DIGEST" "docker.io/$CURL_IMAGE" > "$WORKDIR/add-curl.json"
code="$(cds_write PUT /allowlist/workloads/curl "$WORKDIR/add-curl.json")"
[ "$code" = "204" ] || fail "signed allowlist re-add: want HTTP 204, got $code"
# kubelet's CreateContainerError backoff stretches into the minutes, so this
# wait must comfortably outlive it.
kubectl -n demo wait --for=condition=Ready pod/denied --timeout=360s \
    || fail "pod still blocked after its image was allowlisted"
pass "signed allowlist write flips a denied pod to Running (plugin pulled the update)"

log "Mesh"
# Mirrored from test/e2e/mesh-cw-enforcement.sh: a direct pod-IP dial from a
# meshed namespace is intercepted and wrapped (the inbound counter moves);
# the bypasses that skip interception — a Service VIP, a dial from a
# mesh-excluded namespace — must never reach the workload in plaintext.
POD_IP="$(kubectl -n demo get pod "$POD" -o jsonpath='{.status.podIP}')"
[ -n "$POD_IP" ] || fail "could not resolve the workload pod IP"

pod_fixture client it-mesh-client default sleep 1200 | kubectl apply -f - >/dev/null
kubectl wait --for=condition=Ready pod/it-mesh-client --timeout=120s || fail "mesh client pod not Ready"
CLIENT_IP="$(kubectl get pod it-mesh-client -o jsonpath='{.status.podIP}')"
await_ipset RATLS-MESH-LOCAL-PODS "$CLIENT_IP"
await_ipset RATLS-MESH-CW-PODS "$POD_IP"

# The egress guard drops every non-TCP packet a cw pod sends, carving out
# UDP/53 to the cluster resolver. The carve-out sits in a chain downstream of
# kube-proxy's Service DNAT, so a query arrives there addressed to a CoreDNS
# pod and a rule written against the packet's destination cannot fire — the
# pod stays Running and every name it resolves fails. Assert resolution, not
# health.
KUBERNETES_IP="$(kubectl -n default get svc kubernetes -o jsonpath='{.spec.clusterIP}')"
resolved="$(kubectl -n demo exec "$POD" -c app -- timeout 15 nslookup kubernetes.default.svc.cluster.local 2>&1)" \
    || fail "cw pod cannot resolve a cluster name; the egress guard's DNS carve-out is unreachable in its chain:
$resolved"
echo "$resolved" | grep -q "$KUBERNETES_IP" \
    || fail "cw pod's resolver answered without the kubernetes ClusterIP $KUBERNETES_IP: $resolved"
pass "cw pod resolves cluster DNS through the egress guard's carve-out"

# The carve-out names one resolver. Widening it to any UDP/53 destination
# would pass the check above and hand every cw pod a plaintext channel to an
# arbitrary host, so the scope is asserted directly.
if kubectl -n demo exec "$POD" -c app -- timeout 8 nslookup example.com 192.0.2.53 >/dev/null 2>&1; then
    fail "cw pod reached an off-cluster resolver on UDP/53; the carve-out must name the cluster DNS server only"
fi
pass "cw pod cannot reach an unnamed resolver on UDP/53"

inbound='^ratls_mesh_connections_total.*direction="inbound"'
base_inbound="$(mesh_metric "$inbound")"
code="$(kubectl exec it-mesh-client -- curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "http://$POD_IP:8080/" || true)"
[ "$code" = "200" ] || fail "pod-IP request to the cw workload failed (got $code); the mesh-wrapped path must work"
await_metric_above "$inbound" "${base_inbound:-0}" "mesh inbound connection counter"
pass "pod-IP dial to the cw workload is mesh-wrapped (inbound counter moved)"

# Service VIP over the cw pods: the mesh skips ClusterIPs by design, so the
# hop must fail closed or ride the mesh — never plaintext (see below).
cat > "$WORKDIR/vip-svc.yaml" <<'EOF'
apiVersion: v1
kind: Service
metadata:
  name: it-cw-vip
  namespace: demo
spec:
  type: ClusterIP
  selector:
    confidential.ai/cw: vllm
  ports:
    - { port: 80, targetPort: 8080 }
EOF
kubectl apply -f "$WORKDIR/vip-svc.yaml"
VIP="$(kubectl -n demo get svc it-cw-vip -o jsonpath='{.spec.clusterIP}')"
for _ in $(seq 1 30); do
    kubectl get endpointslices -n demo -l kubernetes.io/service-name=it-cw-vip \
        -o jsonpath='{.items[*].endpoints[*].addresses[*]}' 2>/dev/null | grep -q . && break
    sleep 2
done
# Two secure outcomes, depending on which nat PREROUTING rule runs first:
# mesh-first -> the VIP matches no pod-IP rule, kube-proxy DNATs, the FORWARD
# guard DROPs (curl rc 28); kube-proxy-first -> the DNAT'd packet matches the
# mesh's pod-IP interception and the hop is WRAPPED (rc 0, inbound counter
# moves). The insecure outcome is plaintext, which no counter move proves.
drops='^ratls_mesh_iptables_cw_inbound_drops_total'
base_drops="$(mesh_metric "$drops")"
base_inbound_vip="$(mesh_metric "$inbound")"
out="$(kubectl exec it-mesh-client -- sh -c "curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://$VIP:80/; echo rc=\$?" || true)"
rc="$(echo "$out" | grep -o 'rc=[0-9]*' | cut -d= -f2)"
case "$rc" in
    28)
        await_metric_above "$drops" "${base_drops:-0}" "cw inbound drop counter"
        pass "Service-VIP plaintext bypass dropped by the cw inbound guard (counter moved)"
        ;;
    0)
        echo "$out" | grep -q "^200" || fail "VIP dial rc=0 but no 200: $out"
        await_metric_above "$inbound" "${base_inbound_vip:-0}" \
            "VIP dial returned 200 but the mesh recorded no inbound connection, so the hop reached the cw workload outside the mesh — in plaintext"
        pass "Service-VIP dial wrapped by the mesh (inbound counter moved; rule-ordering variant)"
        ;;
    *)
        fail "VIP bypass to the cw workload: want rc=28 (dropped) or rc=0 (wrapped), got rc=$rc"
        ;;
esac

# A mesh-excluded namespace (kube-system) is not intercepted on egress; its
# direct dial to the cw pod IP is left to the node's inbound chains.
pod_fixture client it-mesh-excl kube-system sleep 600 | kubectl apply -f - >/dev/null
kubectl wait --for=condition=Ready pod/it-mesh-excl -n kube-system --timeout=120s \
    || fail "excluded-namespace client pod not Ready"
# This dial crosses the same nat PREROUTING chains as the VIP case, so it has
# the same two secure outcomes and the same one insecure outcome. Which of the
# two secure ones happens is a property of rule ordering, not of the client's
# namespace, so demanding rc=28 alone fails on a wrapped hop and passes a
# plaintext one unnoticed (rc=0 proves only "not dropped"). Require the
# matching counter instead.
base_drops_excl="$(mesh_metric "$drops")"
base_inbound_excl="$(mesh_metric "$inbound")"
out="$(kubectl exec -n kube-system it-mesh-excl -- sh -c "curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://$POD_IP:8080/; echo rc=\$?" || true)"
rc="$(echo "$out" | grep -o 'rc=[0-9]*' | cut -d= -f2)"
case "$rc" in
    28)
        await_metric_above "$drops" "${base_drops_excl:-0}" "cw inbound drop counter"
        pass "excluded-namespace plaintext bypass dropped by the cw inbound guard (counter moved)"
        ;;
    0)
        echo "$out" | grep -q "^200" || fail "excluded-namespace dial rc=0 but no 200: $out"
        await_metric_above "$inbound" "${base_inbound_excl:-0}" \
            "excluded-namespace dial returned 200 but the mesh recorded no inbound connection, so the hop reached the cw workload outside the mesh — in plaintext"
        pass "excluded-namespace dial wrapped by the mesh (inbound counter moved; rule-ordering variant)"
        ;;
    *)
        fail "excluded-namespace bypass to the cw workload: want rc=28 (dropped) or rc=0 (wrapped), got rc=$rc"
        ;;
esac

log "router front door"
kubectl -n "$NS" exec deploy/c8s-router -c nginx -- cat /tls/ca.pem > "$WORKDIR/mesh-ca.pem" \
    || fail "could not read the mesh CA from router"
kubectl create configmap it-mesh-ca --from-file=ca.pem="$WORKDIR/mesh-ca.pem"
pod_fixture front-door it-curl-lb default curl -sS --cacert /ca/ca.pem \
    "https://c8s-router.$NS.svc/healthz" > "$WORKDIR/curl-lb.yaml"
kubectl apply -f "$WORKDIR/curl-lb.yaml"
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/it-curl-lb --timeout=120s \
    || fail "front-door healthz request failed"
[ "$(kubectl logs it-curl-lb)" = "ok" ] || fail "front-door /healthz did not return ok"
pass "router front door serves HTTPS verified against the CDS mesh CA"

log "Workload adoption"
kubectl apply -f test/integration/cluster/manifests/adopt-me.yaml
kubectl -n adopted wait --for=condition=Available deploy/web --timeout=120s \
    || fail "adoption fixture never became Available"
./build/c8s install --namespace "$NS" --cvm-mode=bare-metal --hardware-platform=sev-snp \
    --single-node --resolve-digests=false --image-tag="$IMAGE_TAG" \
    --operator-keys "$WORKDIR/operator-pub.pem" \
    --measurements "$MOCK_MEASUREMENT" \
    --workload-ref web=adopted/deployment/web:8080 --upstream web \
    -f "$WORKDIR/values.yaml" --wait || fail "c8s install --workload-ref failed"
TMPL_ANNOTATION="$(kubectl -n adopted get deploy web -o jsonpath='{.spec.template.metadata.annotations.confidential\.ai/cw}')"
[ "$TMPL_ANNOTATION" = "web" ] || fail "adopted workload template not stamped (got: $TMPL_ANNOTATION)"
kubectl -n adopted rollout status deploy/web --timeout=300s || fail "adopted workload never rolled out"
pass "install adopted a running workload (template stamped, rollout injected)"

# The status mirror aggregates a user-declared ConfidentialWorkload CR over
# the cw-labeled pods (kubectl get cwl).
cat > "$WORKDIR/cw.yaml" <<'EOF'
apiVersion: confidential.ai/v1alpha2
kind: ConfidentialWorkload
metadata:
  name: web
  namespace: adopted
spec:
  workloadRef:
    kind: Deployment
    name: web
EOF
kubectl apply -f "$WORKDIR/cw.yaml"
SUMMARY=""
for _ in $(seq 1 30); do
    SUMMARY="$(kubectl -n adopted get cwl web -o jsonpath='{.status.attestationSummary.total}/{.status.attestationSummary.attested}' 2>/dev/null || true)"
    [ "$SUMMARY" = "1/1" ] && break
    sleep 2
done
[ "$SUMMARY" = "1/1" ] || fail "status mirror never reported the adopted workload (got: $SUMMARY)"
pass "status mirror reports the adopted workload (attestationSummary 1/1)"

# router now routes its catch-all to the adopted workload over the mesh.
kubectl delete pod it-curl-lb 2>/dev/null || true
pod_fixture front-door it-curl-lb default curl -sS --cacert /ca/ca.pem \
    "https://c8s-router.$NS.svc/" > "$WORKDIR/curl-lb.yaml"
kubectl apply -f "$WORKDIR/curl-lb.yaml"
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/it-curl-lb --timeout=120s \
    || fail "front-door request to the adopted workload failed"
# Read the body once: piping a live `kubectl logs` into `grep -q` is a race
# under pipefail (grep exits on the match and the producer can die to SIGPIPE)
# and re-reading in the failure message can show a body grep never saw.
BODY="$(kubectl logs it-curl-lb)" || fail "could not read the it-curl-lb logs"
case "$BODY" in
    *"Welcome to nginx"*) ;;
    *) fail "front door did not proxy the adopted workload: $BODY" ;;
esac
pass "router routes the front door to the adopted workload over the mesh"

log "Checking the served allowlist pins the host sweep argv"
# The port-forward can point at a CDS pod the second install rolled; recycle
# it before reading the served document.
cds_pf_stop
cds_pf_start
curl -sSk "https://127.0.0.1:$CDS_LOCAL_PORT/allowlist" > "$WORKDIR/served.json" \
    || fail "could not read the served allowlist"
python3 - "$WORKDIR/served.json" "$NRI_STORE_DIGEST" <<'PYEOF'
import json, sys
doc = json.load(open(sys.argv[1]))
digest = sys.argv[2]
# Operator-written entries can carry null for absent lists/policies.
containers = [c for w in doc["workloads"].values()
              for c in (w.get("initContainers") or []) + (w.get("containers") or [])
              if c.get("digest") == digest]
assert containers, f"no served entry carries {digest[:19]}"
# Admission unions across entries per digest: one any-argv row for this
# digest would admit the sweep regardless of the pin.
for c in containers:
    assert (c.get("command") or {}).get("policy") != "any" and (c.get("args") or {}).get("policy") != "any", \
        f"any-argv admission for {digest[:19]}: {c}"
shapes = [(tuple((c.get("command") or {}).get("argv") or []), tuple((c.get("args") or {}).get("argv") or []))
          for c in containers]
assert (("/bin/sleep",), ("2147483647",)) in shapes, f"no /bin/sleep pause pin for the sweep: {shapes}"
assert any(s[0] == ("/bin/sh", "-c") and len(s[1]) == 1 and "c8s host sweep" in s[1][0] for s in shapes), \
    f"no host-sweep script pin: {shapes}"
print(f"served allowlist: {len(containers)} argv-pinned shapes for the nri image, sweep shapes pinned")
PYEOF
# The uninstall's sweep image resolution relies on the release carrying
# tag=it and no digest for the nri image; a chart-default digest would flip
# the sweep to an upstream image this lane never loaded.
helm -n "$NS" get values c8s --all -o json | python3 -c '
import json, sys
img = json.load(sys.stdin)["nriImagePolicy"]["image"]
assert img.get("tag") == "it" and not img.get("digest"), \
    f"nriImagePolicy.image = {img}; want tag=it and no digest"
'
pass "served allowlist pins the host sweep argv (no any-argv hole for the nri digest)"

log "Uninstall"
./build/c8s uninstall --namespace "$NS" || fail "c8s uninstall failed"
if helm -n "$NS" list -q | grep -q c8s; then
    fail "helm release still present after uninstall"
fi
if kubectl get mutatingwebhookconfiguration c8s-pod-injector >/dev/null 2>&1; then
    fail "mutating webhook config left behind after uninstall"
fi
if kubectl get validatingadmissionpolicy c8s-deny-host-namespaces >/dev/null 2>&1; then
    fail "ValidatingAdmissionPolicies left behind after uninstall"
fi
pass "uninstall removes the release, webhook, and admission policies"

echo ""
echo "=== All $CHECKS cluster integration checks passed ==="
