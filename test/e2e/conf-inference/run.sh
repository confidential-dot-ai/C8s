#!/usr/bin/env bash
# Post-boot half of the confidential-inference e2e on the tdx-metal lane:
# deploy the pinned release's gateway, simulator worker and router on the
# measured node, then check from outside, as a customer does, with
# TEErminator and the gateway API. Nothing here skips; a missing input fails.
#
# The node was launched with prepare.sh's app.json as --workloads. The
# script routes the front door to the gateway with `c8s routes add`, as the
# operator does after boot. After the launch-path checks it uploads the full
# allowlist with `c8s allowlist upload` and checks again.
#
# Env: GUEST_IP, KUBECONFIG, CIE_DIR (prepare.sh's output), LAUNCH_DIR
# (launch-config new --out), IMAGE_MANIFEST, GH_TOKEN (pulls the org-internal
# images for the job's lifetime).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/../lib.sh"
. "$here/pins.env"
: "${GUEST_IP:?}" "${KUBECONFIG:?}" "${CIE_DIR:?}" "${LAUNCH_DIR:?}" "${IMAGE_MANIFEST:?}" "${GH_TOKEN:?}"
export PATH="$CIE_DIR/bin:$PATH"
cd "$CIE_DIR"
set -a
. ./front-door.env
set +a

ns=confidential-inference
front=https://$GUEST_IP:443
cds=https://$GUEST_IP:30808
pin=(--image-policy-file "$LAUNCH_DIR/server.json")
key=$LAUNCH_DIR/server.key
operator_pub=$LAUNCH_DIR/server/pubkey
apps=(gateway inference-worker-0 sglang-router)
router=$(jq -er '[.workloads | keys[] | select(startswith("c8s-router-"))] | if length == 1 then .[0] else error("want one router entry") end' node-image/allowlist-seed.json)
echo "front-door workload from this build's seed: $router"

# Every entry built for the launch is active as built: the seed this build
# renders and the app entries derived with this CLI.
c8s allowlist export --url "$front" "${pin[@]}" > live.json
jq -e --slurpfile want allowlist/allowlist.json \
  '. as $live | $want[0].workloads | to_entries | all(.value == $live.workloads[.key])' live.json >/dev/null \
  || fail "the active allowlist differs from the seed and launch workloads this build produced"
echo "ok: launch allowlist active as built"

# CDS secrets: the gateway's pepper and the gwstate volume key.
c8s cds ca --url "$cds" "${pin[@]}" --out mesh-ca.pem
openssl rand -hex 32 > pepper
c8s secrets put /confidential-inference/gateway/api-key-pepper --from-file pepper \
  --url "$cds" "${pin[@]}" --mesh-ca mesh-ca.pem --operator-key "$key"
c8s secrets put /confidential-inference/volumes/gwstate --from-file gwstate.escrow.json \
  --url "$cds" "${pin[@]}" --mesh-ca mesh-ca.pem --operator-key "$key"

# The gateway's CDS policy documents, as the operator tooling builds them:
# the served measurement set, and its entry for this launch's server key.
curl -fsSk "$cds/measurements" -o served-image-policy.json
jq -e --rawfile pub "$LAUNCH_DIR/server/pubkey" '
  {schema_version, tee, measurements: [.measurements[] | select((.approver_key | rtrimstr("\n")) == ($pub | rtrimstr("\n")))]}
  | if (.measurements | length) == 1 then . else error("want one server entry") end' \
  served-image-policy.json > cds-image-policy.json
c8s verify "$cds" --kind cds --mode armtls-cert --image-policy-file cds-image-policy.json \
  --served-policy-file served-image-policy.json --operator-keys "$operator_pub"
echo "ok: CDS attests, serves the launch measurements and the launch operator key"

# The front door's only route: / on $ROUTE_HOST to the gateway's mesh TLS
# port, whose leaf must name the gateway entry.
c8s routes add --new --url "$cds" "${pin[@]}" --operator-key "$key" --operator-keys "$operator_pub" \
  --host "$ROUTE_HOST" --path / --address "c8s-gateway.$ns.svc.cluster.local:9444" --workload gateway
# The acme name resolves through sslip.io; the cds one only here.
[ "$FRONT_DOOR_MODE" = acme ] || echo "$GUEST_IP $ROUTE_HOST" | sudo tee -a /etc/hosts >/dev/null

pub_der() { openssl pkey -in "$key" -pubout -outform DER; }
op_sha=$(pub_der | sha256sum | cut -d' ' -f1)
set_sha=$({ printf 'c8s-operator-key-set-v1\0'; pub_der | openssl dgst -sha256 -binary; } | sha256sum | cut -d' ' -f1)

# The admin signer the gateway trusts for /admin requests.
openssl ecparam -name prime256v1 -genkey -noout -out admin.key
openssl req -x509 -new -key admin.key -sha256 -days 1 -subj /CN=c8s-e2e-admin -out admin.crt
kubectl create namespace "$ns"
kubectl -n "$ns" create secret docker-registry ghcr-pull --docker-server ghcr.io \
  --docker-username "${GITHUB_ACTOR:-c8s-e2e}" --docker-password "$GH_TOKEN"
kubectl -n "$ns" create secret generic gateway-admin-mtls --from-file=client.crt=admin.crt

mapfile -t chart_args < chart-args
helm template confidential-inference ci/helm/confidential-inference "${chart_args[@]}" \
  --show-only templates/gateway.yaml \
  --set-file attestationReceipts.cds.imagePolicy=cds-image-policy.json \
  --set-file attestationReceipts.cds.servedImagePolicy=served-image-policy.json \
  --set-string "attestationReceipts.expectedOperatorPublicKeySha256=sha256:$op_sha" \
  --set-string "attestationReceipts.expectedOperatorKeySetSha256=sha256:$set_sha" > identity.yaml
# The prepared render, with only its release-identity ConfigMap replaced.
python3 - manifest.yaml identity.yaml > deploy.yaml <<'EOF'
import sys
import yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if isinstance(d, dict)]
identity = next(d for d in yaml.safe_load_all(open(sys.argv[2]))
                if isinstance(d, dict) and d["kind"] == "ConfigMap" and d["metadata"]["name"] == "gateway-release-identity")
docs = [identity if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "gateway-release-identity" else d for d in docs]
yaml.safe_dump_all(docs, sys.stdout, sort_keys=False)
EOF
kubectl -n "$ns" apply -f deploy.yaml
# Not `rollout status`: a first pull can outlast the deployments' 10-minute
# progress deadline. The minute-by-minute listing is the timeline a failure
# needs; exec is closed on the node image.
dump() {
  kubectl get namespace "$ns" -o jsonpath='{.status.phase} {.metadata.deletionTimestamp}{"\n"}' || true
  kubectl get nodes -o json | jq -r '.items[] | (.spec.taints // [] | .[] | "node taint \(.key):\(.effect) since \(.timeAdded)"),
    (.status.conditions[] | "node \(.type)=\(.status) since \(.lastTransitionTime) \(.message)")'
  kubectl -n "$ns" get events --sort-by=.lastTimestamp | tail -60
  for p in $(kubectl -n "$ns" get pods -o name); do
    kubectl -n "$ns" get "$p" -o json | jq -r '
      "\(.metadata.name) deletion=\(.metadata.deletionTimestamp) phase=\(.status.phase) reason=\(.status.reason) \(.status.message)",
      ((.status.initContainerStatuses // []) + (.status.containerStatuses // []) | .[]
      | "  \(.name): ready=\(.ready) restarts=\(.restartCount) state=\(.state) last=\(.lastState.terminated // {} | tostring | .[0:600])")'
  done
}
ready=""
for _ in $(seq 1 30); do
  kubectl -n "$ns" get pods --no-headers -o wide | sed "s/^/$(date -u +%H:%M:%S) /"
  if kubectl -n "$ns" get pods -o json | jq -e '
      [.items[] | select(.metadata.deletionTimestamp == null)
       | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))] | length == 3' >/dev/null; then
    ready=1
    break
  fi
  sleep 60
done
if [ -z "$ready" ]; then
  dump
  fail "the gateway, router and worker did not all become ready in 30 minutes"
fi
echo "ok: gateway (pepper, gwstate, claims socket), worker and router are ready"

# TEErminator, built at the pinned commit, with its state in a temp HOME.
git init -q teerminator-src
git -C teerminator-src fetch -q --depth 1 "https://github.com/$TEERMINATOR_REPO.git" "$TEERMINATOR_COMMIT"
git -C teerminator-src checkout -q FETCH_HEAD
(cd teerminator-src && go build -o "$CIE_DIR/bin/teerminator" .)
# TEErminator keeps its state under os.UserConfigDir. HOME stays: rustup
# and cargo for verify-js.sh live there.
export XDG_CONFIG_HOME=$CIE_DIR/teerminator-home/config
mkdir -p "$XDG_CONFIG_HOME"
local_addr=127.0.0.1:18080
# TEErminator v0.0.3 and c8s-verify-js read a flat {mrtd, rtmr1, rtmr2}
# manifest; the node image publishes them under .tdx.
jq -e '.tdx | {mrtd, rtmr1, rtmr2}' "$IMAGE_MANIFEST" > tdx-image.json
# An acme front door serves pebble's WebPKI chain; TEErminator checks it
# against pebble's issuing root.
if [ "$FRONT_DOOR_MODE" = acme ]; then
  curl -fsk https://127.0.0.1:15000/roots/0 -o pebble-root.pem
  teerminator certs add pebble-root.pem
fi

# A verified row names the remote, attest-lb and Verified.
verified() {
  local out
  out=$(teerminator status --timeout 60s 2>&1) || true
  echo "$out"
  grep -Eq "^${local_addr}[[:space:]].*attest-lb[[:space:]].*Verified[[:space:]]*$" <<<"$out"
}

# Stamps follow allowlist writes within the get-cert renewal backoff (2s
# doubling to 30s), so allow a few rounds.
attest() {
  teerminator remote rm "$local_addr" >/dev/null 2>&1 || true
  teerminator remote add "$local_addr" "https://$ROUTE_HOST" --mode attest-lb --server-name "$SERVER_NAME" \
    --image-manifest tdx-image.json --tdx-tcb-status UpToDate --workload "$router" \
    --route-operator-key "$operator_pub"
  for _ in $(seq 1 12); do verified && return 0; sleep 10; done
  fail "the front door is not Verified as $router"
}

# The inference path on failure. Exec and the API server's proxy are closed
# on the node image, so a plain (non-cw) probe pod with the gateway's labels
# asks the router at the address the gateway dials, and reports through its
# termination message.
inference_dump() {
  local busybox=busybox:1.36 digest probe=router-probe
  digest=$(c8s allowlist inspect-image "$busybox" | awk '$1 == "digest:" { print $2 }') || true
  c8s allowlist add "$digest" "$busybox" --url "$front" "${pin[@]}" --operator-key "$key" >/dev/null || true
  # shellcheck disable=SC2016 # $p expands in the probe's shell.
  kubectl -n "$ns" run "$probe" --image="$busybox" --restart=Never --labels=app.kubernetes.io/component=gateway \
    --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65534,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"probe","image":"'"$busybox"'","command":["sh","-c","for p in workers health v1/models; do echo \"== $p\"; wget -qO- -T 5 http://c8s-sglang-router.confidential-inference.svc.cluster.local:30000/$p 2>&1 | head -c 700; echo; done > /dev/termination-log"],"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}' \
    >/dev/null || true
  local msg=""
  for _ in $(seq 1 30); do
    msg=$(kubectl -n "$ns" get pod "$probe" -o jsonpath='{.status.containerStatuses[0].state.terminated.message}' 2>/dev/null || true)
    [ -n "$msg" ] && break
    sleep 2
  done
  echo "router as seen by a plain pod with the gateway's labels:"
  echo "${msg:-no answer}"
  kubectl -n "$ns" get pod "$probe" -o jsonpath='{.status.containerStatuses[0].state}{"\n"}' || true
  kubectl -n "$ns" delete pod "$probe" --wait=false >/dev/null 2>&1 || true
  kubectl -n c8s-system get pods -o wide || true
  kubectl get events -A --sort-by=.lastTimestamp 2>&1 | tail -80 || true
  local pod container
  for pod in $(kubectl -n "$ns" get pods -o name 2>/dev/null) \
    $(kubectl -n c8s-system get pods -o name 2>/dev/null | grep -E 'armtls-mesh|c8s-cds|c8s-router'); do
    local pns=$ns
    kubectl -n "$ns" get "$pod" >/dev/null 2>&1 || pns=c8s-system
    kubectl -n "$pns" get "$pod" -o json | jq -r '
      "\(.metadata.name):", ((.status.initContainerStatuses // []) + (.status.containerStatuses // []) | .[]
      | "  \(.name): ready=\(.ready) restarts=\(.restartCount) state=\(.state | tostring | .[0:300])")' || true
    for container in $(kubectl -n "$pns" get "$pod" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}' 2>/dev/null); do
      echo "== logs $pns/${pod#pod/}/$container"
      kubectl -n "$pns" logs "$pod" -c "$container" --tail=40 2>&1 || true
    done
  done
}

proxy_pid=""
trap '[ -z "$proxy_pid" ] || kill "$proxy_pid" 2>/dev/null || true' EXIT
start_proxy() {
  [ -z "$proxy_pid" ] || kill "$proxy_pid" 2>/dev/null || true
  teerminator start > teerminator.log 2>&1 &
  proxy_pid=$!
  for _ in $(seq 1 30); do curl -s -o /dev/null "http://$local_addr/" && return 0; sleep 1; done
  cat teerminator.log
  fail "the TEErminator proxy did not start"
}

# One customer round: attest, pin the served allowlist, re-attest with the
# pin, and use the API through the verifying proxy.
customer_round() {
  local fetched=$1
  attest
  # After an upload the front door's leaf still names the previous snapshot
  # until get-cert renews it, and fetch refuses that mismatch.
  local i
  for i in $(seq 1 12); do
    teerminator allowlist fetch "$local_addr" -o "$fetched" --pin && break
    [ "$i" -lt 12 ] || fail "the front door's stamp never named the served allowlist"
    sleep 10
  done
  verified || fail "status is not Verified with the pinned allowlist"
  c8s allowlist export --url "$front" "${pin[@]}" > exported.json
  cmp -s "$fetched" exported.json || fail "/allowlist bytes differ from c8s allowlist export"
  start_proxy
  python3 "$here/client.py" mint-key --admin-key admin.key --out api-key
  python3 "$here/client.py" complete --api-key-file api-key || { inference_dump; fail "no completion through the gateway"; }
  workload_args=()
  for app in "${apps[@]}"; do workload_args+=(--workload "$app"); done
  python3 "$here/client.py" attestation --mode "$FRONT_DOOR_MODE" --allowlist "$fetched" "${workload_args[@]}"
  IMAGE_MANIFEST=$CIE_DIR/tdx-image.json "$here/verify-js.sh" "https://$ROUTE_HOST" "$router" api-key "$fetched" "$operator_pub"
}

customer_round fetched-launch.json
echo "ok: launch allowlist path verified"

c8s allowlist upload allowlist/allowlist.json --url "$front" "${pin[@]}" --operator-key "$key" --cvm-mode bare-metal
customer_round fetched-upload.json
cmp -s fetched-upload.json allowlist/allowlist.json || fail "the front door serves different bytes than the uploaded canonical allowlist"
echo "PASS: confidential-inference runs on this build and verifies from outside, by launch and by upload"
