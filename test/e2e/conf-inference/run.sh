#!/usr/bin/env bash
# Post-boot half of the confidential-inference e2e on the tdx-metal lane:
# deploy the pinned release's gateway, simulator worker and router on the
# measured node, then check from outside, as a customer does, with
# TEErminator and the gateway API. Nothing here skips; a missing input fails.
#
# The node was launched with prepare.sh's app.json as --workloads and the
# gateway as --router-upstream. After the launch-path checks the script
# uploads the full allowlist with `c8s allowlist upload` and checks again.
#
# Env: GUEST_IP, KUBECONFIG, CIE_DIR (prepare.sh's output), LAUNCH_DIR
# (launch-config new --out), IMAGE_MANIFEST.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/../lib.sh"
. "$here/pins.env"
: "${GUEST_IP:?}" "${KUBECONFIG:?}" "${CIE_DIR:?}" "${LAUNCH_DIR:?}" "${IMAGE_MANIFEST:?}"
export PATH="$CIE_DIR/bin:$PATH"
cd "$CIE_DIR"

ns=confidential-inference
front=https://$GUEST_IP:443
cds=https://$GUEST_IP:30808
pin=(--image-policy-file "$LAUNCH_DIR/server.json")
key=$LAUNCH_DIR/server.key
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
  --served-policy-file served-image-policy.json --operator-keys "$LAUNCH_DIR/server/pubkey"
echo "ok: CDS attests, serves the launch measurements and the launch operator key"

pub_der() { openssl pkey -in "$key" -pubout -outform DER; }
op_sha=$(pub_der | sha256sum | cut -d' ' -f1)
set_sha=$({ printf 'c8s-operator-key-set-v1\0'; pub_der | openssl dgst -sha256 -binary; } | sha256sum | cut -d' ' -f1)

# The admin signer the gateway trusts for /admin requests.
openssl ecparam -name prime256v1 -genkey -noout -out admin.key
openssl req -x509 -new -key admin.key -sha256 -days 1 -subj /CN=c8s-e2e-admin -out admin.crt
kubectl create namespace "$ns"
kubectl -n "$ns" create secret generic gateway-admin-mtls --from-file=client.crt=admin.crt

helm template confidential-inference ci/helm/confidential-inference --namespace "$ns" --kube-version 1.32.0 \
  --values release/profile-values-release-values.yaml \
  --values release/profile-values-release-staging-values.yaml \
  --values release/release-values.yaml \
  --values "$here/values.yaml" \
  --set-file attestationReceipts.cds.imagePolicy=cds-image-policy.json \
  --set-file attestationReceipts.cds.servedImagePolicy=served-image-policy.json \
  --set-string "attestationReceipts.expectedOperatorPublicKeySha256=sha256:$op_sha" \
  --set-string "attestationReceipts.expectedOperatorKeySetSha256=sha256:$set_sha" \
  | kubectl -n "$ns" apply -f -
for workload in deployment/gateway deployment/sglang-router statefulset/inference-worker-0; do
  if ! kubectl -n "$ns" rollout status "$workload" --timeout=20m; then
    kubectl -n "$ns" get pods -o wide
    for p in $(kubectl -n "$ns" get pods -o name); do
      kubectl -n "$ns" get "$p" -o json | jq -r '
        (.status.initContainerStatuses // []) + (.status.containerStatuses // []) | .[]
        | "\(.name): ready=\(.ready) restarts=\(.restartCount) state=\(.state) last=\(.lastState.terminated // {} | tostring | .[0:600])"'
      kubectl -n "$ns" describe "$p" | sed -n '/^Events:/,$p' | tail -10
    done
    fail "$workload did not become ready"
  fi
done
echo "ok: gateway (pepper, gwstate, claims socket), worker and router are ready"

# TEErminator, built at the pinned commit, with its state in a temp HOME.
git init -q teerminator-src
git -C teerminator-src fetch -q --depth 1 "https://github.com/$TEERMINATOR_REPO.git" "$TEERMINATOR_COMMIT"
git -C teerminator-src checkout -q FETCH_HEAD
(cd teerminator-src && go build -o "$CIE_DIR/bin/teerminator" .)
export HOME=$CIE_DIR/teerminator-home XDG_CONFIG_HOME=$CIE_DIR/teerminator-home/config
mkdir -p "$XDG_CONFIG_HOME"
local_addr=127.0.0.1:18080

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
  teerminator remote add "$local_addr" "https://$GUEST_IP" --mode attest-lb --server-name c8s.local \
    --image-manifest "$IMAGE_MANIFEST" --tdx-tcb-status UpToDate --workload "$router"
  for _ in $(seq 1 12); do verified && return 0; sleep 10; done
  fail "the front door is not Verified as $router"
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
  teerminator allowlist fetch "$local_addr" -o "$fetched" --pin
  verified || fail "status is not Verified with the pinned allowlist"
  c8s allowlist export --url "$front" "${pin[@]}" > exported.json
  cmp -s "$fetched" exported.json || fail "/allowlist bytes differ from c8s allowlist export"
  start_proxy
  api_key=$(python3 "$here/client.py" mint-key --admin-key admin.key)
  python3 "$here/client.py" complete --api-key "$api_key"
  "$here/verify-js.sh" "$router" "$api_key" "$fetched"
  workload_args=()
  for app in "${apps[@]}"; do workload_args+=(--workload "$app"); done
  python3 "$here/client.py" attestation --allowlist "$fetched" "${workload_args[@]}"
}

customer_round fetched-launch.json
echo "ok: launch allowlist path verified"

c8s allowlist upload allowlist/allowlist.json --url "$front" "${pin[@]}" --operator-key "$key" --cvm-mode bare-metal
customer_round fetched-upload.json
cmp -s fetched-upload.json allowlist/allowlist.json || fail "the front door serves different bytes than the uploaded canonical allowlist"
echo "PASS: confidential-inference runs on this build and verifies from outside, by launch and by upload"
