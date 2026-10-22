#!/usr/bin/env bash
# The router in the acme front-door mode on the measured image: its pod must
# match the seeded router entry and get that name stamped, as in cds mode.
#
# The lane boots in cds mode. A baked router pod has one shape for both
# modes, but in acme mode its acme sidecar issues instead of standing by, and
# nginx and cds-attest serve the ACME leaf. So this boots a second CVM from
# the lane VM's spec, with a launch that names a router hostname and an ACME
# directory that does not resolve. Nothing is issued and the front door keeps
# the sidecar's self-signed placeholder, which attest-lb binds like a real
# ACME leaf. `c8s verify` then checks from outside that the leaf behind the
# front door is stamped with the seeded router entry.
#
# Deletes the lane's CVM first: the host may not hold two.
# Env: NS, VM (the lane's CVM), IMAGE_MANIFEST, ROUTER_SEED (the seed this
# build renders, prepare.sh's node-image/allowlist-seed.json).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"
: "${NS:?}" "${VM:?}" "${IMAGE_MANIFEST:?}" "${ROUTER_SEED:?}"

acme_vm=$VM-acme
host=front.c8s-e2e.test
work=$(mktemp -d)
cd "$work"
router=$(jq -er '[.workloads | keys[] | select(startswith("c8s-router-"))] | if length == 1 then .[0] else error("want one router entry") end' "$ROUTER_SEED")
echo "seeded router entry: $router"

# The ACME directory is under .invalid, so the sidecar can reach no CA.
c8s launch-config new --out launch --cluster-id "$acme_vm" --server-name c8s-node \
  --image-manifest "$IMAGE_MANIFEST" \
  --router-hostname "$host" --acme-directory-url https://acme.invalid/directory
kubectl -n "$NS" create secret generic "$acme_vm-opkey" \
  --from-file=pubkey=launch/server/pubkey \
  --from-file=launch.yaml=launch/server/launch.yaml \
  --from-file=launch.yaml.sig=launch/server/launch.yaml.sig

# The lane VM's spec with this launch's opkey and a scratch disk of its own,
# and without the gateway's state disk.
kubectl -n "$NS" get vm "$VM" -o json | jq --arg name "$acme_vm" '
  {apiVersion, kind,
   metadata: {name: $name, namespace: .metadata.namespace, labels: .metadata.labels, annotations: .metadata.annotations},
   spec: (.spec
     | .template.metadata.labels["kubevirt.io/domain"] = $name
     | .template.spec.domain.devices.disks |= map(select(.name != "gwstate"))
     | .template.spec.volumes |= map(select(.name != "gwstate")
         | if .name == "scratch" then .persistentVolumeClaim.claimName = "\($name)-scratch"
           elif .name == "opkey" then .secret.secretName = "\($name)-opkey"
           else . end))}' > vm.json
kubectl -n "$NS" get pvc "$VM-scratch" -o json | jq --arg name "$acme_vm-scratch" '
  {apiVersion, kind, metadata: {name: $name, namespace: .metadata.namespace, labels: .metadata.labels},
   spec: (.spec | {accessModes, resources, storageClassName})}' > scratch.json
kubectl -n "$NS" delete vm "$VM" --wait=true --timeout=180s
kubectl -n "$NS" wait --for=delete "vmi/$VM" --timeout=180s
kubectl create -f scratch.json -f vm.json

ip=""
for _ in $(seq 1 60); do
  ip=$(kubectl -n "$NS" get vmi "$acme_vm" -o jsonpath='{.status.interfaces[0].ipAddress}' 2>/dev/null || true)
  [ -n "$ip" ] && break
  sleep 5
done
[ -n "$ip" ] || { kubectl -n "$NS" describe vmi "$acme_vm" | tail -25; fail "the acme-mode CVM got no IP"; }
for _ in $(seq 1 120); do
  code=$(curl -sk --connect-timeout 2 --max-time 4 -o /dev/null -w '%{http_code}' "https://$ip:8443/" || true)
  [ "${code:-000}" != 000 ] && break
  sleep 5
done
c8s get-kubeconfig --node "$ip" --operator-key launch/server.key --image-manifest "$IMAGE_MANIFEST" \
  --out kubeconfig --timeout 180s
export KUBECONFIG=$work/kubeconfig

# The kubeconfig is served before CDS is up.
for _ in $(seq 1 30); do
  c8s cds ca --url "https://$ip:30808" --image-policy-file launch/server.json --out mesh-ca.pem && break
  sleep 10
done
[ -s mesh-ca.pem ] || { echo "FAIL: no mesh CA from CDS at $ip:30808" >&2; exit 1; }

# The router pod starts once the acme sidecar has written its placeholder,
# and get-cert's stamp follows the pod's match.
verdict() {
  c8s verify "https://$ip:443" --kind lb --mode attest-lb --server-name "$host" \
    --image-policy-file launch/server.json --mesh-ca mesh-ca.pem --workload "$router" -o json > verdict.json
}
ok=""
for _ in $(seq 1 30); do
  if verdict; then ok=1; break; fi
  sleep 10
done
if [ -z "$ok" ]; then
  cat verdict.json || true
  kubectl -n c8s-router get pods -o json | jq -r '.items[] | "\(.metadata.name) phase=\(.status.phase)",
    ((.status.initContainerStatuses // []) + (.status.containerStatuses // []) | .[]
    | "  \(.name): ready=\(.ready) restarts=\(.restartCount) state=\(.state | tostring | .[0:300])")' || true
  for c in c8s-cert acme cds-attest; do
    echo "== logs c8s-router/$c"
    kubectl -n c8s-router logs deploy/c8s-router -c "$c" --tail=40 2>&1 || true
  done
  fail "the acme-mode front door is not verified as $router"
fi
jq . verdict.json

# The leaf the verdict binds is the acme sidecar's self-signed placeholder,
# not the CDS-issued leaf the cds mode serves.
openssl s_client -connect "$ip:443" -servername "$host" </dev/null 2>/dev/null | openssl x509 > serving.pem
[ "$(openssl x509 -in serving.pem -noout -issuer_hash)" = "$(openssl x509 -in serving.pem -noout -subject_hash)" ] \
  || fail "the front door serves an issued leaf, not the acme placeholder"
digest=$(openssl x509 -in serving.pem -outform DER | openssl dgst -sha256 -binary | base64 -w0 | tr '+/' '-_' | tr -d '=')
jq -e --arg d "$digest" '.serving_leaf_sha256 == $d' verdict.json >/dev/null \
  || fail "the verdict binds another serving leaf than the placeholder"
echo "PASS: in acme mode the router matches $router and attest-lb binds the acme leaf"
