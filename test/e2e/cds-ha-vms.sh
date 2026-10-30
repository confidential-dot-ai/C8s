#!/usr/bin/env bash
# Three CDS VMs serving one cluster on real SEV-SNP hardware: every replica
# admits its peers by their attestation, the operator posts the Genesis decree
# to one of them over the attested channel, and losing the leader's VM costs
# the cluster neither its mesh CA nor the address its clients dial.
#
# The lane's own CVMs are deleted first: the host may not hold this cluster
# beside them, so run this last in a lane's payload. It leaves the lane
# without CVMs; the cluster it created is deleted on the way out.
#
# Needs: c8s, jq, kubectl (launcher cluster).
# Env: NS, CDS_VM (the lane's CDS VM, whose spec every replica is cloned
# from), VM (the lane's node CVM, deleted for the host's capacity),
# CDS_IMAGE_MANIFEST, SMP (the vCPU count that image is launched with),
# NODE_CIDR, CDS_ALLOWLIST_SEED (the release's allowlist-seed-snp.json) and
# CDS_NODE_PINS (the node identities the cluster certifies, as a launch
# bundle's peers.json).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=test/e2e/lib.sh
. "$here/lib.sh"
: "${NS:?}" "${CDS_VM:?}" "${VM:?}" "${CDS_IMAGE_MANIFEST:?}" "${SMP:?}" "${NODE_CIDR:?}" \
  "${CDS_ALLOWLIST_SEED:?}" "${CDS_NODE_PINS:?}"

# The cluster id carries the lane's run, which the lane's VM name does, so
# every run starts a cluster of its own.
cluster=$CDS_VM-ha
replicas=3
port=8443
work=$(mktemp -d)
names=()
for i in $(seq 1 $replicas); do
  names+=("$cluster-$i")
done

cleanup() {
  kubectl -n "$NS" delete vm "${names[@]}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl -n "$NS" delete svc "$cluster" "${names[@]}" --ignore-not-found >/dev/null 2>&1 || true
  for name in "${names[@]}"; do
    kubectl -n "$NS" delete secret "$name-opkey" --ignore-not-found >/dev/null 2>&1 || true
  done
  rm -rf "$work"
}
trap cleanup EXIT
cd "$work"

# waiting runs a command until it succeeds, for up to ten minutes.
waiting() {
  local what="$1"
  shift
  for _ in $(seq 1 120); do
    "$@" && return 0
    sleep 5
  done
  fail "$what"
}

# The Services come first: the measured configuration names every replica's
# address before any VM boots on it, and a ClusterIP is one the cluster hands
# out up front. The last Service carries every replica, and is the one address
# a node document names.
for name in "${names[@]}"; do
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: $name
  namespace: $NS
spec:
  selector: {kubevirt.io/domain: $name}
  ports: [{port: $port, targetPort: $port}]
EOF
done
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: $cluster
  namespace: $NS
spec:
  selector: {ci.confidential.ai/cds-cluster: $cluster}
  ports: [{port: $port, targetPort: $port}]
EOF

address() { kubectl -n "$NS" get svc "$1" -o jsonpath='{.spec.clusterIP}'; }
has_address() { address "$1" 2>/dev/null | grep -q .; }
# Every replica's address, in the order the Services were created, and the one
# address the cluster's clients dial.
addresses=()
entries=()
for name in "${names[@]}" "$cluster"; do
  waiting "the Service $name got no address" has_address "$name"
done
for name in "${names[@]}"; do
  addresses+=("$(address "$name")")
  entries+=(--replica "$(address "$name")")
done
served=$(address "$cluster")
echo "the replicas answer at ${addresses[*]}, and clients dial $served:$port"

# One configuration for every replica: nothing in it names one of them. The
# operator key signs the decrees this cluster acts on.
c8s keys new --out operator.key --pub-out operator-pub.pem
c8s cds config new \
  --out launch \
  --cluster-id "$cluster" \
  --operator-keys operator-pub.pem \
  --allowlist-seed "$CDS_ALLOWLIST_SEED" \
  --node-pins "$CDS_NODE_PINS" \
  --node-cidr "$NODE_CIDR" \
  --pod-cidr 10.52.0.0/16 \
  --service-cidr 10.53.0.0/16 \
  --image-manifest "$CDS_IMAGE_MANIFEST" \
  --platform sev-snp \
  --vcpus "$SMP" \
  "${entries[@]}" \
  --voters "$replicas"

# Each replica's opkeydata disk holds that one file, under the name the lane's
# CDS secret gives it: the initrd binds those bytes to the VM's attestation,
# and launch/cds-pin.json names the digest every client checks.
key=$(kubectl -n "$NS" get secret "$CDS_VM-opkey" -o json |
  jq -er '.data | keys | if length == 1 then .[0] else error("want one file on the CDS opkeydata disk") end')
for name in "${names[@]}"; do
  kubectl -n "$NS" create secret generic "$name-opkey" \
    --from-file="$key=launch/cds-config.yaml"
done

# Every replica is the lane's CDS VM with its own opkeydata secret and the
# label both Services select it by.
creating=()
for name in "${names[@]}"; do
  kubectl -n "$NS" get vm "$CDS_VM" -o json | jq --arg name "$name" --arg cluster "$cluster" '
    {apiVersion, kind,
     metadata: {name: $name, namespace: .metadata.namespace, labels: .metadata.labels, annotations: .metadata.annotations},
     spec: (.spec
       | .template.metadata.labels["kubevirt.io/domain"] = $name
       | .template.metadata.labels["ci.confidential.ai/cds-cluster"] = $cluster
       | .template.spec.volumes |= map(
           if .name == "opkey" then .secret.secretName = "\($name)-opkey" else . end))}' > "vm-$name.json"
  creating+=(-f "vm-$name.json")
done
kubectl -n "$NS" delete vm "$VM" "$CDS_VM" --wait=true --timeout=180s
kubectl -n "$NS" wait --for=delete "vmi/$VM" "vmi/$CDS_VM" --timeout=180s
kubectl -n "$NS" create "${creating[@]}"

# A replica answers before it holds a cluster: it reports the member id and
# the mesh CA a Genesis decree names. The probe is unattested, as a readiness
# probe is; every check below reads the replicas over the attested channel.
answering() {
  [ "$(curl -sk --connect-timeout 2 --max-time 4 -o /dev/null -w '%{http_code}' "https://$1:$port/healthz" || true)" = 200 ]
}
for i in "${!names[@]}"; do
  waiting "replica ${names[$i]} never answered" answering "${addresses[$i]}"
done
echo "every replica answers, and none of them holds a cluster"

ha() { c8s cds ha "$@" --config launch/cds-config.yaml --cds-pin launch/cds-pin.json; }

# The Genesis decree names one replica's member id and the mesh CA that
# process would install, both read over the attested channel, and is posted
# back to that replica on the same channel.
c8s cds ha decree genesis \
  --config launch/cds-config.yaml --operator-key operator.key \
  --target "${addresses[0]}:$port" --cds-pin launch/cds-pin.json \
  --platform sev-snp --vcpus "$SMP" --image-manifest "$CDS_IMAGE_MANIFEST" \
  --resume-version 0 \
  --out genesis.json
intent=$(jq -er .decree.intent_id genesis.json)

# `ha status` exits non-zero unless every replica the configuration names
# serves this one cluster at one version under one mesh CA.
serves_as_one() { ha status > status.txt 2>&1; }
waiting "the cluster never served from every replica" serves_as_one
[ "$(grep -c 'state="Leader"' status.txt)" = 1 ] || { cat status.txt; fail "not exactly one leader"; }
cat status.txt
ha decrees | grep -q "$intent" || fail "the record of applied decrees does not name the Genesis"

# What a client holds: the mesh CA served behind the one address it dials.
# `cds ca` pins CDS with --image-policy-file, the same document the ha
# commands take as --cds-pin.
mesh_ca() {
  c8s cds ca --url "https://$served:$port" --image-policy-file launch/cds-pin.json --out "$1" \
    || fail "no mesh CA from the cluster at $served:$port"
  openssl x509 -in "$1" -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1
}
before=$(mesh_ca mesh-ca.pem)
echo "the cluster serves mesh CA $before behind $served:$port"

# The leader's VM is lost. The cluster elects another replica, and a client
# dialling the same address reaches one that serves.
leader=$(ha status --json | jq -er '.[] | select(.status.state == "Leader") | .address')
lost=""
survivors=()
for i in "${!names[@]}"; do
  if [ "$leader" = "${addresses[$i]}:$port" ]; then
    lost=${names[$i]}
    continue
  fi
  survivors+=(--url "${addresses[$i]}:$port")
done
[ -n "$lost" ] || fail "the leader answers at $leader, which is no replica of this cluster"
echo "losing the leader's VM, $lost"
kubectl -n "$NS" delete vm "$lost" --wait=true --timeout=180s

elected() { ha status "${survivors[@]}" > survivors.txt 2>&1 && grep -q 'state="Leader"' survivors.txt; }
waiting "the replicas that stayed elected no leader" elected
cat survivors.txt

after=$(mesh_ca mesh-ca-after.pem)
[ "$after" = "$before" ] || fail "the cluster serves mesh CA $after behind $served:$port, and served $before before its leader was lost"
echo "PASS: three CDS VMs, one cluster: the leader's VM is gone, the mesh CA and the address its clients dial are not"
