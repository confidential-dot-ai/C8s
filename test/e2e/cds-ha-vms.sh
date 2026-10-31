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
  publishNotReadyAddresses: true
  selector: {kubevirt.io/domain: $name}
  ports:
    - {name: client, port: $port, targetPort: $port}
    - {name: peer, port: 8444, targetPort: 8444}
EOF
done
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: $cluster
  namespace: $NS
spec:
  publishNotReadyAddresses: false
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
host_data=$(openssl dgst -sha256 -binary launch/cds-config.yaml | base64 -w0)
for name in "${names[@]}"; do
  kubectl -n "$NS" get vm "$CDS_VM" -o json | jq --arg name "$name" --arg cluster "$cluster" --arg host_data "$host_data" --argjson port "$port" '
    {apiVersion, kind,
     metadata: {name: $name, namespace: .metadata.namespace, labels: .metadata.labels, annotations: .metadata.annotations},
     spec: (.spec
       | .template.metadata.annotations["snp.confidential.ai/host-data"] = $host_data
       | .template.metadata.labels["kubevirt.io/domain"] = $name
       | .template.metadata.labels["ci.confidential.ai/cds-cluster"] = $cluster
       | .template.spec.readinessProbe = {httpGet: {path: "/readyz", port: $port, scheme: "HTTPS"},
           initialDelaySeconds: 0, periodSeconds: 2, timeoutSeconds: 2, failureThreshold: 1, successThreshold: 1}
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

routing_ready() {
  kubectl -n "$NS" get endpointslices.discovery.k8s.io -l "kubernetes.io/service-name=$cluster" -o json > endpoints.json || return
  kubectl -n "$NS" get pods -l "ci.confidential.ai/cds-cluster=$cluster" -o json > launchers.json || return
  jq -e --argjson count "$1" --slurpfile slices endpoints.json '
    [.items[] | select(any(.status.conditions[]?; .type == "Ready" and .status == "True")) | .metadata.name] | sort as $ready |
    length == $count and ($slices[0] | [.items[].endpoints[]? | select(.conditions.ready == true) | .targetRef.name] | unique | sort) == $ready
  ' launchers.json >/dev/null || return
  [ "$(jq '.items | length' launchers.json)" = 3 ] || return
  local i code pod_ready
  for i in "${!names[@]}"; do
    code=$(curl -sk --connect-timeout 2 --max-time 4 -o "ready-${names[$i]}.txt" -w '%{http_code}' "https://${addresses[$i]}:$port/readyz") || return
    pod_ready=$(jq -r --arg name "${names[$i]}" '[.items[] | select(.metadata.labels["kubevirt.io/domain"] == $name) | any(.status.conditions[]?; .type == "Ready" and .status == "True")] | if length == 1 then .[0] else null end' launchers.json)
    case "$code:$pod_ready" in 200:true|503:false) ;; *) return 1 ;; esac
  done
}
waiting "unjoined guests entered client endpoints" routing_ready 0
ha status --json > unjoined.json 2> status-error.txt || :
jq -e 'length == 3 and all(.[]; .status != null and .status.joined == false)' unjoined.json >/dev/null || fail "unjoined control addresses are unreachable"

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
waiting "three ready guests never entered client endpoints" routing_ready 3
ha status --json > original.json
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

# Restore the baseline's lost process before accumulating clock quarantines.
kubectl -n "$NS" wait --for=delete "vmi/$lost" --timeout=180s
kubectl -n "$NS" create -f "vm-$lost.json"
restored() {
  ha status --json > restored.json 2> status-error.txt || return
  jq -e --slurpfile original original.json --arg lost "$leader" '
    . as $now | [.[].status.id] | sort as $ids |
    length == 3 and all($now[]; (.status.voters | sort) == $ids) and
    any($now[]; .status.state == "Leader" and .status.roll_safe.ok == true) and
    all($original[0][]; . as $old | any($now[];
      .address == $old.address and .status.ca_fingerprint == $old.status.ca_fingerprint and
      (if .address == $lost then .status.id != $old.status.id else .status.id == $old.status.id end)))
  ' restored.json >/dev/null
}
waiting "the restored VM never regained three healthy voter seats" restored
waiting "restored guests never regained three ready endpoints" routing_ready 3
[ "$(mesh_ca mesh-ca-restored.pem)" = "$before" ] || fail "restoration changed the mesh CA"
cat restored.json

# Pause can induce an ordinary election; the resumed cluster must have an eligible leader.
printf '{}\n' > pause.json
resumed_targets=()
clock_lag_verified() {
  ha status --json > clock.json 2> status-error.txt || :
  jq -e --slurpfile baseline restored.json --argjson count "${#resumed_targets[@]}" '
    . as $now | [$baseline[0][].status.id] | sort as $ids |
    ($now | length) == 3 and all($now[]; . as $current | .status != null and
      (.status.voters | sort) == $ids and (.status.stuck // "") == "" and
      any($baseline[0][]; .address == $current.address and .status.id == $current.status.id and
        .status.ca_fingerprint == $current.status.ca_fingerprint and
        .status.applied_index <= $current.status.applied_index)) and
    ([$now[] | select(.status.serving.reason // "" | contains("clock lags member "))] | length) == $count and
    ([$now[] | select(.status.serving.ok)] | length) == (3 - $count) and
    any($now[]; .status.state == "Leader" and .status.serving.ok and .status.roll_safe.ok == false)
  ' clock.json >/dev/null || return
  local address
  for address in "${resumed_targets[@]}"; do
    jq -e --arg address "$address" 'any(.[]; .address == $address and (.status.serving.reason // "" | contains("clock lags member ")))' clock.json >/dev/null || return
  done
}
for round in 1 2; do
  if [ "$round" = 1 ]; then
    target=$(jq -er '[.[] | select(.status.state != "Leader")][0].address' restored.json)
  else
    target=$(jq -er '.[] | select(.status.state == "Leader" and .status.serving.ok) | .address' clock.json)
  fi
  name=""
  for i in "${!names[@]}"; do
    [ "$target" != "${addresses[$i]}:$port" ] || name=${names[$i]}
  done
  [ -n "$name" ] || fail "no VM for $target"
  kubectl replace --raw "/apis/subresources.kubevirt.io/v1/namespaces/$NS/virtualmachineinstances/$name/pause" -f pause.json || fail "UNVALIDATED: KubeVirt pause unavailable"
  sleep 45
  kubectl replace --raw "/apis/subresources.kubevirt.io/v1/namespaces/$NS/virtualmachineinstances/$name/unpause" -f pause.json || fail "UNVALIDATED: KubeVirt unpause unavailable"
  resumed_targets+=("$target")
  waiting "UNVALIDATED: no retained clock-lag observation and eligible leadership after resuming $name" clock_lag_verified
  cat clock.json
  waiting "guest readiness did not propagate after resuming $name" routing_ready "$((3-round))"
done
jq '{launchers: [.items[] | {name: .metadata.name, conditions: .status.conditions}]}' launchers.json
cat endpoints.json
for name in "${names[@]}"; do printf '%s readiness: ' "$name"; cat "ready-$name.txt"; done
printf 'clock-routing-regression\n' > clock-value
for i in $(seq 1 98); do
  c8s secrets put "/clock-$i" --url "https://$served:$port" --image-policy-file launch/cds-pin.json \
    --mesh-ca mesh-ca.pem --operator-key operator.key --from-file clock-value || fail "aggregate write $i failed"
done
clock_lag_verified || fail "clock state changed during fresh writes"
watermark=$(jq -er '.[] | select(.status.state == "Leader") | .status.applied_index' clock.json)
applied_writes() { clock_lag_verified && jq -e --argjson watermark "$watermark" 'all(.[]; .status.applied_index >= $watermark)' clock.json >/dev/null; }
waiting "quarantined voters stopped applying fresh writes" applied_writes
[ "$(mesh_ca mesh-ca-clock.pem)" = "$before" ] || fail "clock quarantine changed the mesh CA"
echo "PASS: two clock-quarantined voters retained state; one ready guest accepted 98 fresh signed aggregate writes"
