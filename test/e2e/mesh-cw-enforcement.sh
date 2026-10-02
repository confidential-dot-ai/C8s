#!/usr/bin/env bash
# Live-cluster verification that the workload path is mesh-wrapped and that
# plaintext bypass to confidential-workload pods fails closed
# (ratlsMesh.cwInboundEnforcement). Proves on a real cluster what unit and
# chart tests cannot: a dial to a cw pod IP is actually intercepted and
# wrapped (the mesh inbound counter moves on the workload's node), the
# FORWARD drop actually fires on this cluster's CNI for Service-VIP and
# excluded-namespace traffic, the drop counter records it, and the egress
# guard's DNS carve-out is written so it can match in that chain at all. The inbound
# connection counter is the wrap signal; no packet capture (tcpdump on CVM
# node images is flaky and adds nothing the counters don't prove).
#
# Needs: kubectl pointed at a cluster with the C8s chart installed and a
# Running confidential workload (a pod labeled confidential.ai/cw).
#
# Env:
#   CW_NS / CW_ID   pick a specific workload (default: first Running cw pod)
#   CW_PORT         port to probe (default: the pod's first containerPort)
#   CLIENT_IMAGE    curl-capable client image (default curl 8.8.0, digest-pinned)
#   CLIENT_UID      numeric non-root UID declared by that image (default 100,
#                   the verified curl_user UID in the pinned default)
#   EXCLUDED_NS     mesh-excluded source namespace (default kube-system)
#   MESH_HEALTH_PORT     ratls-mesh health/metrics port (chart
#                        ratlsMesh.ports.health; default 15021)
#   MESH_NS              namespace the chart is installed in (default
#                        c8s-system), read for the ratls-mesh DaemonSet
#   METRIC_WAIT_SECONDS  how long to wait for a counter to move; also the
#                        abort budget for a baseline that never gets a
#                        successful scrape (default 75; raise it above ~2x
#                        ratlsMesh.iptablesSync.resyncPeriod on clusters tuned
#                        to a longer resync)
set -euo pipefail
. "$(dirname "$0")/lib.sh"

client_image="${CLIENT_IMAGE:-curlimages/curl:8.8.0@sha256:73e4d532ea62d7505c5865b517d3704966ffe916609bedc22af6833dc9969bcd}"
client_uid="${CLIENT_UID:-100}"
excluded_ns="${EXCLUDED_NS:-kube-system}"
health_port="${MESH_HEALTH_PORT:-15021}"
mesh_ns="${MESH_NS:-c8s-system}"
metric_wait="${METRIC_WAIT_SECONDS:-75}"

[[ "$client_uid" =~ ^[1-9][0-9]*$ ]] \
  || fail "CLIENT_UID must be a positive numeric UID (got '$client_uid')"

ns="mesh-cw-check-$$"
client=client
excluded_pod="mesh-cw-check-excluded-$$"
vip_svc="mesh-cw-check-vip-$$"

cw_ns=""
cleanup() {
  kubectl delete namespace "$ns" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete pod "$excluded_pod" -n "$excluded_ns" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  [ -n "$cw_ns" ] && kubectl delete service "$vip_svc" -n "$cw_ns" --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- discover the confidential workload -------------------------------------

selector="confidential.ai/cw"
[ -n "${CW_ID:-}" ] && selector="confidential.ai/cw=${CW_ID}"
ns_flag=(--all-namespaces)
[ -n "${CW_NS:-}" ] && ns_flag=(-n "$CW_NS")

read -r cw_ns cw_pod < <(kubectl get pods "${ns_flag[@]}" -l "$selector" \
  --field-selector=status.phase=Running \
  -o jsonpath='{range .items[0]}{.metadata.namespace} {.metadata.name}{end}' 2>/dev/null) || true
[ -n "${cw_pod:-}" ] || fail "no Running pod labeled confidential.ai/cw found (set CW_NS/CW_ID to pick one)"

cw_ip=$(kubectl get pod "$cw_pod" -n "$cw_ns" -o jsonpath='{.status.podIP}')
cw_id=$(kubectl get pod "$cw_pod" -n "$cw_ns" -o jsonpath='{.metadata.labels.confidential\.ai/cw}')
cw_node=$(kubectl get pod "$cw_pod" -n "$cw_ns" -o jsonpath='{.spec.nodeName}')
cw_node_ip=$(kubectl get node "$cw_node" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
cw_port="${CW_PORT:-$(kubectl get pod "$cw_pod" -n "$cw_ns" -o jsonpath='{.spec.containers[0].ports[0].containerPort}')}"
[ -n "$cw_port" ] || fail "pod $cw_ns/$cw_pod declares no containerPort; set CW_PORT"

echo "workload: $cw_ns/$cw_pod (cw=$cw_id) at $cw_ip:$cw_port on $cw_node ($cw_node_ip)"

# --- client pod (fresh namespace: a normal, non-excluded mesh source) -------

kubectl create namespace "$ns" >/dev/null
# A plain client pod: restricted-compliant, since the fresh namespace inherits
# the node image's restricted PodSecurity default.
kubectl run "$client" -n "$ns" --image="$client_image" --restart=Never \
  --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":'"$client_uid"',"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"'"$client"'","image":"'"$client_image"'","command":["sleep","3600"],"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}' \
  >/dev/null
kubectl wait --for=condition=Ready pod/"$client" -n "$ns" --timeout=120s >/dev/null

client_node=$(kubectl get pod "$client" -n "$ns" -o jsonpath='{.spec.nodeName}')
client_node_ip=$(kubectl get node "$client_node" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')

client_curl() { kubectl exec -n "$ns" "$client" -- curl -s "$@"; }

# Sum a mesh metric from a node's ratls-mesh /metrics (hostNetwork). The
# health port is a node IP, never a pod IP, so this scrape is not itself
# mesh-intercepted. Exit 1 with no output marks a failed scrape, kept distinct
# from a genuine 0 (curl -f fails on HTTP errors; kubectl exec propagates the
# exit code): a blip must retry, never read as "counter is 0".
mesh_metric() {
  local node_ip=$1 pattern=$2 body
  body=$(client_curl -f --max-time 10 "http://${node_ip}:${health_port}/metrics" 2>/dev/null) || return 1
  awk -v p="$pattern" '$0 ~ p {sum += $NF} END {printf "%d", sum+0}' <<<"$body"
}

# Baselines gate every await_metric_above, so one must come from a genuine
# scrape. Retry until one scrape succeeds; abort if none does inside the
# budget.
metric_baseline() {
  local node_ip=$1 pattern=$2 what=$3 v
  local deadline=$((SECONDS + metric_wait))
  while :; do
    if v=$(mesh_metric "$node_ip" "$pattern"); then
      printf '%d\n' "$v"
      return 0
    fi
    [ $SECONDS -lt $deadline ] || break
    sleep 5
  done
  fail "$what: no successful metrics scrape of $node_ip:$health_port within ${metric_wait}s; cannot baseline"
}

# Poll until a metric exceeds a baseline, skipping failed scrapes rather than
# reading them as 0. The cw drop counter is published by the iptables-sync
# sidecar on its resync tick, so the default deadline gives two 30s ticks of
# headroom; raise METRIC_WAIT_SECONDS for a longer resyncPeriod.
await_metric_above() {
  local node_ip=$1 pattern=$2 baseline=$3 what=$4
  local deadline=$((SECONDS + metric_wait)) v scraped=""
  while [ $SECONDS -lt $deadline ]; do
    if v=$(mesh_metric "$node_ip" "$pattern"); then
      scraped=1
      [ "$v" -gt "$baseline" ] && { echo "ok: $what ($baseline -> $v)"; return 0; }
    fi
    sleep 5
  done
  [ -n "$scraped" ] || fail "$what: every metrics scrape of $node_ip:$health_port failed within ${metric_wait}s"
  fail "$what: no increase above $baseline within ${metric_wait}s"
}

# --- positive: a pod-IP dial is mesh-wrapped --------------------------------

inbound='^ratls_mesh_connections_total.*direction="inbound"'
base_inbound=$(metric_baseline "$cw_node_ip" "$inbound" "mesh inbound connections on $cw_node")

client_curl -o /dev/null --max-time 10 "http://${cw_ip}:${cw_port}/" \
  || fail "direct pod-IP request to $cw_ip:$cw_port failed (exit $?); the mesh-wrapped path must work"
echo "ok: pod-IP request answered"

await_metric_above "$cw_node_ip" "$inbound" "$base_inbound" \
  "mesh inbound connections on $cw_node moved: the hop was wrapped, not plaintext"

# --- negative: a Service VIP over the cw pods is dropped, not plaintext -----

kubectl apply -n "$cw_ns" -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata:
  name: $vip_svc
spec:
  type: ClusterIP
  selector:
    confidential.ai/cw: "$cw_id"
  ports:
    - port: $cw_port
      targetPort: $cw_port
EOF
vip=$(kubectl get service "$vip_svc" -n "$cw_ns" -o jsonpath='{.spec.clusterIP}')

# kube-proxy must have endpoints programmed before the bypass attempt means
# anything; otherwise the VIP times out for the wrong reason.
deadline=$((SECONDS + 60))
until kubectl get endpointslices -n "$cw_ns" -l "kubernetes.io/service-name=$vip_svc" \
    -o jsonpath='{.items[*].endpoints[*].addresses[*]}' 2>/dev/null | grep -q .; do
  [ $SECONDS -lt $deadline ] || fail "Service $vip_svc never got endpoints"
  sleep 2
done

drops='^ratls_mesh_iptables_cw_inbound_drops_total'
# The drop fires on the client's node: iptables-mode kube-proxy DNATs the VIP
# there, and the post-DNAT packet hits that node's FORWARD guard (cw ipset is
# cluster-wide). Under IPVS/nftables kube-proxy the VIP is rewritten off the
# FORWARD path (see the README precondition), so this counter assertion, and
# the guard itself, only hold in iptables mode.
base_drops=$(metric_baseline "$client_node_ip" "$drops" "cw inbound drops on $client_node")

rc=0
client_curl -o /dev/null --max-time 5 "http://${vip}:${cw_port}/" || rc=$?
# Assert the timeout code specifically: a DROP makes curl hang until --max-time
# (exit 28). Any other exit means a different outcome the guard did not cause: 0
# = the bypass reached the workload; 7 = connection refused, i.e. the packet was
# rejected not dropped (a listener/NetworkPolicy artifact, not our guard); other
# codes = kubectl exec itself failed, which would false-green a bare "nonzero".
[ "$rc" -ne 0 ] || fail "VIP bypass reached the workload: curl http://$vip:$cw_port succeeded. Is the ratls-mesh DaemonSet rolled with the cw guard (RATLS-MESH-CW chain present)?"
[ "$rc" -eq 28 ] || fail "VIP dial to $vip:$cw_port exited $rc, expected 28 (timeout from a DROP); a non-timeout failure is not proof the cw guard blocked it"
echo "ok: VIP bypass blocked (curl exit 28 = timeout from DROP)"

await_metric_above "$client_node_ip" "$drops" "$base_drops" \
  "cw inbound drop counter on $client_node moved: the guard, not a coincidence, blocked it"

# --- negative: an excluded-namespace source cannot reach cw pods ------------

kubectl run "$excluded_pod" -n "$excluded_ns" --image="$client_image" \
  --restart=Never --command -- sleep 600 >/dev/null
kubectl wait --for=condition=Ready pod/"$excluded_pod" -n "$excluded_ns" --timeout=120s >/dev/null

# The drop fires on the excluded pod's node (its egress to the cw pod IP hits
# that node's FORWARD guard), which may differ from the client's node above.
excluded_node=$(kubectl get pod "$excluded_pod" -n "$excluded_ns" -o jsonpath='{.spec.nodeName}')
excluded_node_ip=$(kubectl get node "$excluded_node" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
[ -n "$excluded_node_ip" ] || fail "node $excluded_node reports no InternalIP; cannot read its drop counter"
base_excluded_drops=$(metric_baseline "$excluded_node_ip" "$drops" "cw inbound drops on $excluded_node")

rc=0
kubectl exec -n "$excluded_ns" "$excluded_pod" -- \
  curl -s -o /dev/null --max-time 5 "http://${cw_ip}:${cw_port}/" || rc=$?
# Same reasoning as the VIP dial: require exit 28 (DROP timeout), and back it
# with a drop-counter move so a kubectl exec failure cannot false-green this.
[ "$rc" -ne 0 ] || fail "excluded-namespace ($excluded_ns) source reached $cw_ip:$cw_port in plaintext; the guard must drop unmeshed sources"
[ "$rc" -eq 28 ] || fail "excluded-namespace dial to $cw_ip:$cw_port exited $rc, expected 28 (timeout from a DROP); a non-timeout failure is not proof the guard blocked it"
echo "ok: excluded-namespace source blocked (curl exit 28 = timeout from DROP)"

await_metric_above "$excluded_node_ip" "$drops" "$base_excluded_drops" \
  "cw inbound drop counter on $excluded_node moved: the guard blocked the excluded source, not a coincidence"

# --- egress guard: the DNS carve-out is scoped where it can match -----------

# A cw pod that loses DNS still reaches Running, so this is asserted against
# the chain the node actually runs rather than against the pod's health. Read
# on the workload's node, in the sidecar that programs it.
mesh_pod=$(kubectl get pods -n "$mesh_ns" -l app=c8s-ratls-mesh \
  --field-selector="spec.nodeName=$cw_node" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[ -n "$mesh_pod" ] || fail "no ratls-mesh pod on $cw_node in namespace $mesh_ns (set MESH_NS)"

egress_chain=$(kubectl exec -n "$mesh_ns" "$mesh_pod" -c iptables-sync -- \
  iptables -L RATLS-MESH-CW-EGRESS -n -v -x 2>/dev/null) \
  || fail "RATLS-MESH-CW-EGRESS not readable on $cw_node; is the cw egress guard installed?"

dns_rows=$(awk '/udp/ && /dpt:53/' <<<"$egress_chain")
[ -n "$dns_rows" ] || fail "RATLS-MESH-CW-EGRESS carries no UDP/53 carve-out on $cw_node; cw pods cannot resolve:
$egress_chain"

# The carve-out names no destination, so it survives kube-proxy's Service DNAT
# and holds whatever address this cluster's resolver has. A row naming one is
# the regression this replaced: where the resolver sits elsewhere it puts the
# carve-out out of reach and every cw DNS query hits the drop below.
# In `iptables -L -n -v -x` the destination column is field 9; unscoped reads
# 0.0.0.0/0. A conntrack scope shows as an extra match instead of a column.
scoped=$(awk '$9 != "0.0.0.0/0" || /ctorigdst/' <<<"$dns_rows")
[ -z "$scoped" ] || fail "the UDP/53 carve-out is destination-scoped; it must name no address:
$scoped"

# A RETURN below the drop is a RETURN that never runs.
drop_line=$(awk '/DROP/ && /!tcp/ {print NR; exit}' <<<"$egress_chain")
dns_line=$(awk '/udp/ && /dpt:53/ {print NR; exit}' <<<"$egress_chain")
if [ -n "$drop_line" ] && [ -n "$dns_line" ] && [ "$dns_line" -gt "$drop_line" ]; then
  fail "the UDP/53 carve-out is ordered below the non-TCP drop, so it is unreachable:
$egress_chain"
fi
echo "ok: cw egress DNS carve-out is unscoped and ordered above the drop"

# Membership is what the guard keys on. An empty set is enforcement that is not
# running, and reads identically to a guard that is simply not being exercised.
cw_members=$(kubectl exec -n "$mesh_ns" "$mesh_pod" -c iptables-sync -- \
  ipset list RATLS-MESH-CW-PODS 2>/dev/null | awk '/^Number of entries:/ {print $NF}')
[ "${cw_members:-0}" -gt 0 ] || fail "ipset RATLS-MESH-CW-PODS on $cw_node holds no members while $cw_ns/$cw_pod is Running; the guard is not enforcing on any cw pod"
echo "ok: cw ipset on $cw_node holds $cw_members member(s)"

echo "PASS: workload path mesh-wrapped; VIP and excluded-source plaintext bypasses fail closed; egress DNS carve-out matchable"
