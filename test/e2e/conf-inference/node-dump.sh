#!/usr/bin/env bash
# DEBUG ONLY (not for merge): the gateway -> sglang-router path as the node
# sees it, on a dev image with a node shell (C8S_NODE_SSH_CONFIG) and the
# node's admin kubeconfig. Called by run.sh's inference_dump.
# Usage: node-dump.sh <app-namespace> <netshoot-image-ref>
set -uo pipefail
ns=$1 shoot=$2
export KUBECONFIG="$C8S_ADMIN_KUBECONFIG"
n() { ssh -n -F "$C8S_NODE_SSH_CONFIG" node "export PATH=/var/lib/rancher/rke2/bin:\$PATH; $*"; }
sec() { echo; echo "######## $*"; }

sec pods and services
kubectl get pods -A -o wide
kubectl -n "$ns" get svc -o yaml
kubectl -n "$ns" get endpointslices -o wide
kubectl -n "$ns" get networkpolicy -o yaml
kubectl get networkpolicy -A
kubectl get globalnetworkpolicies.crd.projectcalico.org,networkpolicies.crd.projectcalico.org -A -o yaml 2>&1 | head -200
pod_ip() { kubectl -n "$ns" get pods -l "app.kubernetes.io/component=$1" -o jsonpath='{.items[0].status.podIP}'; }
gw=$(kubectl -n "$ns" get pods -l app.kubernetes.io/component=gateway -o jsonpath='{.items[0].metadata.name}')
gwip=$(pod_ip gateway)
rt=$(kubectl -n "$ns" get pods -o json | jq -r '.items[] | select(.metadata.name | test("router")) | .metadata.name' | head -1)
rtip=$(kubectl -n "$ns" get pod "$rt" -o jsonpath='{.status.podIP}')
svcip=$(kubectl -n "$ns" get svc sglang-router -o jsonpath='{.spec.clusterIP}')
echo "gateway $gw $gwip; router $rt $rtip; sglang-router svc $svcip"
kubectl -n "$ns" get pod "$gw" -o json | jq '.spec.containers[] | {name, image, ports}'

sec node rules
n 'command -v iptables-save nft ipset conntrack tcpdump; iptables-save -V'
for t in nat filter mangle raw; do sec "iptables-save -t $t"; n "iptables-save -t $t"; done
sec nft; n 'nft list ruleset 2>&1 | head -800'
sec ipset; n 'ipset list'
sec routes; n 'ip -d addr; ip route; ip rule; ip route show table all | head -80; sysctl net.ipv4.ip_forward net.bridge.bridge-nf-call-iptables'

sec debug pod
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata: {name: netdebug, namespace: kube-system}
spec:
  hostNetwork: true
  hostPID: true
  tolerations: [{operator: Exists}]
  containers:
  - name: s
    image: $shoot
    command: [sleep, "3600"]
    securityContext: {privileged: true}
EOF
kubectl -n kube-system wait --for=condition=Ready pod/netdebug --timeout=180s
dbg() { kubectl -n kube-system exec netdebug -- "$@"; }

probe() {
  local url=$1
  sec "probe $url from $gw (conntrack + tcpdump)"
  dbg conntrack -F 2>/dev/null
  dbg sh -c "timeout 25 tcpdump -nni any -c 400 'host $gwip or host $rtip or host $svcip' 2>&1" > /tmp/tcpdump.out &
  local tp=$!
  sleep 3
  for c in "curl -sv -m 10 $url" "wget -qO- -T 10 $url" "python3 -c 'import urllib.request,sys;print(urllib.request.urlopen(sys.argv[1],timeout=10).read()[:300])' $url"; do
    echo "-- exec: $c"
    kubectl -n "$ns" exec "$gw" -- sh -c "$c" 2>&1 | tail -15 && break
  done
  wait "$tp"
  cat /tmp/tcpdump.out
  sec "conntrack for $gwip"
  dbg conntrack -L -s "$gwip" 2>&1 | head -40
  dbg conntrack -L -d "$gwip" 2>&1 | head -40
}
probe "http://sglang-router.$ns.svc:30000/health"
probe "http://$rtip:30000/health"
sec "probe from the router pod itself and from netdebug (host netns)"
kubectl -n "$ns" exec "$rt" -- sh -c "curl -s -m5 http://127.0.0.1:30000/health || wget -qO- -T5 http://127.0.0.1:30000/health" 2>&1 | tail -3
dbg curl -sv -m 5 "http://$rtip:30000/health" 2>&1 | tail -8
dbg curl -sv -m 5 "http://$svcip:30000/health" 2>&1 | tail -8
sec "iptables counters after probes"
n 'iptables-save -c -t nat | grep -iE "armtls|30000|ARMTLS|KUBE-SVC|cali-" | head -150; iptables-save -c -t filter | grep -E "^\[[1-9]" | head -200; iptables-save -c -t mangle | grep -E "^\[[1-9]" | head -100'

sec logs
for p in $(kubectl -n kube-system get pods -o name | grep -E 'calico|canal'); do
  for c in $(kubectl -n kube-system get "$p" -o jsonpath='{.spec.containers[*].name}'); do
    echo "== $p/$c"; kubectl -n kube-system logs "$p" -c "$c" --tail=150 2>&1 | grep -viE 'debug' | tail -80
  done
done
for p in $(kubectl -n c8s-system get pods -o name | grep armtls-mesh); do
  for c in $(kubectl -n c8s-system get "$p" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}'); do
    echo "== $p/$c"; kubectl -n c8s-system logs "$p" -c "$c" --tail=200 2>&1 | tail -120
  done
done
for p in $(kubectl -n "$ns" get pods -o name); do
  for c in $(kubectl -n "$ns" get "$p" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}'); do
    echo "== $p/$c"; kubectl -n "$ns" logs "$p" -c "$c" --tail=60 2>&1 | tail -40
  done
done
kubectl -n kube-system delete pod netdebug --wait=false
exit 0
