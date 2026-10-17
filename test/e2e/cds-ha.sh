#!/usr/bin/env bash
# Live-cluster check of CDS-HA (Raft replicas on cds-role nodes): every
# replica serves the same state, writes at any replica reach all of them,
# secret release works, and the cluster survives losing its leader.
#
# Sequence:
#   1. Every HA replica answers /ha/status, one leader, all serving, one mesh
#      CA and one allowlist ETag (seen from a curl pod inside the cluster).
#   2. Write an allowlist entry and a secret through the CDS front door; every
#      replica converges to the new ETag.
#   3. Start a pod that receives the secret (release through whichever replica
#      its node reaches).
#   4. With E2E_HA_STOP_NODE / E2E_HA_START_NODE: stop the leader's node, wait
#      for a new leader and a serving majority, write and release again, start
#      the node and wait until every replica serves again (as a new member).
#
# Needs kubectl pointed at the guest cluster, `c8s` on PATH, and:
#   C8S_CDS_URL         CDS front door, e.g. https://<node>:30808
#   C8S_MEASUREMENTS / C8S_MEASUREMENTS_CONFIG  pin of the CDS endpoint (lib.sh)
#   C8S_OPERATOR_KEY    operator EC key PEM pinned on CDS
# Optional:
#   E2E_HA_REPLICAS     expected replica count (default: one per cds node)
#   E2E_HA_STOP_NODE    command run with a node name to stop that node
#   E2E_HA_START_NODE   command run with a node name to start it again
#   E2E_HA_TIMEOUT      seconds to wait for each convergence (default 120)
#   E2E_CURL_IMAGE      curl image for the in-cluster probe (default curlimages/curl:8.10.1)
#   E2E_NGINX_IMAGE     image of the secret consumer (default nginxinc/nginx-unprivileged:1.27-alpine)
set -euo pipefail
# shellcheck source=test/e2e/lib.sh
. "$(dirname "$0")/lib.sh"
cds_measurement_args
# shellcheck disable=SC2154  # measurement_args is set by cds_measurement_args
: "${C8S_CDS_URL:?CDS front door URL}" "${C8S_OPERATOR_KEY:?operator key}"
NS=c8s-e2e-ha-$$
TIMEOUT=${E2E_HA_TIMEOUT:-120}
CURL=${E2E_CURL_IMAGE:-curlimages/curl:8.10.1}
NGINX=${E2E_NGINX_IMAGE:-nginxinc/nginx-unprivileged:1.27-alpine}
cli() { c8s "$@" --url "$C8S_CDS_URL" "${measurement_args[@]}" --operator-key "$C8S_OPERATOR_KEY"; }
work=$(mktemp -d)
cleanup() {
  if cw_namespace_owned "$NS"; then kubectl delete namespace "$NS" --wait=false >/dev/null 2>&1 || true; fi
  cli allowlist delete e2e-ha-consumer >/dev/null 2>&1 || true
  cli allowlist delete e2e-ha-probe >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
cw_namespace "$NS" || fail "create namespace $NS"

expected=${E2E_HA_REPLICAS:-$(kubectl get nodes -l c8s.confidential.ai/role=cds --no-headers | wc -l)}
[ "$expected" -ge 3 ] || fail "need at least 3 cds nodes, have $expected"

# The probe pod prints one line per replica every 2 s (node state serving
# ca etag), read back through its logs: no exec rights needed. Its image
# needs an allowlist entry like any workload; when another entry already
# admits it, that apply is refused and the existing one is used.
# shellcheck disable=SC2016  # expands in the pod
probe_loop='while true; do for ip in $(nslookup c8s-cds-peers.c8s-system.svc.cluster.local 2>/dev/null | awk "/^Address: /{print \$2}" | grep -v :); do s=$(curl -sk -m 2 https://$ip:8443/ha/status | tr -d "\n"); e=$(curl -sk -m 2 -o /dev/null -D - https://$ip:8443/allowlist | tr -d "\r" | awk "tolower(\$1)==\"etag:\"{print \$2}"); echo "S $s ETAG=$e"; done; sleep 2; done'
curl_digest=$(crane digest "${CURL%@*}" 2>/dev/null || true)
[ -n "$curl_digest" ] || fail "resolve $CURL (crane)"
CURL="${CURL%@*}@$curl_digest"
json() { python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))'; }
cat >"$work/probe.json" <<EOF
{"schema":"c8s.allowlist/v1","workloads":{"e2e-ha-probe":{"label":"$CURL","initContainers":[],"containers":[{"digest":"$curl_digest","image":"$CURL","command":{"policy":"exact","argv":["sh","-c",$(printf '%s' "$probe_loop" | json)]},"args":{"policy":"deny"},"mounts":{"policy":"any"},"env":{"policy":"any"}}]}}}
EOF
cli allowlist apply "$work/probe.json" >/dev/null 2>&1 || echo "   (probe entry not applied: an existing entry admits $CURL)"
kubectl -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: probe}
spec:
  enableServiceLinks: false
  securityContext: {runAsNonRoot: true, runAsUser: 100, seccompProfile: {type: RuntimeDefault}}
  containers:
  - name: c
    image: $CURL
    command: ["sh", "-c", $(printf '%s' "$probe_loop" | json)]
    securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
EOF
kubectl -n "$NS" wait --for=condition=Ready pod/probe --timeout="${TIMEOUT}s" >/dev/null || fail "probe pod not ready"

# status prints the latest line per replica: node state serving ca etag.
status() {
  kubectl -n "$NS" logs probe --since=5s 2>/dev/null \
    | sed -nE 's/^S .*"node_name":"([^"]*)".*"state":"([^"]*)".*"serving":(true|false).*"ca_fingerprint":"(.{12})[^"]*".* ETAG=(.*)$/\1 \2 \3 \4 \5/p' \
    | awk '{last[$1]=$0} END {for (n in last) print last[n]}'
}
# converge waits until $1 replicas serve with one CA and one ETag ($2: ETag
# that must differ from, optional) and prints that ETag.
converge() {
  local want=$1 not=${2:-} deadline=$((SECONDS + TIMEOUT)) s
  while [ $SECONDS -lt $deadline ]; do
    s=$(status)
    if [ "$(echo "$s" | awk '$3=="true"' | wc -l)" -ge "$want" ] \
      && [ "$(echo "$s" | awk '$3=="true"{print $4,$5}' | sort -u | wc -l)" -eq 1 ] \
      && { [ -z "$not" ] || ! echo "$s" | grep -qF " $not"; }; then
      echo "$s" | awk '$3=="true"{print $5; exit}'
      return 0
    fi
    sleep 2
  done
  echo "$s" >&2
  return 1
}
leader() { status | awk '$2=="Leader"{print $1; exit}'; }

echo "1. $expected replicas serve one state"
etag0=$(converge "$expected") || fail "replicas did not converge"
[ "$(status | awk '$2=="Leader"' | wc -l)" -eq 1 ] || fail "not exactly one leader"

echo "2. writes reach every replica"
digest=$(crane digest "$NGINX" 2>/dev/null || true)
[ -n "$digest" ] || fail "resolve $NGINX (crane)"
# shellcheck disable=SC2016  # expands in the pod, not here
script='until [ -f /run/c8s/secrets/V ]; do sleep 1; done; echo "V=$(cat /run/c8s/secrets/V)"; sleep 100000'
cat >"$work/wl.json" <<EOF
{"schema":"c8s.allowlist/v1","workloads":{"e2e-ha-consumer":{"label":"${NGINX%@*}@$digest","initContainers":[],"containers":[{"digest":"$digest","image":"$NGINX@$digest","command":{"policy":"exact","argv":["sh","-c",$(printf '%s' "$script" | json)]},"args":{"policy":"deny"},"mounts":{"policy":"exact","rules":[{"destination":"/etc/c8s/certs","kind":"emptyDir"},{"destination":"/run/c8s/secrets","kind":"emptyDir"}]},"env":{"policy":"any"}}],"secrets":{"policy":"allow","read":["/e2e-ha/v"]}}}}
EOF
cli allowlist apply "$work/wl.json" >/dev/null || fail "allowlist write"
converge "$expected" "$etag0" >/dev/null || fail "allowlist write did not reach every replica"
curl -sk "$C8S_CDS_URL/ca" >"$work/ca.pem"
put_secret() { printf '%s' "$1" | cli secrets put /e2e-ha/v --overwrite --mesh-ca "$work/ca.pem" >/dev/null; }
put_secret one || fail "secret write"

# consume NAME WANT starts a consumer and checks it receives WANT.
consume() {
  kubectl -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $1
  annotations: {confidential.ai/cw: e2e-ha-consumer, confidential.ai/c8s-secrets: "V=/e2e-ha/v"}
spec:
  enableServiceLinks: false
  securityContext: {runAsNonRoot: true, runAsUser: 101, seccompProfile: {type: RuntimeDefault}}
  containers:
  - name: c
    image: $NGINX@$digest
    command: ["sh", "-c", $(printf '%s' "$script" | json)]
    securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
EOF
  local deadline=$((SECONDS + TIMEOUT))
  while [ $SECONDS -lt $deadline ]; do
    if kubectl -n "$NS" logs "$1" -c c 2>/dev/null | grep -qx "V=$2"; then return 0; fi
    sleep 2
  done
  kubectl -n "$NS" describe pod "$1" >&2 || true
  return 1
}
echo "3. secret release"
consume consumer-1 one || fail "secret not released"

if [ -n "${E2E_HA_STOP_NODE:-}" ] && [ -n "${E2E_HA_START_NODE:-}" ]; then
  L=$(leader); [ -n "$L" ] || fail "no leader"
  echo "4. stop the leader's node $L"
  $E2E_HA_STOP_NODE "$L"
  start=$SECONDS
  deadline=$((SECONDS + TIMEOUT))
  while status | awk -v n="$L" '$1==n && $3=="true"' | grep -q .; do
    [ $SECONDS -lt $deadline ] || fail "$L still serving after the stop command"
    sleep 2
  done
  converge $((expected - 1)) >/dev/null || fail "no serving majority after losing the leader"
  L2=$(leader)
  if [ -z "$L2" ] || [ "$L2" = "$L" ]; then fail "no new leader (had $L, now '$L2')"; fi
  echo "   new leader $L2 after $((SECONDS - start)) s"
  put_secret two || fail "secret write after leader loss"
  consume consumer-2 two || fail "secret not released after leader loss"
  $E2E_HA_START_NODE "$L"
  converge "$expected" >/dev/null || fail "stopped node's replica did not rejoin"
  echo "   $L rejoined after $((SECONDS - start)) s"
fi
echo "PASS: CDS-HA"
