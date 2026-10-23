#!/usr/bin/env bash
# Live-cluster check of CDS-HA (Raft replicas on cds-role nodes): every
# replica serves the same state, writes at any replica reach all of them,
# secret release works, and the cluster survives losing its leader.
#
# Sequence:
#   1. Every HA replica answers /ha/status, one leader, all serving, one mesh
#      CA (sampled through the CDS front door).
#   2. Write an allowlist entry and a secret through the CDS front door; every
#      replica applies the write.
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
#   E2E_NGINX_IMAGE     image of the secret consumer (default nginxinc/nginx-unprivileged:1.27-alpine)
set -euo pipefail
# shellcheck source=test/e2e/lib.sh
. "$(dirname "$0")/lib.sh"
cds_measurement_args
# shellcheck disable=SC2154  # measurement_args is set by cds_measurement_args
: "${C8S_CDS_URL:?CDS front door URL}" "${C8S_OPERATOR_KEY:?operator key}"
NS=c8s-e2e-ha-$$
TIMEOUT=${E2E_HA_TIMEOUT:-120}
NGINX=${E2E_NGINX_IMAGE:-nginxinc/nginx-unprivileged:1.27-alpine}
cli() { c8s "$@" --url "$C8S_CDS_URL" "${measurement_args[@]}" --operator-key "$C8S_OPERATOR_KEY"; }
work=$(mktemp -d)
cleanup() {
  if cw_namespace_owned "$NS"; then kubectl delete namespace "$NS" --wait=false >/dev/null 2>&1 || true; fi
  cli allowlist delete e2e-ha-consumer >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
cw_namespace "$NS" || fail "create namespace $NS"

# Ready cds nodes only: a rollout replaces cds nodes under new names, and the
# old Node objects stay NotReady until someone deletes them.
expected=${E2E_HA_REPLICAS:-$(kubectl get nodes -l c8s.confidential.ai/role=cds --no-headers | awk '$2=="Ready"' | wc -l)}
[ "$expected" -ge 3 ] || fail "need at least 3 cds nodes, have $expected"

json() { jq -Rs .; }

# status samples GET /ha/status through the CDS front door, which spreads
# requests over the replicas, and prints the latest line per replica: node
# state serving ca applied_index. Every pod in a tenant namespace is a mesh
# member, so an in-cluster probe cannot dial the replicas directly.
status() {
  local _
  for _ in $(seq 1 40); do
    curl -sk -m 3 "$C8S_CDS_URL/ha/status" 2>/dev/null | tr -d '\n'
    echo
  done | sed -nE 's/.*"node_name":"([^"]*)".*"state":"([^"]*)".*"serving":(true|false).*"ca_fingerprint":"(.{12})[^"]*".*"applied_index":([0-9]+).*/\1 \2 \3 \4 \5/p' \
    | awk '{last[$1]=$0} END {for (n in last) print last[n]}'
}
# retry runs a command every 2 s until it succeeds, for up to TIMEOUT s.
retry() {
  local deadline=$((SECONDS + TIMEOUT))
  until "$@"; do
    [ $SECONDS -lt $deadline ] || return 1
    sleep 2
  done
}
# converged: $1 replicas serve with one CA, each having applied at least
# index $2 (optional).
converged() {
  local s
  s=$(status)
  [ "$(echo "$s" | awk -v m="${2:-0}" '$3=="true" && $5>=m' | wc -l)" -ge "$1" ] \
    && [ "$(echo "$s" | awk '$3=="true"{print $4}' | sort -u | wc -l)" -eq 1 ]
}
converge() { retry converged "$@" || { status >&2; return 1; }; }
leader() { status | awk '$2=="Leader"{print $1; exit}'; }
# leader_index prints the leader's applied index (other replicas may lag).
leader_index() { status | awk '$2=="Leader"{print $5; f=1; exit} END{exit !f}'; }
not_serving() { ! status | awk -v n="$1" '$1==n && $3=="true"' | grep -q .; }
# new_leader sets L2 to the leader and checks it is not $1.
new_leader() { L2=$(leader); [ -n "$L2" ] && [ "$L2" != "$1" ]; }

echo "1. $expected replicas serve one state"
converge "$expected" || fail "replicas did not converge"
[ "$(status | awk '$2=="Leader"' | wc -l)" -eq 1 ] || fail "not exactly one leader"

echo "2. writes reach every replica"
digest=$(crane digest "$NGINX" 2>/dev/null || true)
[ -n "$digest" ] || fail "resolve $NGINX (crane)"
# shellcheck disable=SC2016  # expands in the pod, not here
script='until [ -f /run/c8s/secrets/V ]; do sleep 1; done; echo "V=$(cat /run/c8s/secrets/V)"; sleep 100000'
cat >"$work/wl.json" <<EOF
{"schema":"c8s.allowlist/v1","workloads":{"e2e-ha-consumer":{"label":"${NGINX%@*}@$digest","initContainers":[],"containers":[{"digest":"$digest","image":"$NGINX@$digest","command":{"policy":"exact","argv":["sh","-c",$(printf '%s' "$script" | json)]},"args":{"policy":"deny"},"mounts":{"policy":"exact","rules":[{"destination":"/run/c8s/secrets","kind":"emptyDir"}]},"env":{"policy":"any"}}],"secrets":{"policy":"allow","read":["/e2e-ha/v"]}}}}
EOF
cli allowlist apply "$work/wl.json" >/dev/null || fail "allowlist write"
# The write is committed when apply returns, so the leader has applied it:
# the leader's index is at or past it, and every replica must reach it.
written=$(retry leader_index) || fail "no leader seen after the allowlist write"
converge "$expected" "$written" || fail "allowlist write did not reach every replica"
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
  retry released "$1" "$2" || { kubectl -n "$NS" describe pod "$1" >&2 || true; return 1; }
}
released() { kubectl -n "$NS" logs "$1" -c c 2>/dev/null | grep -qx "V=$2"; }
echo "3. secret release"
consume consumer-1 one || fail "secret not released"

if [ -n "${E2E_HA_STOP_NODE:-}" ] && [ -n "${E2E_HA_START_NODE:-}" ]; then
  L=$(leader); [ -n "$L" ] || fail "no leader"
  echo "4. stop the leader's node $L"
  $E2E_HA_STOP_NODE "$L"
  # Whatever happens next, start the node again.
  trap '$E2E_HA_START_NODE "$L" >/dev/null 2>&1 || true; cleanup' EXIT
  start=$SECONDS
  retry not_serving "$L" || fail "$L still serving after the stop command"
  # Followers keep serving for the lease after their last contact, so wait
  # for the new leader itself, then for a serving majority under it.
  retry new_leader "$L" || fail "no new leader (had $L, now '${L2:-}')"
  converge $((expected - 1)) || fail "no serving majority after losing the leader"
  echo "   new leader $L2 after $((SECONDS - start)) s"
  put_secret two || fail "secret write after leader loss"
  consume consumer-2 two || fail "secret not released after leader loss"
  $E2E_HA_START_NODE "$L"
  converge "$expected" || fail "stopped node's replica did not rejoin"
  echo "   $L rejoined after $((SECONDS - start)) s"
fi
echo "PASS: CDS-HA"
