#!/usr/bin/env bash
# Live-cluster check that the C8s control plane converged: pods in c8s-system
# are Running with every container Ready.
#
# With no arguments every pod must be ready. Name-prefix arguments narrow it to
# those components, for installs that deliberately leave others out.
#
# Needs kubectl pointed at a cluster with C8s installed.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ns=c8s-system

if [ "${C8S_NODE_IMAGE:-}" = 1 ]; then
  : "${C8S_MEASUREMENTS_CONFIG:?node-image checks require the full server policy}"
  : "${C8S_ALLOWLIST_URL:?node-image checks require the measured CDS front door}"
  workloads=(deployment/c8s-operator deployment/c8s-cds deployment/c8s-router daemonset/c8s-armtls-mesh)
  # The authenticated credential listener can become available before RKE2
  # has applied the complete AddOn. Require every core workload to exist.
  kubectl -n "$ns" wait --for=create "${workloads[@]}" --timeout=8m
  for workload in "${workloads[@]}"; do
    kubectl -n "$ns" rollout status "$workload" --timeout=8m
  done
  # Public policies are host-staged, not stored in Kubernetes. Check that
  # every consumer uses its required read-only file. The external armTLS
  # request below verifies the actual endpoint against the signed policy.
  kubectl -n "$ns" get "${workloads[@]}" -o json | jq -e '
    def policy($workload; $container; $flag):
      any(.items[];
        .metadata.name == $workload and
        (.spec.template.spec |
          any(.volumes[]?;
            .name == "node-config" and .hostPath.path == "/run/c8s-node" and
            .hostPath.type == "Directory") and
          any((.containers + (.initContainers // []))[];
            .name == $container and ((.args // []) | index($flag)) != null and
            any(.volumeMounts[]?;
              .name == "node-config" and .mountPath == "/run/c8s-node" and .readOnly == true))));
    policy("c8s-operator"; "operator"; "--image-policy-file=/run/c8s-node/cds.json") and
    policy("c8s-cds"; "cds"; "--image-policy-file=/run/c8s-node/peers.json") and
    policy("c8s-router"; "c8s-cert"; "--image-policy-file=/run/c8s-node/cds.json") and
    policy("c8s-router"; "allowlist-proxy"; "--image-policy-file=/run/c8s-node/cds.json") and
    policy("c8s-armtls-mesh"; "armtls-mesh"; "--image-policy-file=/run/c8s-node/peers.json") and
    policy("c8s-armtls-mesh"; "armtls-mesh"; "--cds-image-policy-file=/run/c8s-node/cds.json") and
    all(.items[].spec.template.spec.volumes[]?;
      ((.hostPath.path // "") | startswith("/run/confos")) | not)
  ' >/dev/null || fail "baked workloads lost their required public identity policies or mount private launch data"
  chart=$(kubectl -n kube-system get helmcharts.helm.cattle.io c8s --ignore-not-found -o name)
  [ -z "$chart" ] || fail "node image unexpectedly started a runtime c8s Helm installation"
fi

select_pods() {
  if [ "$#" -eq 0 ]; then cat; return 0; fi
  local pat="" p
  for p in "$@"; do pat="${pat:+$pat|}^$p"; done
  grep -E "$pat" || true
}

# awk, not a regex backreference: `$2 !~ /^([0-9]+)\/\1$/` looks right and is
# not (awk has no backreferences), so it silently only ever matches 1/1 and
# calls every sidecar-bearing pod not-ready.
count_notready() {
  awk 'NF {split($2,a,"/"); if (a[1]!=a[2] || $3!="Running") n++} END {print n+0}'
}

converged=""
backoff=0
for _ in $(seq 1 40); do
  listing=$(kubectl -n "$ns" get pods --no-headers 2>/dev/null | select_pods "$@" || true)
  total=$(printf '%s\n' "$listing" | awk 'NF' | wc -l)
  n=$(printf '%s\n' "$listing" | count_notready)
  if [ "$total" -gt 0 ] && [ "$n" -eq 0 ]; then converged=1; break; fi
  # A pull that is still backing off after a minute does not recover inside
  # the window; fail now rather than spending the whole timeout on it.
  case "$listing" in
    *ImagePullBackOff*) backoff=$((backoff + 1)) ;;
    *) backoff=0 ;;
  esac
  if [ "$backoff" -ge 5 ]; then
    kubectl -n "$ns" get events --sort-by=.lastTimestamp 2>/dev/null | grep -i pull | tail -6 || true
    fail "image pulls are backing off; components cannot converge"
  fi
  sleep 15
done

printf '%s\n' "${listing:-}"
if [ -z "$converged" ]; then
  kubectl -n "$ns" describe pods | tail -40
  fail "c8s components did not converge (${n:-?} of ${total:-0} not ready)"
fi

if [ "${C8S_NODE_IMAGE:-}" = 1 ]; then
  ready=0
  for _ in $(seq 1 60); do
    if c8s allowlist list --url "$C8S_ALLOWLIST_URL" --image-policy-file "$C8S_MEASUREMENTS_CONFIG" >/dev/null 2>&1; then
      ready=1; break
    fi
    sleep 5
  done
  [ "$ready" = 1 ] || fail "measured CDS/front-door services did not become ready under the server policy"
fi

echo "PASS: all $total c8s Kubernetes components Running"
