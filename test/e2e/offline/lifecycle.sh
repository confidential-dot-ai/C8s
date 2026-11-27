#!/usr/bin/env bash
set -euo pipefail
umask 077
here=$(cd "$(dirname "$0")" && pwd)
if [[ $# != 1 ]]; then echo "usage: $0 NEW_RESULTS_DIRECTORY" >&2; exit 2; fi
out=$1
: "${TA_URL:?}" "${TA_PIN:?}" "${WORKER_PIN:?}" "${SITE_PROFILE:?}" "${ACCEPTED_POLICIES:?}"
: "${WORKLOAD_URL:?}" "${ALLOWLIST:?}" "${NGINX_URL:?}" "${ROUTE_DIGEST:?}" "${NGINX_BODY_SHA256:?}"
: "${WORKER_HOST:?SSH host alias for the pilot}" "${RENEWAL_TIMEOUT_SECONDS:?bound covering certificate renewal}"
[[ $WORKER_HOST =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ && $RENEWAL_TIMEOUT_SECONDS =~ ^[1-9][0-9]*$ ]] || exit 2
mkdir -- "$out"
mkdir "$out/initial" "$out/renewed" "$out/restarted"
date -u +%FT%TZ > "$out/start-utc"
site=(--tdx-collateral-profile "$SITE_PROFILE")
c8s ta verify "$TA_URL" --image-policy-file "$TA_PIN" "${site[@]}" --served-policy-file "$WORKER_PIN" -o json > "$out/ta.json"
c8s ta ca --ta-url "$TA_URL" --ta-image-policy-file "$TA_PIN" "${site[@]}" --out "$out/mesh-ca.pem"
kubectl -n demo apply -f "$here/../../../samples/nginx-confidential-pod.yaml"
ready() { kubectl -n demo rollout status deploy/demo-nginx --timeout=10m; }
workload() {
    local dest=$1
    shift
    c8s verify "$WORKLOAD_URL" --kind workload --mode armtls-cert --image-policy-file "$WORKER_PIN" \
        --pin-policy "$ACCEPTED_POLICIES" --mesh-ca "$out/mesh-ca.pem" --workload demo-nginx \
        --allowlist "$ALLOWLIST" "${site[@]}" "$@" -o json > "$dest"
    jq -se 'length == 1 and (.[0] | .verified == true and .measurement_pinned == true and .tdx_tcb_status == "UpToDate" and
        .workload == "demo-nginx" and (.sandbox_id | type=="string" and length>0) and
        (.cert_sha256 | test("^[0-9a-f]{64}$")))' "$dest" >/dev/null
}
ready
workload "$out/initial/workload.json"
"$here/route.py" "$out/initial"
first=$(jq -r .cert_sha256 "$out/initial/workload.json")
sandbox=$(jq -r .sandbox_id "$out/initial/workload.json")
deadline=$((SECONDS + RENEWAL_TIMEOUT_SECONDS))
while :; do
    workload "$out/renewed/workload.json" --sandbox-id "$sandbox"
    renewed=$(jq -r .cert_sha256 "$out/renewed/workload.json")
    [[ $renewed != "$first" ]] && break
    (( SECONDS < deadline )) || { echo "same verified certificate through the renewal deadline" >&2; exit 1; }
    sleep 15
done
"$here/route.py" "$out/renewed"
node=$(kubectl -n demo get pod -l app=demo-nginx -o json | jq -er '[.items[]|select(.metadata.deletionTimestamp == null)]|if length==1 then .[0].spec.nodeName else error("expected one running nginx pod") end')
boot_id() { kubectl get node "$node" -o json | jq -er '.status.nodeInfo.bootID | select(type=="string" and length>0)'; }
boot_id > "$out/initial/worker-boot-id"
host=(ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "$WORKER_HOST")
"${host[@]}" 'set -eu
    unit=c8s-offline-worker.service
    systemctl is-active --quiet "$unit"
    before=$(systemctl show -p InvocationID --value "$unit")
    sudo -n systemctl stop "$unit"
    test "$(systemctl show -p ActiveState --value "$unit")" = inactive
    test "$(systemctl show -p MainPID --value "$unit")" = 0
    sudo -n /opt/c8s-offline/site/install.sh worker >&2
    systemctl is-active --quiet "$unit"
    after=$(systemctl show -p InvocationID --value "$unit")
    test -n "$before"
    test -n "$after"
    test "$before" != "$after"
    printf "%s\\n%s\\n" "$before" "$after"' > "$out/worker-invocations"
deadline=$((SECONDS + 600))
while :; do
    if boot_id > "$out/restarted/worker-boot-id" && ! cmp -s "$out/initial/worker-boot-id" "$out/restarted/worker-boot-id"; then break; fi
    (( SECONDS < deadline )) || { echo "worker did not report a new boot ID" >&2; exit 1; }
    sleep 5
done
ready
workload "$out/restarted/workload.json"
after=$(jq -r .cert_sha256 "$out/restarted/workload.json")
[[ $after != "$first" && $after != "$renewed" ]] || { echo "restarted worker presented an earlier leaf" >&2; exit 1; }
"$here/route.py" "$out/restarted"
date -u +%FT%TZ > "$out/end-utc"
