#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 6 ]]; then
    echo "usage: $0 APPROVAL.json APPROVAL_SHA256 SITE_RIM_URL SITE_OCSP_URL APPROVED_POLICY.rego NEW_RESULTS_DIRECTORY" >&2
    exit 2
fi
approval=$1 pinned=$2 rims=$3 ocsp=$4 policy=$5 results=$6
here=$(cd "$(dirname "$0")" && pwd)
mkdir -- "$results"
"$here/check-site-clock.sh"
cp -- "$approval" "$results/approval.json"
cp -- "$policy" "$results/policy.rego"
digest() { sha256sum < "$1" | cut -d' ' -f1; }
[[ $(digest "$results/approval.json") == "$pinned" ]] || { echo "unapproved qualification inputs" >&2; exit 1; }
[[ $(digest "$results/policy.rego") == "$(jq -er .policySha256 "$results/approval.json")" ]] || { echo "policy differs from approval" >&2; exit 1; }
jq -ce .ueids "$results/approval.json" > "$results/ueids.json"
nonce=$(openssl rand -hex 32)
printf '%s\n' "$nonce" > "$results/challenge"
printf '%s\n' "$rims" "$ocsp" > "$results/endpoints"
digest "$(command -v nvattest)" > "$results/nvattest.sha256"
[[ $(cat "$results/nvattest.sha256") == "$(jq -er .nvattestSha256 "$results/approval.json")" ]] || { echo "unapproved nvattest build" >&2; exit 1; }
uname -r > "$results/kernel"
nvidia-smi --query-gpu=pci.bus_id,uuid,name,driver_version,vbios_version --format=csv,noheader | LC_ALL=C sort > "$results/inventory.csv"
[[ $(digest "$results/inventory.csv") == "$(jq -er .inventorySha256 "$results/approval.json")" ]] || { echo "GPU inventory differs from enrollment" >&2; exit 1; }
nvidia-smi --query-gpu=index --format=csv,noheader > "$results/indices"
mapfile -t indices < "$results/indices"
[[ ${#indices[@]} == 8 ]] || { echo "expected 8 assigned GPUs, found ${#indices[@]}" >&2; exit 1; }
for index in "${indices[@]}"; do
    [[ $index =~ ^[0-9]+$ ]]
    nvidia-smi conf-compute -f -i "$index" > "$results/cc-$index.txt"
    if ! awk '{ line=tolower($0) }
        line ~ /cc (status|feature)[[:space:]]*:/ {seen++; if (line !~ /:[[:space:]]*(on|enabled)[[:space:]]*$/) bad=1}
        END { exit !(seen && !bad) }' "$results/cc-$index.txt"; then
        echo "GPU $index must report CC on" >&2; exit 1;
    fi
done
timeout 5m nvattest --format json --log-level off attest --device gpu --gpu-evidence-source nvml \
    --nonce "$nonce" --verifier local --rim-store remote --rim-url "$rims" --ocsp-url "$ocsp" \
    --verify-rim-signatures --verify-rim-cert-chain --relying-party-policy "$results/policy.rego" > "$results/attest.json"
jq -ser --arg nonce "$nonce" --slurpfile expected "$results/ueids.json" -f "$here/claims.jq" "$results/attest.json"
