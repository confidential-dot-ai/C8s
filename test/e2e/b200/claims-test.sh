#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
cd "$scratch"
jq -n '[range(8) | tostring]' > assignment
jq -n --arg nonce challenge --slurpfile input assignment -f "$here/testdata/claims.jq" > valid
check() { jq -ser --arg nonce challenge --slurpfile expected assignment -f "$here/claims.jq"; }
check < valid
if check </dev/null || cat valid valid | check; then exit 1; fi
for mutation in 'del(.claims[0])' '.claims[1]=.claims[0]' '.claims[0].ueid="unenrolled"' \
    '.claims[3].eat_nonce="earlier"' '.claims[0]["x-nvidia-gpu-attestation-report-signature-verified"]=false' \
    '.claims[0]["x-nvidia-gpu-vbios-rim-cert-chain"]["x-nvidia-cert-ocsp-status"]="revoked"' \
    '.claims[6]["x-nvidia-gpu-driver-rim-signature-verified"]=false' '.claims[4].secboot=false'; do
    if jq "$mutation" valid | check 2>/dev/null; then echo "accepted $mutation" >&2; exit 1; fi
done
