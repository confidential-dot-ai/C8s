#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
cd "$scratch"
mkdir bin
printf '%s\n' '#!/bin/sh' 'echo "System clock wrong by 0.000013 seconds (ignored)"' > bin/chronyd
chmod +x bin/chronyd
export B200_NTS_SERVER=site.test B200_NTS_CA=$scratch/root.pem PATH=$scratch/bin:$PATH
mkdir subject run
for i in {1..8}; do printf '00000000:10:0%s.0, GPU-test-%s, NVIDIA B200, 1, A\n' "$i" "$i"; done > good-inventory
cp good-inventory run/inventory.csv
enrolled=$(sha256sum < run/inventory.csv | cut -d' ' -f1)
sdk=$(sha256sum < bin/chronyd | cut -d' ' -f1)
echo "$sdk" > run/nvattest.sha256
jq -n '[range(8) | tostring]' > run/ueids.json
openssl rand -hex 32 > run/challenge
jq -n --arg nonce "$(cat run/challenge)" --slurpfile input run/ueids.json -f "$here/testdata/claims.jq" > run/attest.json
echo test-policy > run/policy.rego
policy_hash=$(sha256sum < run/policy.rego | cut -d' ' -f1)
echo synthetic-rim | sha256sum | cut -d' ' -f1 > served-rims
rim_hash=$(cat served-rims)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout root.key \
    -subj /CN=TestRoot -days 4 -out root.pem 2>/dev/null

issue() {
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$1.key" -subj "/CN=$1" -out "$1.csr" 2>/dev/null
    openssl x509 -req -in "$1.csr" -CA "$2.pem" -CAkey "$2.key" -days 3 -out "$1.pem" -extfile "$3" 2>/dev/null
}
echo 'basicConstraints=critical,CA:TRUE' > ca
echo 'basicConstraints=critical,CA:FALSE' > leaf
issue alternate root ca
issue issuer root ca
cat alternate.pem issuer.pem > intermediates.pem
issue device issuer leaf
issue other issuer leaf
fingerprint=$(openssl x509 -in device.pem -outform der | sha256sum | cut -d' ' -f1)

cp device.pem subject/cert.pem
cp issuer.pem subject/issuer.pem
serial=$(openssl x509 -in device.pem -noout -serial | cut -d= -f2)
expiry=$(date -u -d '+2 days' +%y%m%d%H%M%SZ)
printf 'V\t%s\t\t%s\tunknown\t/CN=device\n' "$expiry" "$serial" > index
respond() {
    openssl ocsp -index index -rsigner issuer.pem -rkey issuer.key -CA issuer.pem \
        -issuer issuer.pem -cert device.pem -respout subject/ocsp.der "$@" >/dev/null 2>&1
    sha256sum subject/ocsp.der | cut -d' ' -f1 > served
}
window() {
    local now pinned
    now=$(date +%s)
    jq -n --slurpfile ueids run/ueids.json --arg policy "$policy_hash" --arg cert "$fingerprint" \
        --arg rim "$rim_hash" --arg enrolled "$enrolled" --arg sdk "$sdk" --argjson age "$1" '{nvattestSha256:$sdk,inventorySha256:$enrolled,ueids:$ueids[0],policySha256:$policy,maxStatusAgeSeconds:$age,
        rimSha256:[$rim],certificateFingerprints:{subject:$cert}}' > run/approval.json
    pinned=$(sha256sum < run/approval.json | cut -d' ' -f1)
    "$here/refresh-window.py" run "$pinned" . root.pem intermediates.pem served served-rims "$((now - $2))" "$now"
}
reject() {
    if window "$1" "$2" >log 2>&1; then echo "unexpected acceptance: $3" >&2; exit 1; fi
    grep -q -- "$3" log || { cat log >&2; exit 1; }
}
respond
window 7200 20 > log
jq -e '.limitingObject=="subject" and (.earliestExpiryUtc|endswith("Z"))' log > /dev/null
remaining=$(jq .remainingSeconds log)
(( remaining > 3500 && remaining <= 3600 ))
reject 300 301 'cannot cover'
respond -nmin 60
sleep 1.1
reject 1 1 "outside approved age"
respond -nmin 1
reject 300 120 'cannot cover'
cp other.pem subject/cert.pem
reject 300 10 'subject:'
cp device.pem subject/cert.pem
respond -rsigner device.pem -rkey device.key
reject 300 10 'subject:'
printf 'R\t%s\t%s\t%s\tunknown\t/CN=device\n' "$expiry" "$(date -u +%y%m%d%H%M%SZ)" "$serial" > index
respond
reject 300 20 'missing signed good status'
head -c 12 subject/ocsp.der > truncated
mv truncated subject/ocsp.der
reject 300 10 'subject:'
rm subject/ocsp.der
reject 300 10 'subject:'
printf 'V\t%s\t\t%s\tunknown\t/CN=device\n' "$expiry" "$serial" > index
respond
: > served
reject 300 10 'differ from responses served'
respond
: > served-rims
reject 300 10 'RIM bytes served'
echo "$rim_hash" > served-rims
echo unapproved-policy >> run/policy.rego
reject 300 10 'policy.rego differs'
echo test-policy > run/policy.rego
echo altered > run/inventory.csv
reject 300 10 "inventory.csv differs"
sed '2s/GPU-test-2/GPU-test-1/' good-inventory > run/inventory.csv
enrolled=$(sha256sum < run/inventory.csv | cut -d' ' -f1)
reject 300 10 "distinct PCI"
cp good-inventory run/inventory.csv
enrolled=$(sha256sum < run/inventory.csv | cut -d' ' -f1)
echo changed > run/nvattest.sha256
reject 300 10 "unapproved nvattest"
echo "$sdk" > run/nvattest.sha256
sed -i 's/0.000013/32.000000/' bin/chronyd
reject 300 10 'system clock must agree'
printf '#!/bin/sh\nexit 1\n' > bin/chronyd
reject 300 10 'could not measure site time'
