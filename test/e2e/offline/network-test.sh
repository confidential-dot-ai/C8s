#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
if [[ ${1:-} != isolated ]]; then exec unshare -Urn -- "$0" isolated; fi
[[ $(readlink /proc/self/ns/net) != "$(readlink /proc/1/ns/net)" ]] || exit 1
tmp=$(mktemp -d)
cd "$tmp"
unshare -n sleep 120 &
client=$!
trap 'kill "$client" 2>/dev/null || true; rm -rf -- "$tmp"' EXIT
if [[ $(sysctl -n net.ipv4.ip_forward) != 1 ]]; then sysctl -w net.ipv4.ip_forward=1; fi
[[ $(sysctl -n net.ipv4.ip_forward) == 1 ]]
ip link add pilot type veth peer name client
ip link set client netns "$client"
ip addr add 10.61.0.1/24 dev pilot
ip link set pilot up
ip link add site type dummy
ip addr add 192.0.2.1/24 dev site
ip link set site up
ns=(nsenter -t "$client" -n)
"${ns[@]}" ip link set client up
for index in 2 3 4 5; do "${ns[@]}" ip addr add "10.61.0.$index/24" dev client; done
"${ns[@]}" ip route add default via 10.61.0.1
cat > site.json <<'JSON'
{"interfaces":["pilot"],"destinations":["10.61.0.1"],"dnsNames":["registry.site.test"],
"pilotId":"test","refreshObserverKey":"observer.pub","verifierImage":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sources":{"host":["10.61.0.2"],"ta":["10.61.0.3"],"worker":["10.61.0.4"],"cli":["10.61.0.5"]}}
JSON
jq --arg end "$(date -u -d '+12 hours' +%FT%TZ)" '.pilotEndUtc=$end' site.json > approved.json
cp approved.json site.json
cp approved.json network.json
"$here/network.py" firewall site.json > filter.nft
nft -f filter.nft
nft -s list table inet c8s_pilot > before.nft
ip -j link show > interfaces.json
tcpdump -Z root -nn -i any -y LINUX_SLL2 -Q in -w dns.pcap 'port 53' 2>tcpdump.log &
capture=$!
until grep -q 'listening on' tcpdump.log; do kill -0 "$capture"; sleep .1; done
mkdir first final
stamp() { date -u +%FT%T.%NZ > "$1"; }
stamp start-utc
stamp pilot-start-utc
for run in first final; do
    stamp "$run/start-utc"
    for index in 2 3 4 5; do "${ns[@]}" dig +time=1 +tries=1 -b "10.61.0.$index" @10.61.0.1 registry.site.test >/dev/null || true; done
    stamp "$run/end-utc"
done
sleep 1
kill -INT "$capture"
wait "$capture"
stamp end-utc
nft -s list table inet c8s_pilot > after.nft
nft -j list counter inet c8s_pilot denied > counter.json
journalctl --quiet -k --since "$(cat start-utc)" -o cat | awk 'index($0, "c8s-pilot-denied ")' > denied.log
audit() { "$here/network.py" audit site.json . first "${1:-final}"; }
reject() { if audit "${2:-final}" >log 2>&1; then exit 1; fi; grep -Fq "$1" log; }
if audit >log 2>&1; then exit 1; fi
snap=$(sha256sum < site.json | cut -d' ' -f1)
record=$(jq -nc --arg sha "$snap" --arg at "$(cat first/end-utc)" '{schemaVersion:1,event:"selected_tdx_recheck",scope:"intel_collateral",outcome:"valid",trigger:"sighup",generation:1,sha256:$sha,siteTime:$at}')
printf '%s INFO selected_tdx: %s\n' "$(cat first/end-utc)" "$record" > refresh-event.log
openssl genpkey -algorithm ED25519 -out observer.key
openssl pkey -in observer.key -pubout -out observer.pub
jq -n --slurpfile cfg site.json --arg snap "$snap" --arg digest "$(sha256sum < refresh-event.log | cut -d' ' -f1)" --arg utc "$(cat first/end-utc)" \
    '{scope:"intel_collateral",event:"background-refresh-succeeded",pilotId:"test",observedUtc:$utc,eventSha256:$digest,verifierImage:$cfg[0].verifierImage,generation:1,snapshotSha256:$snap}' > refresh.json
openssl pkeyutl -sign -inkey observer.key -rawin -in refresh.json -out refresh.sig
audit
reject 'strictly ordered' first
jq --arg end "$(date -u -d '+2 days' +%FT%TZ)" '.pilotEndUtc=$end' approved.json > site.json
reject 'different pilot configuration'
cp site.json network.json
reject 'final 24 hours'
cp approved.json network.json
cp approved.json site.json
printf 'altered' >> refresh-event.log
reject 'mismatched source refresh event'
truncate -s -7 refresh-event.log
cp refresh-event.log valid-event; cp refresh.json valid-witness
for bad in s/sighup/startup/ s/valid/invalid/ 's/"generation":1/"generation":true/' "s/$snap/${snap:1}/"; do
    sed "$bad" valid-event > refresh-event.log
    jq --arg source "$(sha256sum < refresh-event.log | cut -d' ' -f1)" '.eventSha256=$source' valid-witness > refresh.json
    openssl pkeyutl -sign -inkey observer.key -rawin -in refresh.json -out refresh.sig
    reject 'did not verify the selected Intel generation'
done
mv valid-event refresh-event.log; mv valid-witness refresh.json
openssl pkeyutl -sign -inkey observer.key -rawin -in refresh.json -out refresh.sig
sed -i s/registry.site.test/unrelated.site.test/ site.json network.json
reject 'unapproved DNS name'
sed -i s/unrelated.site.test/registry.site.test/ site.json network.json
"${ns[@]}" dig +time=1 +tries=1 @192.0.2.1 registry.site.test >/dev/null || true
before=$(nft -j list counter inet c8s_pilot denied | jq -e '[.nftables[].counter.packets // empty] | first | select(.>0)')
"${ns[@]}" dig +time=1 +tries=1 @192.0.2.99 registry.site.test >/dev/null || true
nft -j list counter inet c8s_pilot denied > counter.json
reject 'denied egress'
jq -e --argjson before "$before" '[.nftables[].counter.packets // empty] | first > $before' counter.json >/dev/null
