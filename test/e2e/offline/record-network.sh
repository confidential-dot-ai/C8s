#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
[[ $# == 2 ]] || { echo "usage: $0 SITE.json NEW_RECORDING_DIRECTORY" >&2; exit 2; }
mkdir -- "$2"
out=$(realpath "$2")
cp -- "$1" "$out/network.json"
"$here/network.py" firewall "$out/network.json" > "$out/filter.nft"
nft -f "$out/filter.nft"
nft -s list table inet c8s_pilot > "$out/before.nft"
ip -j link show > "$out/interfaces.json"
tcpdump -nn -i any -Q in -y LINUX_SLL2 -s0 -U -B 8192 -w - 'port 53' > "$out/dns.pcap" 2>"$out/tcpdump.log" &
recorder=$!
until grep -q 'listening on' "$out/tcpdump.log"; do kill -0 "$recorder"; sleep .1; done
date -u +%FT%TZ > "$out/start-utc"
echo "Gateway denial and DNS capture are active. Press Ctrl-C after the lifecycle run."
requested=false
trap 'requested=true; kill -INT "$recorder" 2>/dev/null || true' INT TERM
wait "$recorder" || true
"$requested" || { echo "capture ended before operator stop; see tcpdump.log" >&2; exit 1; }
wait "$recorder"
date -u +%FT%TZ > "$out/end-utc"
nft -s list table inet c8s_pilot > "$out/after.nft"
cmp "$out/before.nft" "$out/after.nft"
nft -j list counter inet c8s_pilot denied > "$out/counter.json"
journalctl --quiet -k --since "$(cat "$out/start-utc")" -o cat | awk 'index($0, "c8s-pilot-denied ")' > "$out/denied.log"
echo "Recording closed. The gateway filter remains active."
