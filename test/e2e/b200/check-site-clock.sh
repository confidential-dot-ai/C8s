#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

: "${B200_NTS_SERVER:?set the site NTS server name}"
: "${B200_NTS_CA:?set the independently trusted site NTS CA file}"
if [[ ! $B200_NTS_SERVER =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ || ! $B200_NTS_CA =~ ^/[^[:space:]]+$ || ! -f $B200_NTS_CA ]]; then
    echo "need a site DNS name and an absolute NTS CA file path without whitespace" >&2
    exit 1
fi
measurement=$(chronyd -Q -t 20 "ntstrustedcerts 1 $B200_NTS_CA" "server $B200_NTS_SERVER iburst nts certset 1 maxdelay 0.5" 2>&1) || {
    echo "could not measure site time: $measurement" >&2; exit 1;
}
if ! awk '/System clock wrong by -?[0-9]+\.[0-9]+ seconds \(ignored\)/ {
    for (i = 1; i <= NF; i++) if ($i == "seconds" && $(i-1) > -1 && $(i-1) < 1) ok=1
} END { exit !ok }' <<< "$measurement"; then
    echo "system clock must agree with authenticated site time within one second: $measurement" >&2
    exit 1
fi
