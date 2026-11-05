#!/usr/bin/env bash
# Exercise the shared helper itself, with kubectl replaced at its boundary.
set -euo pipefail
test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$test_dir/lib.sh"

calls=()
create_status=0
label_status=0
kubectl() {
  calls+=("$*")
  case "$1" in
    create) return "$create_status" ;;
    label) return "$label_status" ;;
    *) fail "unexpected kubectl command: $*" ;;
  esac
}

cw_namespace c8s-test
[[ ${#calls[@]} == 2 && $CW_NAMESPACE_CREATED == c8s-test ]] || fail "creation ownership not recorded"
[[ ${calls[0]} == 'create namespace c8s-test' ]] || fail "namespace must be created, not adopted"
cw_namespace_owned c8s-test || fail "created namespace not owned"
if cw_namespace_owned another; then fail "unrelated namespace claimed"; fi
[[ ${calls[1]} == 'label namespace c8s-test pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest pod-security.kubernetes.io/warn=restricted pod-security.kubernetes.io/audit=restricted' ]] || fail "wrong Restricted labels"

calls=()
create_status=1
if cw_namespace existing; then fail "existing namespace accepted"; fi
[[ ${#calls[@]} == 1 && -z $CW_NAMESPACE_CREATED ]] || fail "existing namespace labelled or claimed"

calls=()
create_status=42
status=0
cw_namespace unavailable || status=$?
[[ $status == 42 && ${#calls[@]} == 1 && -z $CW_NAMESPACE_CREATED ]] || fail "create failure not preserved"

calls=()
create_status=0
label_status=1
if cw_namespace denied; then fail "label rejection ignored"; fi
[[ ${#calls[@]} == 2 && $CW_NAMESPACE_CREATED == denied ]] || fail "new namespace lost its cleanup ownership"

echo 'PASS: CW namespace creation, exact labels, collision refusal, create error and label error ownership'

# cds_write: a CDS without persistence refuses operator tokens for
# --jwt-clock-skew after it starts, so that refusal is retried with a fresh
# token; any other outcome passes straight through.
too_early='server returned 401: operator token issued too early for a CDS without persistence (Helm cds.persistence.enabled); wait --jwt-clock-skew (Helm cds.jwtClockSkew) after CDS start and mint a fresh one'
errfile=$(mktemp)
callfile=$(mktemp)
sleepfile=$(mktemp)
trap 'rm -f "$errfile" "$callfile" "$sleepfile"' EXIT
c8s_refusals=0
c8s_error=''
c8s_status=0
# The stub runs in the helper's command substitution, so it counts on disk.
c8s() {
  echo >>"$callfile"
  if [ "$(wc -l <"$callfile")" -le "$c8s_refusals" ]; then echo "$too_early" >&2; return 1; fi
  if [ -n "$c8s_error" ]; then echo "$c8s_error" >&2; return "$c8s_status"; fi
  echo "note: target is a router front door" >&2
  echo "wrote $*"
}
sleep() { echo "$1" >>"$sleepfile"; }
reset() { c8s_refusals=$1 c8s_error=$2 c8s_status=$3; : >"$callfile"; : >"$sleepfile"; }
c8s_calls() { wc -l <"$callfile" | tr -d " "; }
slept() { awk '{ s += $1 } END { print s + 0 }' "$sleepfile"; }

reset 2 "" 0
out=$(cds_write c8s allowlist add digest image 2>"$errfile") || fail "write refused during the start window was not retried"
[[ $out == 'wrote allowlist add digest image' && $(c8s_calls) == 3 ]] || fail "write not retried until accepted: calls=$(c8s_calls) out=$out"
grep -q 'retrying' "$errfile" || fail "the wait was not explained: $(cat "$errfile")"
grep -q 'router front door' "$errfile" || fail "the accepted write's stderr was dropped"

reset 0 "" 0
out=$(cds_write c8s allowlist add digest image 2>"$errfile") || fail "accepted write failed"
[[ $(c8s_calls) == 1 && $(slept) == 0 ]] || fail "an accepted write waited or repeated: calls=$(c8s_calls) slept=$(slept)"

reset 0 'server returned 401: operator token reused' 3
status=0
cds_write c8s allowlist add digest image >/dev/null 2>"$errfile" || status=$?
[[ $status == 3 && $(c8s_calls) == 1 && $(slept) == 0 ]] || fail "another refusal was retried or its status changed: status=$status calls=$(c8s_calls) slept=$(slept)"
[[ $(cat "$errfile") == 'server returned 401: operator token reused' ]] || fail "another refusal's stderr was not preserved: $(cat "$errfile")"

reset 1000 "" 0
status=0
cds_write c8s allowlist add digest image >/dev/null 2>"$errfile" || status=$?
[[ $status == 1 && $(slept) -ge 30 ]] || fail "retrying must outlast the default 30s window and then fail: status=$status slept=$(slept)"
grep -q 'issued too early' "$errfile" || fail "the final refusal was not reported: $(cat "$errfile")"

echo 'PASS: cds_write retries the start-window refusal with a fresh token, outlasts the default window, and passes every other outcome through'
