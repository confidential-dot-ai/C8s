# Shared assertions for the node-image harnesses. Unlike test/e2e/lib.sh's
# fail-fast fail(), ok() counts and keeps going; the "FAIL:" prefix stays
# aligned with that lib (CI greps it).

PASS=0; FAIL=0
declare -a FAILURES

note() { printf '%s\n' "$*"; }

# ok DESC cmd... — count an assertion, attributed to $CASE.
ok() {
    local desc="$1"; shift
    if "$@"; then PASS=$((PASS+1)); else
        FAIL=$((FAIL+1)); FAILURES+=("$CASE: $desc"); note "  FAIL: $CASE: $desc"
    fi
}

not() { ! "$@"; }

# stderr_has PATTERN — the last run's stderr (captured in $WORK) names the cause.
stderr_has() { grep -q "$1" "$WORK/stderr"; }

# summarize TITLE — print totals; exit 1 if anything failed.
summarize() {
    note ""
    note "==== $1 ===="
    note "PASS: $PASS  FAIL: $FAIL"
    if (( FAIL > 0 )); then
        note "-- failures:"
        local f; for f in "${FAILURES[@]}"; do note "   $f"; done
        exit 1
    fi
}

file_mode() { stat -c %a "$1" 2>/dev/null || echo MISSING; }
