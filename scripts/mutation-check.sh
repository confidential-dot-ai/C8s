#!/usr/bin/env bash
# mutation-check.sh - advisory diff-based mutation testing (gremlins).
#
# Usage:
#   scripts/mutation-check.sh run <base-ref> [out]   mutate code changed vs base-ref,
#                                                    write <out>.json and <out>.log
#   scripts/mutation-check.sh full [out]             mutate every covered mutant (slow)
#   scripts/mutation-check.sh summary [out]          print markdown summary from <out>.json
#   scripts/mutation-check.sh selftest               check summary against generated fixtures
#   scripts/mutation-check.sh ci <base-ref>          run + summary >> GITHUB_STEP_SUMMARY,
#                                                    always exit 0 (advisory)
#
# gremlins is pinned as a tool dependency in go.mod. Static policy (excluded
# files) lives in .gremlins.yaml; only tests of the mutated package run per
# mutant, but the initial coverage pass runs the full suite.
set -euo pipefail

cmd="${1:-}"

run_mutation() { # $1=base-ref ("" mutates everything) $2=out-prefix
  local base="$1" out="$2"
  if [[ -n "$base" ]]; then
    go tool gremlins unleash --diff "$base" \
      --output "${out}.json" --output-statuses lc 2>&1 | tee "${out}.log"
  else
    go tool gremlins unleash \
      --output "${out}.json" --output-statuses lc 2>&1 | tee "${out}.log"
  fi
}

summary() { # $1=out-prefix
  local json="$1.json"
  command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
  echo "## Mutation testing (advisory)"
  echo
  if [[ ! -s "$json" ]]; then
    echo "No report produced (gremlins failed before mutation testing; see job log)."
    return 0
  fi
  if [[ "$(jq '.mutants_total // 0' "$json")" -eq 0 ]]; then
    echo "No mutants generated: the diff touched no mutable Go code."
    return 0
  fi
  jq -r '"- Test efficacy: \(.test_efficacy * 10 | round / 10)% (killed / (killed + lived))",
         "- Mutant coverage: \(.mutations_coverage * 10 | round / 10)%",
         "- Mutants: \(.mutants_total) total, \(.mutants_killed // 0) killed, \(.mutants_lived // 0) lived, \(.mutants_not_covered // 0) not covered, \(.mutants_not_viable // 0) not viable"' "$json"
  local survivors
  survivors="$(jq -r '.files[]? | .file_name as $f | .mutations[]?
    | select(.status == "LIVED" or .status == "NOT COVERED")
    | "- `\($f):\(.line):\(.column)` \(.type) \(.status)"' "$json")"
  if [[ -n "$survivors" ]]; then
    echo
    echo "### Surviving mutants"
    echo "$survivors" | head -n 100
    local n
    n="$(echo "$survivors" | wc -l | tr -d ' ')"
    if [[ "$n" -gt 100 ]]; then
      echo "- (truncated, $n total)"
    fi
  fi
}

selftest() { # summary must handle survivors, zero mutants, and a missing report
  local dir out
  dir="$(mktemp -d)"
  # shellcheck disable=SC2064  # expand now: $dir is local and gone at EXIT
  trap "rm -rf '$dir'" EXIT
  # Gremlins-report-shaped fixtures, generated here so no report dumps are
  # committed to the repo.
  cat > "$dir/summary-sample.json" <<'JSON'
{
  "go_module": "github.com/confidential-dot-ai/confidential-kubernetes",
  "files": [
    {
      "file_name": "calc.go",
      "mutations": [
        {"type": "CONDITIONALS_NEGATION", "status": "LIVED", "line": 6, "column": 7},
        {"type": "ARITHMETIC_BASE", "status": "KILLED", "line": 3, "column": 35},
        {"type": "CONDITIONALS_BOUNDARY", "status": "LIVED", "line": 6, "column": 7}
      ]
    }
  ],
  "test_efficacy": 33.33333333333333,
  "mutations_coverage": 100,
  "mutants_total": 3,
  "mutants_killed": 1,
  "mutants_lived": 2,
  "mutants_not_viable": 0,
  "mutants_not_covered": 0
}
JSON
  cat > "$dir/summary-zero.json" <<'JSON'
{
  "go_module": "probe",
  "files": [],
  "test_efficacy": 0,
  "mutations_coverage": 0,
  "mutants_total": 0,
  "mutants_killed": 0,
  "mutants_lived": 0,
  "mutants_not_viable": 0,
  "mutants_not_covered": 0
}
JSON
  out="$(summary "$dir/summary-sample")"
  echo "$out" | grep -q -- "- Test efficacy: 33.3%" || { echo "selftest: efficacy line wrong" >&2; return 1; }
  echo "$out" | grep -q "LIVED" || { echo "selftest: survivor list missing" >&2; return 1; }
  out="$(summary "$dir/summary-zero")"
  echo "$out" | grep -q "No mutants generated" || { echo "selftest: zero-mutant path wrong" >&2; return 1; }
  out="$(summary "$dir/no-such-report")"
  echo "$out" | grep -q "No report produced" || { echo "selftest: missing-report path wrong" >&2; return 1; }
  echo "selftest ok"
}

case "$cmd" in
run)
  run_mutation "${2:?base ref required}" "${3:-mutation}"
  ;;
full)
  run_mutation "" "${2:-mutation}"
  ;;
summary)
  summary "${2:-mutation}"
  ;;
selftest)
  selftest
  ;;
ci)
  # Advisory end to end: report to the step summary, never fail the job.
  run_mutation "${2:?base ref required}" mutation \
    || echo "gremlins exited non-zero (advisory, continuing)" >&2
  summary mutation >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"
  ;;
*)
  echo "usage: $0 {run <base-ref> [out]|full [out]|summary [out]|selftest|ci <base-ref>}" >&2
  exit 2
  ;;
esac
