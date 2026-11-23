#!/usr/bin/env bash
# mutation-check.sh - advisory diff-based mutation testing (gremlins).
#
# Usage:
#   scripts/mutation-check.sh run <base-ref> [out]   mutate code changed vs base-ref,
#                                                    write <out>.json and <out>.log
#   scripts/mutation-check.sh full [out]             mutate every covered mutant (slow)
#   scripts/mutation-check.sh summary [out] [root]   print markdown summary from <out>.json,
#                                                    reading mutated lines from under <root>
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

summary() { # $1=out-prefix $2=source-root (default .)
  local json="$1.json" root="${2:-.}"
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
  local lived
  lived="$(jq -r '.files[]? | .file_name as $f | .mutations[]?
    | select(.status == "LIVED") | [$f, .line, .column, .type] | @tsv' "$json")"
  [[ -n "$lived" ]] || return 0
  echo
  echo "### Lived mutants"
  echo
  echo "The tests of each line's package still pass with the operator replaced as shown."
  echo "Add a test that fails on it, or say in the PR why it stays."
  echo
  local file line col type
  while IFS=$'\t' read -r file line col type; do
    describe "$root" "$file" "$line" "$col" "$type"
  done <<< "$lived"
}

# The operator gremlins puts in place of $2 for mutant type $1 (its enabled
# mutators only); empty when $2 is not an operator that type mutates.
replacement() {
  case "$1 $2" in
  "CONDITIONALS_NEGATION ==") echo "!=" ;;
  "CONDITIONALS_NEGATION !=") echo "==" ;;
  "CONDITIONALS_NEGATION <") echo ">=" ;;
  "CONDITIONALS_NEGATION <=") echo ">" ;;
  "CONDITIONALS_NEGATION >") echo "<=" ;;
  "CONDITIONALS_NEGATION >=") echo "<" ;;
  "CONDITIONALS_BOUNDARY <") echo "<=" ;;
  "CONDITIONALS_BOUNDARY <=") echo "<" ;;
  "CONDITIONALS_BOUNDARY >") echo ">=" ;;
  "CONDITIONALS_BOUNDARY >=") echo ">" ;;
  "ARITHMETIC_BASE +") echo "-" ;;
  "ARITHMETIC_BASE -" | "INVERT_NEGATIVES -") echo "+" ;;
  "ARITHMETIC_BASE *") echo "/" ;;
  "ARITHMETIC_BASE /" | "ARITHMETIC_BASE %") echo "*" ;;
  "INCREMENT_DECREMENT ++") echo "--" ;;
  "INCREMENT_DECREMENT --") echo "++" ;;
  esac
}

# shellcheck disable=SC2016  # the markdown formats hold literal backticks
describe() { # $1=source-root $2=file $3=line $4=column $5=type; one markdown list item
  local text="" op="" new="" width root dir src
  # The report's path and position go into a file read, sed and arithmetic:
  # a readable file that is physically under the root and digits only, or the
  # mutant is listed bare. The x keeps a newline ending a directory's name,
  # which the substitution would strip.
  root="$(CDPATH="" cd -P "$1" 2>/dev/null && pwd -P && printf x)" || root=""
  src="$1/$2"
  dir="$(CDPATH="" cd -P "${src%/*}" 2>/dev/null && pwd -P && printf x)" || dir=""
  root="${root%$'\n'x}"
  dir="${dir%$'\n'x}"
  src="$dir/${2##*/}"
  if [[ "$3" =~ ^[1-9][0-9]*$ && "$4" =~ ^[1-9][0-9]*$ && -n "$root" && -n "$dir" && "$dir/" == "${root%/}/"* \
    && -f "$src" && ! -L "$src" && -r "$src" ]]; then
    text="$(sed -n "${3}p" "$src" 2>/dev/null)" || text=""
    # Go columns count bytes; try the two-byte operator before the one-byte one.
    for width in 2 1; do
      op="$(LC_ALL=C; printf '%s' "${text:$(($4 - 1)):width}")"
      new="$(replacement "$5" "$op")"
      [[ -n "$new" ]] && break
    done
  fi
  if [[ -z "$new" ]]; then
    printf -- '- `%s:%s:%s` %s\n' "$2" "$3" "$4" "$5"
    return 0
  fi
  # Drop the indent; of a long line keep the 160 characters around the operator.
  # The column counts bytes and the window characters, so count the prefix.
  local indent="${text%%[![:space:]]*}" before from
  before="$(LC_ALL=C; printf '%s' "${text:0:$(($4 - 1))}")"
  text="${text#"$indent"}"
  from=$((${#before} - ${#indent} - 80))
  if [[ "${#text}" -gt 160 ]]; then
    [[ "$from" -gt $((${#text} - 160)) ]] && from=$((${#text} - 160))
    [[ "$from" -lt 0 ]] && from=0
    local tail=""
    [[ $((from + 160)) -lt "${#text}" ]] && tail="..."
    text="${text:from:160}$tail"
    [[ "$from" -gt 0 ]] && text="...$text"
  fi
  # printf, not echo: a backslash in the source line stays as written.
  printf -- '- `%s:%s:%s`: `%s` replaced with `%s`\n\n  ```go\n  %s\n  ```\n' "$2" "$3" "$4" "$op" "$new" "$text"
}

# shellcheck disable=SC2016  # the expected markdown holds literal backticks
selftest() { # summary must handle lived mutants, zero mutants, and a missing report
  local dir out long
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
        {"type": "CONDITIONALS_BOUNDARY", "status": "LIVED", "line": 6, "column": 7},
        {"type": "ARITHMETIC_BASE", "status": "NOT COVERED", "line": 9, "column": 12},
        {"type": "INVERT_NEGATIVES", "status": "LIVED", "line": 1, "column": 1}
      ]
    }
  ],
  "test_efficacy": 25,
  "mutations_coverage": 80,
  "mutants_total": 5,
  "mutants_killed": 1,
  "mutants_lived": 3,
  "mutants_not_viable": 0,
  "mutants_not_covered": 1
}
JSON
  printf '%s\n' 'package calc' '' 'func add(a, b int) int { return a + b }' '' 'func positive(a int) bool {' \
    "$(printf '\tif a > 0 {')" "$(printf '\t\treturn true')" "$(printf '\t}')" "$(printf '\treturn a - 1 > 0')" '}' > "$dir/calc.go"
  mkdir "$dir/sub"
  ln -s .. "$dir/sub/link"
  ln -s ../calc.go "$dir/sub/link.go"
  # A sibling named as the root plus a newline, reached through a symlink.
  mkdir "$dir/sub"$'\n'
  command cp -f "$dir/calc.go" "$dir/sub"$'\n'/calc.go
  ln -s "../sub"$'\n' "$dir/sub/nl"
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
  out="$(summary "$dir/summary-sample" "$dir")"
  echo "$out" | grep -q -- "- Test efficacy: 25%" || { echo "selftest: efficacy line wrong" >&2; return 1; }
  echo "$out" | grep -qF -- '- `calc.go:6:7`: `>` replaced with `<=`' || { echo "selftest: negation not described" >&2; return 1; }
  echo "$out" | grep -qF -- '- `calc.go:6:7`: `>` replaced with `>=`' || { echo "selftest: boundary not described" >&2; return 1; }
  echo "$out" | grep -qxF '  if a > 0 {' || { echo "selftest: mutated line not shown" >&2; return 1; }
  # A position that is not a number, or a path leaving the root (by name or by symlink), is not read;
  # a file in a package under the root is.
  [[ "$(describe "$dir" calc.go '6p;e true' 7 CONDITIONALS_NEGATION)" == '- `calc.go:6p;e true:7` CONDITIONALS_NEGATION' ]] \
    && [[ "$(describe "$dir" calc.go 6 unknown CONDITIONALS_NEGATION)" == '- `calc.go:6:unknown` CONDITIONALS_NEGATION' ]] \
    && [[ "$(describe "$dir/sub" ../calc.go 6 7 CONDITIONALS_NEGATION)" == '- `../calc.go:6:7` CONDITIONALS_NEGATION' ]] \
    && [[ "$(describe "$dir/sub" link/calc.go 6 7 CONDITIONALS_NEGATION)" == '- `link/calc.go:6:7` CONDITIONALS_NEGATION' ]] \
    && [[ "$(describe "$dir/sub" nl/calc.go 6 7 CONDITIONALS_NEGATION)" == '- `nl/calc.go:6:7` CONDITIONALS_NEGATION' ]] \
    && [[ "$(describe "$dir/sub" link.go 6 7 CONDITIONALS_NEGATION)" == '- `link.go:6:7` CONDITIONALS_NEGATION' ]] \
    || { echo "selftest: an unchecked path or position was used" >&2; return 1; }
  mkdir "$dir/pkg"
  command cp -f "$dir/calc.go" "$dir/pkg/calc.go"
  describe "$dir" pkg/calc.go 6 7 CONDITIONALS_NEGATION | grep -qF 'replaced with `<=`' \
    || { echo "selftest: a file under the root was refused" >&2; return 1; }
  # A position holding no operator of that type still gets a line.
  echo "$out" | grep -qF -- '- `calc.go:1:1` INVERT_NEGATIVES' || { echo "selftest: undescribed mutant dropped" >&2; return 1; }
  # NOT COVERED mutants were never run: counted, not listed.
  echo "$out" | grep -q "1 not covered" || { echo "selftest: not-covered count missing" >&2; return 1; }
  if echo "$out" | grep -q "calc.go:9"; then echo "selftest: not-covered mutant listed" >&2; return 1; fi
  # A long line shows the text around its operator, not its start.
  { printf '\tx := "%0200d"; if a > 0 {}\n' 0; } > "$dir/long.go"
  long="$(describe "$dir" long.go 1 216 CONDITIONALS_BOUNDARY)"
  echo "$long" | grep -qE '^  \.\.\.0+"; if a > 0 \{\}$' || { echo "selftest: long line not windowed on the operator" >&2; return 1; }
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
  summary "${2:-mutation}" "${3:-.}"
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
  echo "usage: $0 {run <base-ref> [out]|full [out]|summary [out] [root]|selftest|ci <base-ref>}" >&2
  exit 2
  ;;
esac
