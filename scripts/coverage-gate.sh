#!/usr/bin/env bash
# coverage-gate.sh — compute and gate Go test coverage.
#
# Usage:
#   scripts/coverage-gate.sh run [profile]        run tests, write coverage profile
#   scripts/coverage-gate.sh kernel <profile>     add real kernel dm-verity coverage
#   scripts/coverage-gate.sh total <profile>      print total coverage (e.g. "67.94")
#
# The profile is produced with -coverpkg=./... so packages without their own
# test files are still measured (a brand-new untested package counts as 0%,
# not "absent"). CI compares the PR's total against the base branch's total
# and fails if it decreased. Workflow tests execute shell/YAML fixtures, not
# production Go, so they run in the normal test job rather than this measurement.
# Use this same script for both head and base to keep the totals comparable.
set -euo pipefail

cmd="${1:-}"
profile="${2:-coverage.out}"

percent() { # per-package coverage table from a coverprofile: "<pct> <stmts> <pkg>"
  awk -F'[ :]' '
    NR==1 {next}
    {
      key=$1":"$2; stmts[key]=$3; if ($4>0) covered[key]=1;
    }
    END {
      for (k in stmts) {
        file=k; sub(/:[^:]*$/, "", file);
        pkg=file; sub(/\/[^\/]*$/, "", pkg);
        tot[pkg]+=stmts[k]; if (covered[k]) cov[pkg]+=stmts[k];
        T+=stmts[k]; if (covered[k]) C+=stmts[k];
      }
      for (p in tot) printf "%.1f %d %s\n", 100*cov[p]/tot[p], tot[p], p;
      # Two decimals: the gate compares this against a tolerance, and at one
      # decimal the smallest representable drop already exceeded it.
      printf "%.2f %d TOTAL\n", (T ? 100*C/T : 0), T;
    }' "$1"
}

case "$cmd" in
run)
  module=$(GOWORK=off go list -m)
  packages=$(go list ./...)
  test_packages=()
  while IFS= read -r package; do
    [ "$package" = "$module/test/workflows" ] || test_packages+=("$package")
  done <<< "$packages"
  [ "${#test_packages[@]}" -gt 0 ] || { echo "no Go packages to measure" >&2; exit 1; }
  go test "${test_packages[@]}" -count=1 -coverprofile="$profile" -coverpkg=./...
  ;;
kernel)
  # Older base revisions have no verity harness. Keep the same measurement
  # procedure for head and base without inventing tests on the older tree.
  if [ ! -f node-guest-image/tests/mount-verity-test.sh ]; then
    echo "no kernel verity harness on this revision"
    exit 0
  fi
  # A base revision's own harness may predate the coverage argument; this
  # script's harness drives the base revision's test binary instead.
  harness="$(cd "$(dirname "$0")/.." && pwd)/node-guest-image/tests/mount-verity-test.sh"
  [ -s "$profile" ] || { echo "run ordinary coverage first" >&2; exit 1; }
  kernel_scratch=$(mktemp -d)
  trap 'rm -rf "$kernel_scratch"' EXIT
  mkdir "$kernel_scratch/profiles"
  go test -c -coverpkg=./... -o "$kernel_scratch/nri-verity.test" ./internal/cmds/nri-image-policy
  sudo -n bash "$harness" "$kernel_scratch/nri-verity.test" "$kernel_scratch/profiles"
  [ -s "$kernel_scratch/profiles/dm-verity.out" ] || { echo "kernel harness produced no profile" >&2; exit 1; }
  # percent() unions covered blocks from duplicate records; retain one header.
  for kernel_profile in "$kernel_scratch"/profiles/*.out; do
    tail -n +2 "$kernel_profile" >> "$profile"
  done
  ;;
total)
  percent "$profile" | awk '$3=="TOTAL" {print $1}'
  ;;
*)
  echo "usage: $0 {run|kernel|total} [profile]" >&2
  exit 2
  ;;
esac
