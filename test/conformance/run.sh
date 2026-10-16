#!/usr/bin/env bash
# Run the conformance scenarios against one backend and write the Cucumber
# report the suite's judge reads. The judge runs this as its test command and
# owns the snapshot, the recording and the verdict; this script owns what only
# the harness can do: set the backend up, run the step definitions, tear the
# backend down. README.md beside this file states the contract.
#
# Env:
#   CONFORMANCE_BACKEND    kind, metal or metal-dev (backends/<name>.sh), plus what it requires
#   CONFORMANCE_FEATURES   the directory of .feature files to run
#   CONFORMANCE_REPORT     where to write the Cucumber JSON report
#   GODOG_TAGS             optional tag expression, e.g. @area:enforcement
#
# Exits with godog's status: non-zero when a step failed. Undefined and pending
# steps are the judge's backlog, not a failure, except in the scenarios
# must-run lists for the backend, which fail the run when they skip.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${CONFORMANCE_BACKEND:?kind, metal or metal-dev}"
: "${CONFORMANCE_FEATURES:?the directory of .feature files}"
: "${CONFORMANCE_REPORT:?where to write the Cucumber JSON report}"

be() { bash "$here/backends/$CONFORMANCE_BACKEND.sh" "$@"; }
trap 'be teardown >/dev/null 2>&1 || true' EXIT

mkdir -p "$(dirname "$CONFORMANCE_REPORT")"
report="$(cd "$(dirname "$CONFORMANCE_REPORT")" && pwd)/$(basename "$CONFORMANCE_REPORT")"
# TestFeatures reads the directory from the environment; it must survive the cd below.
CONFORMANCE_FEATURES="$(cd "$CONFORMANCE_FEATURES" && pwd)"
export CONFORMANCE_FEATURES CONFORMANCE_BACKEND

echo "conformance: $(be subject)" >&2
be setup
rc=0
(cd "$here/steps" && go test -count=1 -timeout 80m . \
    --godog.format="progress,cucumber:$report" \
    ${GODOG_TAGS:+--godog.tags="$GODOG_TAGS"}) || rc=$?

# The scenarios must-run lists for this backend, of those the report holds:
# one that skipped, or has a step no definition matches, fails the run.
must="$(awk -v b="$CONFORMANCE_BACKEND" '$1 == b {print $2}' "$here/must-run")"
skipped="$(jq -r --arg must "$must" '
    ($must | split("\n")) as $tags
    | [.[].elements[]? | select(.type == "scenario")
       | select(any(.steps[]; .result.status == "skipped" or .result.status == "undefined"))
       | .tags[]?.name | select(IN($tags[]))]
    | unique[]' "$report")"
if [ -n "$skipped" ]; then
    echo "conformance: scenarios must-run lists for $CONFORMANCE_BACKEND did not run: ${skipped//$'\n'/ }" >&2
    rc=1
fi
exit "$rc"
