#!/usr/bin/env bash
# Multi-process CDS-HA integration test: five real `c8s cds` processes on
# loopback addresses behind a fault-injecting proxy, with a history checker.
#
#   test/integration/cdsha/run.sh            # full matrix (about 15-20 min)
#   test/integration/cdsha/run.sh -short     # the -short subset (under 3 min)
#   test/integration/cdsha/run.sh -run 'TestNetworkFaults/A1'
#
# Linux only (uses 127.0.77.0/24 and 127.0.78.0/24 on lo). Replica logs go
# to $CDSHA_IT_LOGS (default: a temp dir, printed at the start); set
# CDSHA_IT_KEEP=1 to keep them after a passing run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$REPO_ROOT"

timeout="${CDSHA_IT_TIMEOUT:-45m}"
exec go test -tags integration -count=1 -timeout "$timeout" -v ./test/integration/cdsha/... "$@"
