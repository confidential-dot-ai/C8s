#!/usr/bin/env bash
# The TA HA harness: three real `c8s ta` replicas on loopback addresses.
#
#   test/integration/taha/run.sh            every scenario
#   test/integration/taha/run.sh -short     the subset a pull request runs
#   test/integration/taha/run.sh -run TestARestartedReplicaRejoinsItsCluster
#   TAHA_BACKEND=raft test/integration/taha/run.sh
#
# TAHA_BACKEND names the backend every cluster runs, raft by default; the
# scenarios about Raft's own membership skip under any other backend.
#
# Linux only: the replicas answer at 127.0.77.0/24.
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)/../../.."
exec go test -tags integration -count=1 -timeout "${TAHA_TIMEOUT:-20m}" -v ./test/integration/taha/... "$@"
