#!/usr/bin/env bash
# The CDS HA harness: three real `c8s cds` replicas on loopback addresses.
#
#   test/integration/cdsha/run.sh            every scenario
#   test/integration/cdsha/run.sh -short     the subset a pull request runs
#   test/integration/cdsha/run.sh -run TestARestartedReplicaRejoinsItsCluster
#
# Linux only: the replicas answer at 127.0.77.0/24.
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)/../../.."
exec go test -tags integration -count=1 -timeout "${CDSHA_TIMEOUT:-20m}" -v ./test/integration/cdsha/... "$@"
