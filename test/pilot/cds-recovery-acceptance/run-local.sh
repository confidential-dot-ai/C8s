#!/usr/bin/env bash
# Local protocol qualification only. Hardware custody remains unverified.
# Usage: test/pilot/cds-recovery-acceptance/run-local.sh /absolute/output/dir
set -euo pipefail
if [[ $# != 1 || $1 != /* ]]; then
  echo 'Usage: run-local.sh /absolute/output/dir' >&2
  exit 2
fi
cd "$(dirname "$0")/../../.."
cds_acceptance_output=$1
mkdir -p "$cds_acceptance_output"
# Exclusive output prevents stale results from appearing to certify a new run.
if ! mkdir "$cds_acceptance_output/run"; then
  echo 'Choose a fresh output directory; an acceptance run already exists here.' >&2
  exit 2
fi
cds_acceptance_output="$cds_acceptance_output/run"
git rev-parse HEAD > "$cds_acceptance_output/base-commit.txt"
git status --porcelain > "$cds_acceptance_output/worktree-status.txt"
git diff HEAD --binary > "$cds_acceptance_output/worktree.diff"
echo 'Running local recovery race tests and vet.'
go test -race -count=1 -json ./internal/cdsrecovery ./internal/cdsconfig ./internal/cdsobject ./internal/cmds/cds > "$cds_acceptance_output/unit.jsonl"
go vet ./internal/cdsrecovery ./internal/cdsconfig ./internal/cdsobject ./internal/cmds/cds > "$cds_acceptance_output/vet.log" 2>&1
echo 'Running Raft, object WAL and metadata comparisons sequentially, including sealed recovery.'
CDSHA_RELEASE=1 go test -tags integration -count=1 -timeout 15m -json ./test/integration/cdsha \
  -run '^(TestCARotationBackendParity|TestWorkloadBackendParity|TestProtectedRecoveryRefusesDowngradeReplayAndMissingHistory)$' \
  > "$cds_acceptance_output/process.jsonl"
python3 test/pilot/cds-recovery-acceptance/report.py "$cds_acceptance_output"
