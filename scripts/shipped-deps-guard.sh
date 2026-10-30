#!/usr/bin/env bash
# shipped-deps-guard.sh — keep test code and the replication library out of
# the binaries a CDS or a node measures.
#
# Usage, from anywhere in a checkout:
#   scripts/shipped-deps-guard.sh check     the ./cmd/... builds and the c8s_node build of ./cmd/c8s
#   scripts/shipped-deps-guard.sh selftest  the rules themselves, over fixed import graphs
#
# internal/testutil is linked by nothing shipped. `testing` is linked only by
# github.com/hashicorp/raft, whose testing.go sits in its non-test package;
# linking it registers no test flag unless testing.Init runs. A node runs no
# CDS replica, so the node build links no raft.
set -euo pipefail
cd "$(dirname "$0")/.."

testutil=github.com/confidential-dot-ai/c8s/internal/testutil
raft=github.com/hashicorp/raft

# Each rule reads "<package> <imports...>" lines and prints one line per
# violation.
test_code() {
  awk -v testutil="$testutil" -v raft="$raft" '
    $1 == testutil { print "links " $1 }
    $1 != raft { for (i = 2; i <= NF; i++) if ($i == "testing") print $1 " imports testing" }
  '
}

replication() {
  awk -v raft="$raft" '$1 == raft { print "links " $1 }'
}

# CGO_ENABLED=0 is how the shipped binaries are built.
graph() {
  CGO_ENABLED=0 go list -deps -f '{{.ImportPath}} {{join .Imports " "}}' "$@"
}

refuses() {
  local rule=$1 case=$2 graph=$3
  if [ -z "$("$rule" <<<"$graph")" ]; then
    echo "selftest: $rule accepted $case" >&2
    exit 1
  fi
}

accepts() {
  local rule=$1 case=$2 graph=$3
  if [ -n "$("$rule" <<<"$graph")" ]; then
    echo "selftest: $rule refused $case" >&2
    exit 1
  fi
}

case "${1:-}" in
check)
  shipped=$(graph ./cmd/...)
  node=$(graph -tags c8s_node ./cmd/c8s)
  test_found=$(printf '%s\n%s\n' "$shipped" "$node" | test_code | sort -u)
  raft_found=$(replication <<<"$node")
  if [ -n "$test_found$raft_found" ]; then
    echo "a shipped binary links code it must not:" >&2
    printf '%s\n' "$test_found" "$raft_found" | grep -v '^$' >&2
    exit 1
  fi
  ;;
selftest)
  via_raft="example.com/app fmt $raft
$raft fmt testing"
  via_helper="example.com/app fmt example.com/helper
example.com/helper testing"
  links_testutil="example.com/app $testutil
$testutil fmt"
  plain="example.com/app fmt"

  accepts test_code "testing imported by raft" "$via_raft"
  refuses test_code "a helper importing testing" "$via_helper"
  refuses test_code "a binary linking testutil" "$links_testutil"
  refuses replication "a node build linking raft" "$via_raft"
  accepts replication "a node build without raft" "$plain"
  ;;
*)
  echo "usage: $0 {check|selftest}" >&2
  exit 2
  ;;
esac
