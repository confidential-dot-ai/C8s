#!/usr/bin/env bash
# shipped-deps-guard.sh — keep test code out of the shipped binaries.
#
# Usage:
#   scripts/shipped-deps-guard.sh check     check ./cmd/... and the c8s_node build of ./cmd/c8s
#   scripts/shipped-deps-guard.sh selftest  check the rule itself on fixed import graphs
#
# internal/testattest may not be linked at all. The testing package may be
# imported only by github.com/hashicorp/raft: its testing.go (helpers in the
# non-test package) imports it, and the CDS-HA replicas need raft. Linking
# testing registers no test flags unless testing.Init runs.
set -euo pipefail

# Reads "<package> <imports...>" lines and prints each violation.
violations() {
  awk '
    $1 == "github.com/confidential-dot-ai/c8s/internal/testattest" { print "links " $1 }
    $1 != "github.com/hashicorp/raft" { for (i = 2; i <= NF; i++) if ($i == "testing") print $1 " imports testing" }
  '
}

graph() {
  CGO_ENABLED=0 go list -deps -f '{{.ImportPath}} {{join .Imports " "}}' "$@"
}

case "${1:-}" in
check)
  found=$({ graph ./cmd/...; graph -tags c8s_node ./cmd/c8s; } | violations | sort -u)
  if [ -n "$found" ]; then
    echo "testing code is in the dep graph of a shipped binary:" >&2
    echo "$found" >&2
    exit 1
  fi
  ;;
selftest)
  allowed=$'example.com/app fmt github.com/hashicorp/raft\ngithub.com/hashicorp/raft fmt testing'
  [ -z "$(violations <<<"$allowed")" ] || { echo "selftest: refused testing imported by raft" >&2; exit 1; }
  for refused in \
    $'example.com/app fmt example.com/helper\nexample.com/helper testing' \
    $'example.com/app github.com/confidential-dot-ai/c8s/internal/testattest\ngithub.com/confidential-dot-ai/c8s/internal/testattest fmt'; do
    [ -n "$(violations <<<"$refused")" ] || { echo "selftest: accepted ${refused//$'\n'/; }" >&2; exit 1; }
  done
  ;;
*)
  echo "usage: $0 {check|selftest}" >&2
  exit 2
  ;;
esac
