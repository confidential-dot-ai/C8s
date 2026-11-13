#!/usr/bin/env bash
# release-cli.sh <version> <out-dir> <os>-<arch>...: build the c8s CLI a
# release publishes, as <out-dir>/c8s-<os>-<arch>, from the checked-out commit.
#
# The build is reproducible: the same commit, version and platform give the
# same bytes on any host. The toolchain is the `go` directive of go.mod, not
# the newer patch setup-go-c8s installs, so the commit alone names it. See
# docs/releases.md.
set -euo pipefail

[ $# -ge 3 ] || { echo "usage: $0 <version> <out-dir> <os>-<arch>..." >&2; exit 2; }
version=$1
out=$2
shift 2

[[ "$version" =~ ^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-beta[.][1-9][0-9]*)?$ ]] ||
  { echo "$0: '$version' is not a release tag" >&2; exit 2; }
for platform in "$@"; do
  [[ "$platform" =~ ^(linux|darwin)-(amd64|arm64)$ ]] ||
    { echo "$0: unsupported platform '$platform'" >&2; exit 2; }
done

mkdir -p "$out"
out="$(cd "$out" && pwd)"
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

directive="$(awk '$1 == "go" && $2 ~ /^[0-9]+[.][0-9]+[.][0-9]+$/ { print $2; exit }' go.mod)"
[ -n "$directive" ] || { echo "$0: go.mod has no 'go' directive with a patch version" >&2; exit 1; }

# Every input that reaches the binary is set here, so the caller's environment
# and its `go env -w` file cannot change the bytes.
export GOTOOLCHAIN="go$directive"
export GOENV=off CGO_ENABLED=0 GOFLAGS=-mod=readonly GOWORK=off GOEXPERIMENT=
export GOAMD64=v1 GOARM64=v8.0 GOFIPS140=off
unset GOOS GOARCH

actual="$(go env GOVERSION)"
[ "$actual" = "go$directive" ] ||
  { echo "$0: toolchain is $actual, go.mod names go$directive" >&2; exit 1; }

for platform in "$@"; do
  GOOS="${platform%-*}" GOARCH="${platform#*-}" \
    go build -trimpath -buildvcs=false \
    -ldflags="-s -w -buildid= -X github.com/confidential-dot-ai/c8s/internal/version.Version=$version" \
    -o "$out/c8s-$platform" ./cmd/c8s
done
