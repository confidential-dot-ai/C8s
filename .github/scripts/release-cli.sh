#!/usr/bin/env bash
# release-cli.sh <version> <go-version> <out-dir> <os>-<arch>...: build the
# c8s CLI a release publishes, as <out-dir>/c8s-<os>-<arch>, from the
# checked-out commit, with the toolchain <go-version> (for example go1.27.4).
#
# The build is reproducible: the same commit, version, toolchain and platform
# give the same bytes on any host. A release uses the newest Go patch its
# runner has; `go version c8s-<os>-<arch>` prints the toolchain of a published
# binary. See docs/releases.md.
set -euo pipefail

[ $# -ge 4 ] || { echo "usage: $0 <version> <go-version> <out-dir> <os>-<arch>..." >&2; exit 2; }
version=$1
toolchain=$2
out=$3
shift 3

[[ "$version" =~ ^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-beta[.][1-9][0-9]*)?$ ]] ||
  { echo "$0: '$version' is not a release tag" >&2; exit 2; }
[[ "$toolchain" =~ ^go1[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$ ]] ||
  { echo "$0: '$toolchain' is not a Go release such as go1.27.4" >&2; exit 2; }
for platform in "$@"; do
  [[ "$platform" =~ ^(linux|darwin)-(amd64|arm64)$ ]] ||
    { echo "$0: unsupported platform '$platform'" >&2; exit 2; }
done

mkdir -p "$out"
out="$(cd "$out" && pwd)"
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Every input that reaches the binary is set here, so the caller's environment
# and its `go env -w` file cannot change the bytes. A toolchain older than the
# `go` directive of go.mod fails the build.
export GOTOOLCHAIN="$toolchain"
export GOENV=off CGO_ENABLED=0 GOFLAGS=-mod=readonly GOWORK=off GOEXPERIMENT=
export GOAMD64=v1 GOARM64=v8.0 GOFIPS140=off
unset GOOS GOARCH

actual="$(go env GOVERSION)"
[ "$actual" = "$toolchain" ] ||
  { echo "$0: toolchain is $actual, not $toolchain" >&2; exit 1; }

for platform in "$@"; do
  GOOS="${platform%-*}" GOARCH="${platform#*-}" \
    go build -trimpath -buildvcs=false \
    -ldflags="-s -w -buildid= -X github.com/confidential-dot-ai/c8s/internal/version.Version=$version" \
    -o "$out/c8s-$platform" ./cmd/c8s
done
