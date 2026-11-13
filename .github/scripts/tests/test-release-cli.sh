#!/usr/bin/env bash
# release-cli.sh against a fake go that records the environment and arguments
# of each build, so the test needs no toolchain and no minutes of compiling.

set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$test_dir/../release-cli.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

tests=0
pass() { tests=$((tests + 1)); }
fail() {
  echo "FAIL: $*" >&2
  exit 1
}
expect_failure() {
  if "$@" >"$work/unexpected.stdout" 2>"$work/unexpected.stderr"; then
    fail "command unexpectedly succeeded: $*"
  fi
}


mkdir -p "$work/bin"
cat >"$work/bin/go" <<'EOF'
#!/usr/bin/env bash
if [ "$1 $2" = "env GOVERSION" ]; then
  echo "${FAKE_GOVERSION:-$GOTOOLCHAIN}"
  exit 0
fi
[ "$1" = build ] || exit 2
{
  printf 'env %s %s cgo=%s flags=%s work=%s exp=%s amd64=%s arm64=%s toolchain=%s goenv=%s fips=%s\n' \
    "$GOOS" "$GOARCH" "$CGO_ENABLED" "$GOFLAGS" "$GOWORK" "$GOEXPERIMENT" \
    "$GOAMD64" "$GOARM64" "$GOTOOLCHAIN" "$GOENV" "$GOFIPS140"
  printf 'args %s\n' "$*"
} >> "$FAKE_GO_LOG"
while [ $# -gt 0 ]; do
  if [ "$1" = -o ]; then : > "$2"; fi
  shift
done
EOF
chmod +x "$work/bin/go"
export PATH="$work/bin:$PATH" FAKE_GO_LOG="$work/go.log"

# A caller's environment must not reach the build.
GOOS=windows GOARCH=386 GOFLAGS=-tags=c8s_node CGO_ENABLED=1 GOAMD64=v3 GOFIPS140=v1.0.0 \
  bash "$script" v1.2.3 go1.99.7 "$work/out" linux-amd64 darwin-arm64
[ -f "$work/out/c8s-linux-amd64" ] && [ -f "$work/out/c8s-darwin-arm64" ] ||
  fail "a platform binary is missing"
pass

fixed="cgo=0 flags=-mod=readonly work=off exp= amd64=v1 arm64=v8.0 toolchain=go1.99.7 goenv=off fips=off"
grep -Fxq "env linux amd64 $fixed" "$work/go.log" ||
  fail "linux-amd64 did not build with the fixed environment: $(cat "$work/go.log")"
grep -Fxq "env darwin arm64 $fixed" "$work/go.log" ||
  fail "darwin-arm64 did not build with the fixed environment"
pass

args="args build -trimpath -buildvcs=false -ldflags=-s -w -buildid= -X github.com/confidential-dot-ai/c8s/internal/version.Version=v1.2.3 -o $work/out/c8s-linux-amd64 ./cmd/c8s"
grep -Fxq -- "$args" "$work/go.log" || fail "unexpected build arguments: $(cat "$work/go.log")"
pass

bash "$script" v1.2.3-beta.4 go1.99.7 "$work/beta" linux-arm64
[ -f "$work/beta/c8s-linux-arm64" ] || fail "a beta tag did not build"
pass

FAKE_GOVERSION=go1.0.0 expect_failure bash "$script" v1.2.3 go1.99.7 "$work/out" linux-amd64
grep -q "toolchain is go1.0.0, not go1.99.7" "$work/unexpected.stderr" ||
  fail "a toolchain other than the one named was not refused"
pass

for version in 1.2.3 v1.2 dev v1.2.3-rc.1 'v1.2.3 -X a=b'; do
  expect_failure bash "$script" "$version" go1.99.7 "$work/out" linux-amd64
  grep -q 'is not a release tag' "$work/unexpected.stderr" || fail "version '$version' was not refused"
done
pass

for platform in windows-amd64 linux-riscv64 linux/amd64 ../x; do
  expect_failure bash "$script" v1.2.3 go1.99.7 "$work/out" "$platform"
  grep -q 'unsupported platform' "$work/unexpected.stderr" || fail "platform '$platform' was not refused"
done
pass

for toolchain in 1.99.7 go1.99 go2.0.0 local go1.99.7-rc1; do
  expect_failure bash "$script" v1.2.3 "$toolchain" "$work/out" linux-amd64
  grep -q "is not a Go release" "$work/unexpected.stderr" || fail "toolchain '$toolchain' was not refused"
done
pass

expect_failure bash "$script" v1.2.3 go1.99.7 "$work/out"
pass

echo "release-cli: $tests tests passed"
