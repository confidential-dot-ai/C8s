#!/usr/bin/env bash

set -euo pipefail

TEST_SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly TEST_SCRIPT_DIR
readonly SCRIPT="$TEST_SCRIPT_DIR/../launchfile-module.sh"

fail() {
  echo "test-launchfile-module: $*" >&2
  exit 1
}

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/test-launchfile-module.XXXXXXXX")
trap 'rm -rf "$test_dir"' EXIT
repo="$test_dir/repo"
output="$test_dir/output"

git_q() {
  git -C "$repo" -c user.name=test -c user.email=test@example.com "$@" > /dev/null
}

write_go_mod() {
  cat > "$repo/go.mod" <<EOF
module github.com/confidential-dot-ai/c8s

require (
	example.com/other v1.0.0
	github.com/confidential-dot-ai/c8s/pkg/launchfile $1
)

replace github.com/confidential-dot-ai/c8s/pkg/launchfile => ./pkg/launchfile
EOF
}

commit() {
  git_q add -A
  git_q commit -q -m "$1"
}

tag() {
  git_q tag -a -m "$1" "$1"
}

plan() {
  : > "$output"
  (
    cd "$repo"
    TARGET_SHA="$(git rev-parse HEAD)" VERSION="$1" GITHUB_OUTPUT="$output" \
      bash "$SCRIPT" release-plan > /dev/null 2>&1
  )
}

expect_plan() {
  local version=$1 expected actual
  expected=$(printf 'launchfile-require=%s\nlaunchfile-tag=%s\nlaunchfile-latest=%s' "$2" "$3" "$4")
  plan "$version" || fail "release-plan $version failed"
  actual=$(cat "$output")
  [ "$actual" = "$expected" ] || {
    printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
    fail "release-plan $version differs"
  }
}

expect_plan_fails() {
  if plan "$1"; then fail "release-plan $1 passed: $2"; fi
}

downstream() {
  (cd "$repo" && bash "$SCRIPT" downstream-build > /dev/null 2>&1)
}

git init -q "$repo"
git init -q --bare "$test_dir/origin.git"
git_q remote add origin "$test_dir/origin.git"
mkdir -p "$repo/pkg/launchfile"
echo one > "$repo/pkg/launchfile/cds.go"
write_go_mod v0.0.0
commit initial

# Bootstrap: no module tag yet.
expect_plan 0.5.0 v0.0.0 pkg/launchfile/v0.5.0 pkg/launchfile/v0.5.0
downstream || fail "bootstrap importer build should pass"

tag pkg/launchfile/v0.5.0
# A retry at the tagged commit verifies the same tag.
expect_plan 0.5.0 v0.0.0 pkg/launchfile/v0.5.0 pkg/launchfile/v0.5.0

git_q push -q origin pkg/launchfile/v0.5.0
if downstream; then fail "v0.0.0 must fail once a module tag exists"; fi

# Root-only change: the module keeps its tag.
write_go_mod v0.5.0
commit "require the module tag"
expect_plan 0.5.0 v0.5.0 "" pkg/launchfile/v0.5.0

# A module change cuts the release's own version.
echo two > "$repo/pkg/launchfile/cds.go"
commit "change the module"
expect_plan 0.6.0 v0.5.0 pkg/launchfile/v0.6.0 pkg/launchfile/v0.6.0
expect_plan_fails 0.5.0 "the module changed after its tag at the same version"

write_go_mod v0.6.0
commit "require an unpublished module version"
if downstream; then fail "an unpublished require must fail"; fi

sed -i.bak '/pkg\/launchfile v/d' "$repo/go.mod"
rm "$repo/go.mod.bak"
commit "drop the require"
expect_plan_fails 0.6.0 "go.mod must require the module"

echo "test-launchfile-module: ok"
