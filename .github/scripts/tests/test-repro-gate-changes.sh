#!/usr/bin/env bash

set -euo pipefail

TEST_SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly TEST_SCRIPT_DIR
ROOT=$(cd -- "$TEST_SCRIPT_DIR/../../.." && pwd)
readonly ROOT
readonly CLASSIFIER="$TEST_SCRIPT_DIR/../repro-gate-changes"

fail() {
  echo "test-repro-gate-changes: $*" >&2
  exit 1
}

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/test-repro-gate-changes.XXXXXXXX")
trap 'rm -rf "$test_dir"' EXIT
base_manifest="$test_dir/base.json"
current_manifest="$test_dir/current.json"
changed_paths="$test_dir/changed-paths"

reset_case() {
  cp "$ROOT/.github/build-pins.json" "$base_manifest"
  cp "$base_manifest" "$current_manifest"
  : >"$changed_paths"
}

set_paths() {
  : >"$changed_paths"
  local path
  for path in "$@"; do
    printf '%s\0' "$path" >>"$changed_paths"
  done
}

expect_result() {
  local want_image=$1 actual expected
  actual=$(bash "$CLASSIFIER" "$current_manifest" "$base_manifest" "$changed_paths")
  expected=$(printf 'image=%s' "$want_image")
  [ "$actual" = "$expected" ] || {
    printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
    fail "classification differs"
  }
}

reset_case
set_paths docs/development.md
expect_result false

reset_case
set_paths images/node-guest/worker/mkosi.conf
expect_result true

# Anything under mkosi.extra is baked, whatever its suffix.
reset_case
set_paths images/node-guest/worker/mkosi.extra/usr/share/doc/c8s/README.md
expect_result true

# mkosi.sync installs the worker chart's static pods.
reset_case
set_paths charts/worker/files/static-pods/kube-proxy.yaml
expect_result true

# Beside the image sources but never baked: tests, lint tools, docs.
reset_case
set_paths images/node-guest/tests/immutable-root-test.sh \
  images/node-guest/tools/containerdcheck/main.go \
  images/node-guest/README.md
expect_result false

# The pod profile stacks on the worker profile; the gate builds neither it
# nor anything it stages, its mkosi.extra included.
reset_case
set_paths images/node-guest/pod/mkosi.conf \
  images/node-guest/pod/mkosi.extra/usr/local/bin/pod-stage.sh
expect_result false

# The worker image's shared build inputs beside the profile.
reset_case
set_paths images/node-guest/build
expect_result true

reset_case
set_paths images/node-guest/kernel/c8s.config
expect_result true

reset_case
set_paths images/node-guest/worker/mkosi.sync
expect_result true

# mkosi.sync installs the router's nginx files as they are.
reset_case
set_paths charts/lib/files/router-nginx/nginx.conf
expect_result true

# Go, chart, CI and test changes outside the image tree. The legs share one
# c8s binary and core image build, so source changes cannot make them differ.
reset_case
set_paths cmd/c8s/main.go \
  charts/cloud/templates/router-deployment.yaml \
  charts/worker/templates/cluster/controlplane.yaml \
  test/workflows/workflow_test.go \
  .github/workflows/ci.yml \
  .github/scripts/fetch-release.sh \
  .github/actions/setup-crane/action.yml
expect_result false

# Publication and the classifier itself are outside the gate's build path;
# actionlint.yml runs this test for the classifier.
reset_case
set_paths .github/workflows/c8s-image-publish.yml \
  .github/scripts/repro-gate-changes \
  .github/scripts/tests/test-repro-gate-changes.sh
expect_result false

reset_case
set_paths .github/actions/setup-mkosi/action.yml
expect_result true

reset_case
set_paths .github/workflows/c8s-image.yml
expect_result true

reset_case
set_paths .github/workflows/image-repro-gate.yml
expect_result true

reset_case
set_paths .github/scripts/build-gate-images.sh
expect_result true

reset_case
jq '.builds["node-image"].confos_ref = "1111111111111111111111111111111111111111"' \
  "$base_manifest" >"$current_manifest"
set_paths .github/build-pins.json
expect_result true

# The tag beside a SHA is not a build input: correcting it rolls nothing.
reset_case
jq '.builds["node-image"].confos_tag = "v9.9.9"' \
  "$base_manifest" >"$current_manifest"
set_paths .github/build-pins.json
expect_result false

# The attestation-api digest is: the CDS image fetches those bytes.
reset_case
jq '.builds["node-image"].attestation_api_digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"' \
  "$base_manifest" >"$current_manifest"
set_paths .github/build-pins.json
expect_result true

reset_case
printf 'not-json\n' >"$current_manifest"
if bash "$CLASSIFIER" "$current_manifest" "$base_manifest" "$changed_paths" \
  >"$test_dir/unexpected.stdout" 2>"$test_dir/unexpected.stderr"; then
  fail "malformed current manifest unexpectedly passed"
fi

echo "repro gate change-classification tests passed"
