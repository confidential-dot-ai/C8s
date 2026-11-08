#!/usr/bin/env bash
# chart-attestation-api-digest.sh reads and rewrites the one pinnedDigest line
# of a components.yaml copy; the production file is read, never written.
set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "$test_dir/../../.." && pwd)
script="$repo_dir/.github/scripts/chart-attestation-api-digest.sh"
pins="$repo_dir/charts/lib/files/components.yaml"
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
tests=0

fail() { echo "FAIL: $*" >&2; exit 1; }
expect_failure() {
  if "$@" >"$fixture/unexpected.stdout" 2>"$fixture/unexpected.stderr"; then
    fail "command unexpectedly succeeded: $*"
  fi
}

# The production chart holds exactly one digest, and it is the manifest's.
got=$(bash "$script" get)
pinned=$(jq -er '.builds["node-image"].attestation_api_digest' "$repo_dir/.github/build-pins.json")
[[ "$got" == "$pinned" ]] || fail "chart pinnedDigest $got != manifest attestation_api_digest $pinned"
tests=$((tests + 1))

# set rewrites that one line and nothing else.
copy="$fixture/components.yaml"
cp "$pins" "$copy"
new=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
bash "$script" set "$new" "$copy"
[[ "$(bash "$script" get "$copy")" == "$new" ]] || fail "set did not take"
[[ "$(diff "$pins" "$copy" | grep -c '^[<>]')" -eq 2 ]] || fail "set changed more than the pinnedDigest line"
bash "$script" set "$new" "$copy"
[[ "$(bash "$script" get "$copy")" == "$new" ]] || fail "set is not idempotent"
tests=$((tests + 1))

# A malformed digest never reaches the file.
cp "$pins" "$copy"
for bad in 8d983edc sha256:8d983edc "${new#sha256:}" "sha512:${new#sha256:}" "${new^^}"; do
  expect_failure bash "$script" set "$bad" "$copy"
done
cmp -s "$pins" "$copy" || fail "a rejected digest changed the file"
tests=$((tests + 1))

# Zero or two pinnedDigest lines is an error for both verbs.
grep -v 'pinnedDigest: sha256:' "$pins" >"$copy"
expect_failure bash "$script" get "$copy"
expect_failure bash "$script" set "$new" "$copy"
{ cat "$pins"; grep 'pinnedDigest: sha256:' "$pins"; } >"$copy"
expect_failure bash "$script" get "$copy"
expect_failure bash "$script" set "$new" "$copy"
tests=$((tests + 1))

echo "chart-attestation-api-digest: $tests tests passed"
