#!/usr/bin/env bash

set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "$test_dir/../../.." && pwd)
script="$repo_dir/.github/scripts/pin-manifest.sh"
source_manifest="$repo_dir/.github/build-pins.json"
fixture_dir=$(mktemp -d)
trap 'rm -rf -- "$fixture_dir"' EXIT

tests=0
pass() {
  tests=$((tests + 1))
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

expect_failure() {
  if "$@" >"$fixture_dir/unexpected.stdout" 2>"$fixture_dir/unexpected.stderr"; then
    fail "command unexpectedly succeeded: $*"
  fi
}

new_fixture() {
  local name=$1
  local path="$fixture_dir/$name.json"
  cp -- "$source_manifest" "$path"
  printf '%s\n' "$path"
}

new_confos=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
new_attest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
new_mkosi=cccccccccccccccccccccccccccccccccccccccc
update_args=(--confos "$new_confos" --confos-tag v9.0.0
  --attest "$new_attest" --attest-tag v9.1.0
  --mkosi-sha "$new_mkosi" --mkosi-ver v28)

bash "$script" validate --manifest "$source_manifest" >/dev/null
pass

# Validate production pins above, but keep behavior tests independent of pin
# bumps. Distinct domain pins make accidental cross-domain updates observable.
source_manifest="$fixture_dir/source.json"
cat >"$source_manifest" <<'EOF'
{
  "schema_version": 2,
  "builds": {
    "node-image": {
      "confos_ref": "1111111111111111111111111111111111111111",
      "confos_tag": "v1.0.0",
      "attestation_rs_ref": "2222222222222222222222222222222222222222",
      "attestation_rs_tag": "v2.0.0",
      "mkosi_ref": "3333333333333333333333333333333333333333",
      "mkosi_version": "v27"
    }
  }
}
EOF

exported=$(bash "$script" export --manifest "$source_manifest" \
  --domain node-image --format github-env)
grep -Fxq 'MKOSI_VERSION=v27' <<<"$exported" ||
  fail "node environment export is incomplete"
grep -Eq '^CONFOS_REF=[0-9a-f]{40}$' <<<"$exported" ||
  fail "node confos export is invalid"
grep -q 'v1.0.0' <<<"$exported" &&
  fail "the export must carry the SHA the builds check out, not the tag"
pass

exported=$(bash "$script" export --manifest "$source_manifest" \
  --domain node-image --format github-output \
  --confos-override refs/heads/measurement-check)
grep -Fxq 'confos=refs/heads/measurement-check' <<<"$exported" ||
  fail "safe confos override was not exported"
expect_failure bash "$script" export --manifest "$source_manifest" \
  --domain node-image --format github-env \
  --confos-override $'main\nINJECTED=value'
pass

node_fixture=$(new_fixture node)
bash "$script" update --manifest "$node_fixture" --domain node-image \
  "${update_args[@]}" >/dev/null
[[ $(jq -r '.builds["node-image"].attestation_rs_ref' "$node_fixture") == \
  "$new_attest" ]] || fail "node attestation pin did not update"
[[ $(jq -r '.builds["node-image"].attestation_rs_tag' "$node_fixture") == \
  v9.1.0 ]] || fail "node attestation tag did not update"
pass

no_drift_fixture=$(new_fixture no-drift)
jq -c . "$no_drift_fixture" >"$no_drift_fixture.compact"
mv "$no_drift_fixture.compact" "$no_drift_fixture"
cp "$no_drift_fixture" "$no_drift_fixture.before"
node=$(jq -r '.builds["node-image"]' "$no_drift_fixture")
result=$(bash "$script" update --manifest "$no_drift_fixture" \
  --domain node-image \
  --confos "$(jq -r .confos_ref <<<"$node")" \
  --confos-tag "$(jq -r .confos_tag <<<"$node")" \
  --attest "$(jq -r .attestation_rs_ref <<<"$node")" \
  --attest-tag "$(jq -r .attestation_rs_tag <<<"$node")" \
  --mkosi-sha "$(jq -r .mkosi_ref <<<"$node")" \
  --mkosi-ver "$(jq -r .mkosi_version <<<"$node")")
[[ "$result" == no-drift ]] || fail "no-drift result was not reported"
cmp -s "$no_drift_fixture" "$no_drift_fixture.before" ||
  fail "no-drift update rewrote the manifest"
pass

# The same SHA under a new tag is drift: the release name is part of the pin.
retag_fixture=$(new_fixture retag)
result=$(bash "$script" update --manifest "$retag_fixture" \
  --domain node-image \
  --confos "$(jq -r .confos_ref <<<"$node")" --confos-tag v1.0.1 \
  --attest "$(jq -r .attestation_rs_ref <<<"$node")" \
  --attest-tag "$(jq -r .attestation_rs_tag <<<"$node")" \
  --mkosi-sha "$(jq -r .mkosi_ref <<<"$node")" \
  --mkosi-ver "$(jq -r .mkosi_version <<<"$node")")
[[ "$result" == "updated node-image" ]] || fail "a retag was not treated as drift"
pass

invalid_target=$(new_fixture invalid-target)
cp "$invalid_target" "$invalid_target.before"
expect_failure bash "$script" update --manifest "$invalid_target" \
  --domain node-image --confos "$new_confos" --confos-tag v9.0.0 \
  --attest "$new_attest" --attest-tag v9.1.0 \
  --mkosi-sha not-a-sha --mkosi-ver v28
cmp -s "$invalid_target" "$invalid_target.before" ||
  fail "invalid target changed the manifest"
pass

# A branch, a bare version or a short tag is not a release tag.
for bad_tag in main v1 v1.0 1.0.0 v1.0.0-rc1 'v1.0.0 '; do
  expect_failure bash "$script" update --manifest "$invalid_target" \
    --domain node-image --confos "$new_confos" --confos-tag "$bad_tag" \
    --attest "$new_attest" --attest-tag v9.1.0 \
    --mkosi-sha "$new_mkosi" --mkosi-ver v28
done
cmp -s "$invalid_target" "$invalid_target.before" ||
  fail "invalid tag changed the manifest"
pass

missing_tag=$(new_fixture missing-tag)
jq 'del(.builds["node-image"].confos_tag)' "$missing_tag" >"$missing_tag.next"
mv "$missing_tag.next" "$missing_tag"
expect_failure bash "$script" validate --manifest "$missing_tag"
pass

old_schema=$(new_fixture old-schema)
jq '.schema_version = 1 | del(.builds["node-image"].confos_tag, .builds["node-image"].attestation_rs_tag)' \
  "$old_schema" >"$old_schema.next"
mv "$old_schema.next" "$old_schema"
expect_failure bash "$script" validate --manifest "$old_schema"
pass

unknown_key=$(new_fixture unknown-key)
jq '.builds["node-image"].unexpected = true' "$unknown_key" >"$unknown_key.next"
mv "$unknown_key.next" "$unknown_key"
expect_failure bash "$script" validate --manifest "$unknown_key"
pass

duplicate_key=$(new_fixture duplicate-key)
sed '1,/"schema_version": 2/s/"schema_version": 2/"schema_version": 2, "schema_version": 2/' \
  "$duplicate_key" >"$duplicate_key.next"
mv "$duplicate_key.next" "$duplicate_key"
expect_failure bash "$script" validate --manifest "$duplicate_key"
pass

nested_duplicate=$(new_fixture nested-duplicate)
existing_node_confos=$(jq -r '.builds["node-image"].confos_ref' \
  "$nested_duplicate")
sed "1,/\"confos_ref\": \"$existing_node_confos\"/s/\"confos_ref\": \"$existing_node_confos\"/\"confos_ref\": \"$existing_node_confos\", \"confos_ref\": \"$existing_node_confos\"/" \
  "$nested_duplicate" >"$nested_duplicate.next"
mv "$nested_duplicate.next" "$nested_duplicate"
expect_failure bash "$script" validate --manifest "$nested_duplicate"
pass

mode_fixture=$(new_fixture mode)
chmod 640 "$mode_fixture"
bash "$script" update --manifest "$mode_fixture" --domain node-image \
  "${update_args[@]}" >/dev/null
mode=$(stat -c %a "$mode_fixture" 2>/dev/null || stat -f %Lp "$mode_fixture")
[[ "$mode" == 640 ]] || fail "manifest mode changed to $mode"
pass

echo "pin-manifest: $tests tests passed"
