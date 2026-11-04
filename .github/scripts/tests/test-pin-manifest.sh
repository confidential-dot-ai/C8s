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
new_digest=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
update_args=(--confos "$new_confos" --confos-tag v9.0.0
  --attest "$new_attest" --attest-tag v9.1.0 --attest-digest "$new_digest"
  --mkosi-sha "$new_mkosi" --mkosi-ver v28)

bash "$script" validate --manifest "$source_manifest" >/dev/null
pass

# Validate production pins above, but keep behavior tests independent of pin
# bumps. Distinct domain pins make accidental cross-domain updates observable.
source_manifest="$fixture_dir/source.json"
cat >"$source_manifest" <<'EOF'
{
  "schema_version": 3,
  "builds": {
    "node-image": {
      "confos_ref": "1111111111111111111111111111111111111111",
      "confos_tag": "v1.0.0",
      "attestation_rs_ref": "2222222222222222222222222222222222222222",
      "attestation_rs_tag": "v2.0.0",
      "attestation_api_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
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
grep -Fxq 'CONFOS_TAG=v1.0.0' <<<"$exported" ||
  fail "the export must carry the tag beside the SHA, for hygiene and pin-watch"
grep -Fxq 'ATTESTATION_API_DIGEST=sha256:4444444444444444444444444444444444444444444444444444444444444444' <<<"$exported" ||
  fail "the export must carry the attestation-api digest the CDS build fetches"
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
[[ $(jq -r '.builds["node-image"].attestation_api_digest' "$node_fixture") == \
  "$new_digest" ]] || fail "node attestation-api digest did not update"
pass

no_drift_fixture=$(new_fixture no-drift)
jq -c . "$no_drift_fixture" >"$no_drift_fixture.compact"
mv "$no_drift_fixture.compact" "$no_drift_fixture"
cp "$no_drift_fixture" "$no_drift_fixture.before"
node=$(jq -r '.builds["node-image"]' "$no_drift_fixture")
# The fixture's own pins as update flags; a flag repeated later wins, so a
# case appends only the flag it changes.
current_args=(--confos "$(jq -r .confos_ref <<<"$node")"
  --confos-tag "$(jq -r .confos_tag <<<"$node")"
  --attest "$(jq -r .attestation_rs_ref <<<"$node")"
  --attest-tag "$(jq -r .attestation_rs_tag <<<"$node")"
  --attest-digest "$(jq -r .attestation_api_digest <<<"$node")"
  --mkosi-sha "$(jq -r .mkosi_ref <<<"$node")"
  --mkosi-ver "$(jq -r .mkosi_version <<<"$node")")
result=$(bash "$script" update --manifest "$no_drift_fixture" \
  --domain node-image "${current_args[@]}")
[[ "$result" == no-drift ]] || fail "no-drift result was not reported"
cmp -s "$no_drift_fixture" "$no_drift_fixture.before" ||
  fail "no-drift update rewrote the manifest"
pass

# The same SHA under a new tag is drift: the release name is part of the pin.
retag_fixture=$(new_fixture retag)
result=$(bash "$script" update --manifest "$retag_fixture" \
  --domain node-image "${current_args[@]}" --confos-tag v1.0.1)
[[ "$result" == "updated node-image" ]] || fail "a retag was not treated as drift"
pass

# A moved attestation-api digest under the same ref is drift: the CDS image
# fetches those bytes.
redigest_fixture=$(new_fixture redigest)
result=$(bash "$script" update --manifest "$redigest_fixture" \
  --domain node-image "${current_args[@]}" --attest-digest "$new_digest")
[[ "$result" == "updated node-image" ]] || fail "a digest move was not treated as drift"
pass

invalid_target=$(new_fixture invalid-target)
cp "$invalid_target" "$invalid_target.before"
expect_failure bash "$script" update --manifest "$invalid_target" \
  --domain node-image "${update_args[@]}" --mkosi-sha not-a-sha
cmp -s "$invalid_target" "$invalid_target.before" ||
  fail "invalid target changed the manifest"
pass

# A digest is sha256:<64 hex>; a bare hex, a short hash or another algorithm
# is not one.
for bad_digest in 8d983edc sha256:8d983edc "${new_digest#sha256:}" "sha512:${new_digest#sha256:}" "${new_digest^^}"; do
  expect_failure bash "$script" update --manifest "$invalid_target" \
    --domain node-image "${update_args[@]}" --attest-digest "$bad_digest"
done
cmp -s "$invalid_target" "$invalid_target.before" ||
  fail "invalid digest changed the manifest"
pass

# A branch, a bare version or a short tag is not a release tag.
for bad_tag in main v1 v1.0 1.0.0 v1.0.0-rc1 'v1.0.0 '; do
  expect_failure bash "$script" update --manifest "$invalid_target" \
    --domain node-image "${update_args[@]}" --confos-tag "$bad_tag"
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
jq '.schema_version = 1 | del(.builds["node-image"].confos_tag, .builds["node-image"].attestation_rs_tag, .builds["node-image"].attestation_api_digest)' \
  "$old_schema" >"$old_schema.next"
mv "$old_schema.next" "$old_schema"
expect_failure bash "$script" validate --manifest "$old_schema"
jq '.schema_version = 2 | del(.builds["node-image"].attestation_api_digest)' \
  "$source_manifest" >"$old_schema"
expect_failure bash "$script" validate --manifest "$old_schema"
pass

unknown_key=$(new_fixture unknown-key)
jq '.builds["node-image"].unexpected = true' "$unknown_key" >"$unknown_key.next"
mv "$unknown_key.next" "$unknown_key"
expect_failure bash "$script" validate --manifest "$unknown_key"
pass

duplicate_key=$(new_fixture duplicate-key)
sed '1,/"schema_version": 3/s/"schema_version": 3/"schema_version": 3, "schema_version": 3/' \
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
