#!/usr/bin/env bash
# release-guests.sh against fake oras, gh and cosign that serve the v0.110.0
# guest manifests, record every call and fail any call with other arguments.
set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$test_dir/../release-guests.sh"
fixtures="$test_dir/release-guests"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export FAKE="$work/fake"
digests="$work/digests"
out="$work/out"

tests=0
fail() { echo "FAIL: $*" >&2; exit 1; }
# run: the script succeeds and every tool call it made was expected.
run() {
  bash "$script" "$@" >"$work/stdout" 2>"$work/stderr" || fail "$* failed: $(cat "$work/stderr")"
  [[ ! -s "$FAKE/unexpected" ]] || fail "unexpected calls: $(cat "$FAKE/unexpected")"
}
expect_refusal() {
  local needle=$1
  shift
  if bash "$script" "$@" >"$work/stdout" 2>"$work/stderr"; then fail "unexpectedly succeeded: $*"; fi
  [[ ! -s "$FAKE/unexpected" ]] || fail "unexpected calls: $(cat "$FAKE/unexpected")"
  grep -qF -- "$needle" "$work/stderr" || fail "expected \"$needle\" in: $(cat "$work/stderr")"
}
calls() { grep -c "^$1" "$FAKE/calls.log" || true; }

repo=confidential-dot-ai/confidential-kubernetes
issuer=https://token.actions.githubusercontent.com
guest_signer="https://github.com/$repo/.github/workflows/c8s-image-publish.yml@refs/heads/main"
release_signer="https://github.com/$repo/.github/workflows/semver-tag.yml@refs/heads"
pushes=(worker-tdx worker-tdx-kubevirt worker-sev-snp worker-sev-snp-kubevirt ta ta-kubevirt)
tag=v0.110.0
commit=7fe79677eef399a25d779ee0caa13ecb10799037

mkdir -p "$work/bin"
cat >"$work/bin/oras" <<'EOF'
#!/usr/bin/env bash
echo "oras $*" >>"$FAKE/calls.log"
unexpected() { echo "oras $*" >>"$FAKE/unexpected"; exit 3; }
ref='ghcr[.]io/confidential-dot-ai/guests/(worker|ta)'
digest='sha256:([0-9a-f]{64})'
if [[ "$*" =~ ^"manifest fetch "$ref@$digest$ ]]; then
  cat "$FAKE/registry/${BASH_REMATCH[1]}/${BASH_REMATCH[2]}.json"
elif [[ "$*" =~ ^"resolve "$ref:([a-z0-9.-]+)$ ]]; then
  cat "$FAKE/registry/${BASH_REMATCH[1]}/tags/${BASH_REMATCH[2]}"
elif [[ "$*" =~ ^"repo tags "$ref$ ]]; then
  ls "$FAKE/registry/${BASH_REMATCH[1]}/tags"
elif [[ "$*" =~ ^"tag "$ref@$digest" "([a-z0-9.-]+)$ ]]; then
  [[ -f "$FAKE/registry/${BASH_REMATCH[1]}/${BASH_REMATCH[2]}.json" ]] || unexpected "$@"
  echo "${FAKE_TAGGED_DIGEST:-sha256:${BASH_REMATCH[2]}}" >"$FAKE/registry/${BASH_REMATCH[1]}/tags/${BASH_REMATCH[3]}"
else
  unexpected "$@"
fi
EOF
cat >"$work/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh $*" >>"$FAKE/calls.log"
unexpected() { echo "gh $*" >>"$FAKE/unexpected"; exit 3; }
repo=confidential-dot-ai/confidential-kubernetes
tag='(v[0-9a-z.-]+)'
if [[ "$*" =~ ^"api repos/$repo/compare/refs/heads/"(main|beta)"..."([0-9a-f]{40})" --jq .status"$ ]]; then
  grep -Fxq "${BASH_REMATCH[2]}" "$FAKE/branches/"* || exit 1
  if [[ -f "$FAKE/compare" ]]; then cat "$FAKE/compare"
  elif grep -Fxq "${BASH_REMATCH[2]}" "$FAKE/branches/${BASH_REMATCH[1]}"; then echo behind; else echo diverged; fi
elif [[ "$*" =~ ^"release view "$tag" --repo $repo --json assets --jq .assets[].name"$ ]]; then
  ls "$FAKE/releases/${BASH_REMATCH[1]}"
elif [[ "$*" =~ ^"release download "$tag" --repo $repo --dir "([^ ]+)" --pattern "([^ ]+)" --pattern "([^ ]+)$ ]]; then
  release="$FAKE/releases/${BASH_REMATCH[1]}"
  [[ -f "$release/${BASH_REMATCH[3]}" || -f "$release/${BASH_REMATCH[4]}" ]] || exit 1
  mkdir -p "${BASH_REMATCH[2]}"
  cp "$release/${BASH_REMATCH[3]}" "$release/${BASH_REMATCH[4]}" "${BASH_REMATCH[2]}" 2>/dev/null || true
elif [[ "$*" =~ ^"release upload "$tag" "([^ ]+)" "([^ ]+)" --repo $repo"$ ]]; then
  for asset in "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"; do
    [[ ! -e "$FAKE/releases/${BASH_REMATCH[1]}/${asset##*/}" ]] || unexpected "$@"
    cp "$asset" "$FAKE/releases/${BASH_REMATCH[1]}/"
  done
else
  unexpected "$@"
fi
EOF
# A fake bundle names its signer, issuer and the sha256 of the signed bytes.
cat >"$work/bin/cosign" <<'EOF'
#!/usr/bin/env bash
unexpected() { echo "cosign $*" >>"$FAKE/unexpected"; exit 3; }
sha() { sha256sum <"$1" | cut -d' ' -f1; }
if [[ $# -eq 8 && "$1 $2 $4 $6" == "verify-blob --bundle --certificate-identity --certificate-oidc-issuer" ]]; then
  echo "verify-blob $5 $7 ${8##*/}" >>"$FAKE/cosign.log"
  jq -e --arg identity "$5" --arg issuer "$7" --arg sha "$(sha "$8")" \
    '. == {identity: $identity, issuer: $issuer, sha256: $sha}' "$3" >/dev/null
elif [[ $# -eq 5 && "$1 $2 $3" == "sign-blob --yes --bundle" ]]; then
  echo "sign-blob ${5##*/}" >>"$FAKE/cosign.log"
  jq -cn --arg identity "$FAKE_OIDC_IDENTITY" --arg issuer "$FAKE_OIDC_ISSUER" --arg sha "$(sha "$5")" \
    '{identity: $identity, issuer: $issuer, sha256: $sha}' >"$4"
else
  unexpected "$@"
fi
EOF
chmod +x "$work/bin/"*
export PATH="$work/bin:$PATH" FAKE_OIDC_IDENTITY="$guest_signer" FAKE_OIDC_ISSUER="$issuer"

# serve FILE PUSH [DIGEST]: the registry holds FILE as DIGEST (its own by
# default) and the release build recorded DIGEST for PUSH.
serve() {
  local digest=${3:-sha256:$(sha256sum <"$1" | cut -d' ' -f1)}
  cp "$1" "$FAKE/registry/${2%%-*}/${digest#sha256:}.json"
  echo "$digest" >"$digests/$2.digest"
}
fake_bundle() {
  jq -cn --arg identity "$1" --arg issuer "$issuer" --arg sha "$(sha256sum <"$2" | cut -d' ' -f1)" \
    '{identity: $identity, issuer: $issuer, sha256: $sha}'
}
# release_statement TAG COMMIT SIGNER [REPOSITORY [RELEASE]]: release RELEASE
# (TAG by default) with a release statement.
release_statement() {
  local release="$FAKE/releases/${5:-$1}"
  mkdir -p "$release"
  jq -cnS --arg repository "${4:-$repo}" --arg tag "$1" --arg commit "$2" \
    '{repository: $repository, tag: $tag, commit: $commit, chart: "c"}' >"$release/release-statement.json"
  fake_bundle "$3" "$release/release-statement.json" >"$release/release-statement.sigstore.json"
}
# world TAG COMMIT BRANCH: the state after the release build of TAG on BRANCH.
world() {
  rm -rf "$FAKE" "$digests" "$out"
  mkdir -p "$FAKE/registry/worker/tags" "$FAKE/registry/ta/tags" "$FAKE/branches" "$digests"
  touch "$FAKE/calls.log" "$FAKE/cosign.log" "$FAKE/branches/main" "$FAKE/branches/beta"
  echo "$2" >"$FAKE/branches/$3"
  release_statement "$1" "$2" "$release_signer/$3"
  local push
  for push in "${pushes[@]}"; do serve "$fixtures/$push.json" "$push"; done
}
# with_manifest PUSH JQ: PUSH's fixture manifest edited by JQ is what the build recorded.
with_manifest() {
  jq -cj "$2" "$fixtures/$1.json" >"$work/edited.json"
  serve "$work/edited.json" "$1"
}

# First run: six aliases, the golden statement, signed and uploaded.
world "$tag" "$commit" main
run promote "$tag" "$digests"
[[ $(calls 'oras tag') -eq 6 ]] || fail "promote did not tag six aliases"
for push in "${pushes[@]}"; do
  grep -Fxq "ghcr.io/confidential-dot-ai/guests/${push%%-*}:$tag${push#"${push%%-*}"}" "$work/stdout" ||
    fail "promote did not report $push"
done
run statement "$tag" "$commit" "$digests" "$out"
cmp "$out/guest-statement.json" "$fixtures/guest-statement.json" || fail "the statement differs from the golden file"
run publish "$tag" "$out"
cmp "$FAKE/releases/$tag/guest-statement.json" "$fixtures/guest-statement.json" || fail "the statement was not uploaded"
[[ -f "$FAKE/releases/$tag/guest-statement.sigstore.json" ]] || fail "the bundle was not uploaded"
printf '%s\n' "verify-blob $release_signer/main $issuer release-statement.json" "sign-blob guest-statement.json" \
  "verify-blob $guest_signer $issuer guest-statement.json" | cmp - "$FAKE/cosign.log" || fail "stable cosign calls: $(cat "$FAKE/cosign.log")"
tests=$((tests + 1))

# Second run: nothing to create, the published pair verifies.
: >"$FAKE/calls.log"
: >"$FAKE/cosign.log"
run promote "$tag" "$digests"
[[ $(calls 'oras tag') -eq 0 ]] || fail "a second promote tagged again"
run statement "$tag" "$commit" "$digests" "$out"
run publish "$tag" "$out"
grep -q 'already carries' "$work/stdout" || fail "a second publish did not verify"
[[ $(calls 'gh release upload') -eq 0 ]] || fail "a second publish uploaded"
printf '%s\n' "verify-blob $release_signer/main $issuer release-statement.json" \
  "verify-blob $guest_signer $issuer guest-statement.json" | cmp - "$FAKE/cosign.log" || fail "second-run cosign calls: $(cat "$FAKE/cosign.log")"
tests=$((tests + 1))

# A beta: its release statement under the beta signer, the guest one under main's.
beta=v0.111.0-beta.2
beta_commit=$(printf '%040d' 7)
world "$beta" "$beta_commit" beta
run promote "$beta" "$digests"
run statement "$beta" "$beta_commit" "$digests" "$out"
jq -cS --arg tag "$beta" --arg commit "$beta_commit" '.tag = $tag | .commit = $commit' "$fixtures/guest-statement.json" |
  cmp - "$out/guest-statement.json" || fail "the beta statement differs"
run publish "$beta" "$out"
printf '%s\n' "verify-blob $release_signer/beta $issuer release-statement.json" "sign-blob guest-statement.json" \
  "verify-blob $guest_signer $issuer guest-statement.json" | cmp - "$FAKE/cosign.log" || fail "beta cosign calls: $(cat "$FAKE/cosign.log")"
grep -Fq "compare/refs/heads/beta...$beta_commit" "$FAKE/calls.log" || fail "the beta commit was not checked on beta"
tests=$((tests + 1))

# promote refuses an alias naming another digest before it creates any, and
# checks each alias it creates.
world "$tag" "$commit" main
echo "sha256:$(printf '%064d' 1)" >"$FAKE/registry/ta/tags/$tag-kubevirt"
expect_refusal "ta:$tag-kubevirt names sha256:$(printf '%064d' 1)" promote "$tag" "$digests"
[[ $(calls 'oras tag') -eq 0 ]] || fail "promote tagged before refusing"
world "$tag" "$commit" main
run promote "$tag" "$digests"
echo "sha256:$(printf '%064d' 1)" >"$FAKE/registry/ta/tags/$tag-kubevirt"
expect_refusal "ta:$tag-kubevirt names sha256:$(printf '%064d' 1)" statement "$tag" "$commit" "$digests" "$out"
world "$tag" "$commit" main
FAKE_TAGGED_DIGEST="sha256:$(printf '%064d' 2)" expect_refusal "names sha256:$(printf '%064d' 2)" promote "$tag" "$digests"
world "$tag" "$commit" main
expect_refusal "worker:$tag-tdx does not resolve; run promote first" statement "$tag" "$commit" "$digests" "$out"
tests=$((tests + 1))

# The digests: exactly six files of one sha256 line each.
for subcommand in promote statement; do
  args=("$tag" "$digests")
  [[ $subcommand == promote ]] || args=("$tag" "$commit" "$digests" "$out")
  world "$tag" "$commit" main
  rm "$digests/ta.digest"
  expect_refusal "want exactly ta-kubevirt.digest ta.digest" "$subcommand" "${args[@]}"
  world "$tag" "$commit" main
  touch "$digests/worker-tdx.log"
  expect_refusal "worker-tdx.log" "$subcommand" "${args[@]}"
  digest=$(<"$digests/ta.digest")
  hex=${digest#sha256:}
  for content in '' "$digest"$'\n'"$digest"$'\n' "sha256:${hex^^}"$'\n' "Digest: $digest"$'\n' "$digest"$'\n\n' "$digest"; do
    world "$tag" "$commit" main
    printf '%s' "$content" >"$digests/ta.digest"
    expect_refusal "ta.digest is not one line sha256:<64 hex>" "$subcommand" "${args[@]}"
  done
done
tests=$((tests + 1))

# The manifests: their bytes, the guest artifact and the KubeVirt image.
other="sha256:$(printf '%064d' 3)"
world "$tag" "$commit" main
serve "$fixtures/worker-tdx.json" worker-tdx "$other"
expect_refusal "worker@$other does not hash to its digest" statement "$tag" "$commit" "$digests" "$out"
world "$tag" "$commit" main
serve "$fixtures/ta-kubevirt.json" ta-kubevirt "$other"
expect_refusal "ta@$other does not hash to its digest" statement "$tag" "$commit" "$digests" "$out"
for edit in '.artifactType = "application/vnd.oci.image.config.v1+json"' 'del(.artifactType)' \
  'del(.layers[] | select(.annotations["org.opencontainers.image.title"] == "manifest.json"))' \
  'del(.layers[] | select(.annotations["org.opencontainers.image.title"] == "disk.raw"))' \
  '.layers += [.layers[] | select(.annotations["org.opencontainers.image.title"] == "disk.raw")]' \
  '.layers += [.layers[] | select(.annotations["org.opencontainers.image.title"] == "manifest.json")]'; do
  world "$tag" "$commit" main
  with_manifest worker-sev-snp "$edit"
  expect_refusal "is not a guest artifact with one manifest.json and one disk.raw" statement "$tag" "$commit" "$digests" "$out"
done
for edit in '.mediaType = "application/vnd.docker.distribution.manifest.v2+json"' \
  '.config.mediaType = "application/vnd.oci.empty.v1+json"' '.layers += .layers' '.layers = []'; do
  world "$tag" "$commit" main
  with_manifest worker-tdx-kubevirt "$edit"
  expect_refusal "is not an OCI image with one layer" statement "$tag" "$commit" "$digests" "$out"
done
world "$tag" "$commit" main
cp "$digests/worker-tdx.digest" "$digests/worker-tdx-kubevirt.digest"
expect_refusal "is not an OCI image with one layer" statement "$tag" "$commit" "$digests" "$out"
tests=$((tests + 1))

# The release: its branch, its release statement and its signer.
world "$tag" "$commit" beta
expect_refusal "$commit is not on main (diverged)" statement "$tag" "$commit" "$digests" "$out"
world "$beta" "$beta_commit" main
expect_refusal "$beta_commit is not on beta (diverged)" statement "$beta" "$beta_commit" "$digests" "$out"
expect_refusal "GitHub cannot compare $commit with main" statement "$tag" "$commit" "$digests" "$out"
# The branch's own head is on it. A commit ahead of it, as one on a branch cut from main is, is not.
world "$tag" "$commit" main
run promote "$tag" "$digests"
echo identical >"$FAKE/compare"
run statement "$tag" "$commit" "$digests" "$out"
echo ahead >"$FAKE/compare"
expect_refusal "$commit is not on main (ahead)" statement "$tag" "$commit" "$digests" "$out"
world "$tag" "$commit" main
rm -r "$FAKE/releases/$tag"
expect_refusal "release $tag has no release statement" statement "$tag" "$commit" "$digests" "$out"
world "$tag" "$commit" main
rm "$FAKE/releases/$tag/release-statement".*
touch "$FAKE/releases/$tag/c8s-linux-amd64"
expect_refusal "release $tag has no release statement" statement "$tag" "$commit" "$digests" "$out"
world "$beta" "$beta_commit" beta
release_statement "$beta" "$beta_commit" "$release_signer/main"
expect_refusal "not signed by semver-tag.yml on beta" statement "$beta" "$beta_commit" "$digests" "$out"
for statement in "v0.110.1 $commit $repo" "$tag $beta_commit $repo" "$tag $commit confidential-dot-ai/C8s"; do
  world "$tag" "$commit" main
  read -r other_tag other_commit other_repo <<<"$statement"
  release_statement "$other_tag" "$other_commit" "$release_signer/main" "$other_repo" "$tag"
  expect_refusal "names another repository, tag or commit" statement "$tag" "$commit" "$digests" "$out"
done
tests=$((tests + 1))

# publish: a lone asset, other bytes, a bundle by another signer, a signature
# under another identity, no release.
world "$tag" "$commit" main
run promote "$tag" "$digests"
run statement "$tag" "$commit" "$digests" "$out"
release="$FAKE/releases/$tag"
cp "$out/guest-statement.json" "$release/"
expect_refusal "carries one of guest-statement.json and guest-statement.sigstore.json" publish "$tag" "$out"
mv "$release/guest-statement.json" "$release/guest-statement.sigstore.json"
expect_refusal "carries one of" publish "$tag" "$out"
jq -c '.tag = "v0.110.1"' "$out/guest-statement.json" >"$release/guest-statement.json"
fake_bundle "$guest_signer" "$release/guest-statement.json" >"$release/guest-statement.sigstore.json"
expect_refusal "is not the one written" publish "$tag" "$out"
cp "$out/guest-statement.json" "$release/"
fake_bundle "$release_signer/main" "$release/guest-statement.json" >"$release/guest-statement.sigstore.json"
expect_refusal "is not a signature of" publish "$tag" "$out"
rm "$release/guest-statement"*
FAKE_OIDC_IDENTITY="https://github.com/$repo/.github/workflows/c8s-image-publish.yml@refs/heads/feature" \
  expect_refusal "is not a signature of" publish "$tag" "$out"
[[ ! -e "$release/guest-statement.json" ]] || fail "a statement signed under another identity was uploaded"
# publish takes only the statement of its own tag, and asks GitHub nothing before it knows.
: >"$FAKE/calls.log"
expect_refusal "is not the guest statement of v0.110.1" publish v0.110.1 "$out"
mkdir "$work/empty"
expect_refusal "is not the guest statement of $tag" publish "$tag" "$work/empty"
[[ ! -s "$FAKE/calls.log" ]] || fail "publish called out before it refused: $(cat "$FAKE/calls.log")"
mkdir "$work/unreleased"
jq -c '.tag = "v0.110.1"' "$out/guest-statement.json" >"$work/unreleased/guest-statement.json"
expect_refusal "there is no release v0.110.1" publish v0.110.1 "$work/unreleased"
tests=$((tests + 1))

# Arguments.
for bad in v0.110 0.110.0 v0.110.0-rc.1 v0.110.0-beta.0 'v0.110.0 x' v01.2.3; do
  expect_refusal "is not a stable or beta release tag" promote "$bad" "$digests"
  expect_refusal "is not a stable or beta release tag" statement "$bad" "$commit" "$digests" "$out"
  expect_refusal "is not a stable or beta release tag" publish "$bad" "$out"
done
for bad in 7fe7967 "${commit^^}" "${commit}0" main; do
  expect_refusal "is not a full commit SHA" statement "$tag" "$bad" "$digests" "$out"
done
for args in "" "sign $tag $out" "promote $tag" "statement $tag $commit $digests" "publish $tag $out x"; do
  # shellcheck disable=SC2086 # one argument per word
  if bash "$script" $args 2>"$work/stderr"; then fail "usage accepted: $args"; fi
  grep -q '^usage:' "$work/stderr" || fail "no usage for: $args"
done
tests=$((tests + 1))

echo "release-guests: $tests tests passed"
