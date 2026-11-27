#!/usr/bin/env bash
# Promote, write and publish the signed statement of a release's guest images.
#
#   release-guests.sh promote TAG DIGESTS_DIR
#   release-guests.sh statement TAG COMMIT DIGESTS_DIR OUT_DIR
#   release-guests.sh publish TAG OUT_DIR
#
# DIGESTS_DIR holds exactly the six files `confos push --digest-file` wrote in
# the release build, <image><alias suffix>.digest, each one line sha256:<64 hex>.
# promote creates each missing alias <image>:TAG<suffix> from its recorded
# digest and refuses an alias that names another. statement checks that COMMIT
# is on the channel's branch, that the release statement of TAG verifies and
# names COMMIT, that each recorded manifest is a guest artifact or KubeVirt
# image, and that each alias names it, then writes OUT_DIR/guest-statement.json.
# publish signs it keyless and uploads it with its bundle to the release, or
# verifies the pair the release already carries. Needs gh, oras, cosign and jq.
# See docs/releases.md.

set -euo pipefail
shopt -s inherit_errexit

repository=confidential-dot-ai/confidential-kubernetes
registry=ghcr.io/confidential-dot-ai/guests
issuer=https://token.actions.githubusercontent.com
guest_signer=https://github.com/confidential-dot-ai/confidential-kubernetes/.github/workflows/c8s-image-publish.yml@refs/heads/main
statement=guest-statement.json
bundle=guest-statement.sigstore.json
# One per confos push of a release build, named <image><alias suffix>.
pushes=(worker-tdx worker-tdx-kubevirt worker-sev-snp worker-sev-snp-kubevirt ta ta-kubevirt)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

die() {
  echo "release-guests: $*" >&2
  exit 1
}

usage() {
  echo "usage: promote TAG DIGESTS_DIR | statement TAG COMMIT DIGESTS_DIR OUT_DIR | publish TAG OUT_DIR" >&2
  exit 2
}

bounded() { timeout --kill-after=5s 120s "$@"; }

# worker-tdx-kubevirt is pushed to the image worker, under aliases that end in -tdx-kubevirt.
image_of() { echo "$registry/${1%%-*}"; }
suffix_of() { echo "${1#"${1%%-*}"}"; }

require_release_tag() {
  [[ "$1" =~ ^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-beta[.][1-9][0-9]*)?$ ]] ||
    die "$1 is not a stable or beta release tag"
}

# release_branch TAG: the branch whose pushes release TAG's channel.
release_branch() {
  if [[ "$1" == *-beta.* ]]; then echo beta; else echo main; fi
}

require_digest_files() {
  local dir=$1 want got
  want=$(printf '%s.digest\n' "${pushes[@]}" | sort)
  got=$(find "$dir" -mindepth 1 -printf '%P\n' | sort)
  [[ "$got" == "$want" ]] || die "$dir holds ${got//$'\n'/ }, want exactly ${want//$'\n'/ }"
}

# recorded_digest DIGESTS_DIR PUSH: the file must be exactly one line.
recorded_digest() {
  local file="$1/$2.digest" digest
  IFS= read -r digest <"$file" || true
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || ! printf '%s\n' "$digest" | cmp -s - "$file"; then
    die "$file is not one line sha256:<64 hex>"
  fi
  echo "$digest"
}

require_alias() {
  local image=$1 alias=$2 digest=$3 named
  named=$(bounded oras resolve "$image:$alias") || die "$image:$alias does not resolve; run promote first"
  [[ "$named" == "$digest" ]] || die "$image:$alias names $named, the release build pushed $digest"
}

promote() {
  local tag=$1 dir=$2 push image alias digest tags missing=()
  require_release_tag "$tag"
  require_digest_files "$dir"
  for push in "${pushes[@]}"; do
    image=$(image_of "$push")
    alias=$tag$(suffix_of "$push")
    digest=$(recorded_digest "$dir" "$push")
    tags=$(bounded oras repo tags "$image")
    if grep -Fxq -- "$alias" <<<"$tags"; then
      require_alias "$image" "$alias" "$digest"
    else
      missing+=("$push")
    fi
  done
  for push in "${missing[@]}"; do
    bounded oras tag "$(image_of "$push")@$(recorded_digest "$dir" "$push")" "$tag$(suffix_of "$push")"
  done
  for push in "${pushes[@]}"; do
    require_alias "$(image_of "$push")" "$tag$(suffix_of "$push")" "$(recorded_digest "$dir" "$push")"
    echo "$(image_of "$push"):$tag$(suffix_of "$push")"
  done
}

require_on_branch() {
  local commit=$1 branch=$2 status
  status=$(bounded gh api "repos/$repository/compare/refs/heads/$branch...$commit" --jq .status) ||
    die "GitHub cannot compare $commit with $branch"
  [[ "$status" == identical || "$status" == behind ]] || die "$commit is not on $branch ($status)"
}

require_release_statement() {
  local tag=$1 commit=$2 branch=$3 dir=$work/release
  bounded gh release download "$tag" --repo "$repository" --dir "$dir" \
    --pattern release-statement.json --pattern release-statement.sigstore.json ||
    die "release $tag has no release statement"
  bounded cosign verify-blob \
    --bundle "$dir/release-statement.sigstore.json" \
    --certificate-identity "https://github.com/$repository/.github/workflows/semver-tag.yml@refs/heads/$branch" \
    --certificate-oidc-issuer "$issuer" \
    "$dir/release-statement.json" ||
    die "the release statement of $tag is not signed by semver-tag.yml on $branch"
  jq -e --arg repository "$repository" --arg tag "$tag" --arg commit "$commit" \
    '.repository == $repository and .tag == $tag and .commit == $commit' \
    "$dir/release-statement.json" >/dev/null ||
    die "the release statement of $tag names another repository, tag or commit than $commit"
}

# fetch_manifest IMAGE DIGEST: the path of the manifest, whose bytes hash to DIGEST.
fetch_manifest() {
  local image=$1 digest=$2 file="$work/${2#sha256:}.json"
  bounded oras manifest fetch "$image@$digest" >"$file"
  [[ "sha256:$(sha256sum <"$file" | cut -d' ' -f1)" == "$digest" ]] ||
    die "the manifest of $image@$digest does not hash to its digest"
  echo "$file"
}

# guest PUSH DIGESTS_DIR: the statement entry of the guest pushed as PUSH and PUSH-kubevirt.
guest() {
  local image raw kubevirt raw_manifest kubevirt_manifest
  image=$(image_of "$1")
  raw=$(recorded_digest "$2" "$1")
  kubevirt=$(recorded_digest "$2" "$1-kubevirt")
  raw_manifest=$(fetch_manifest "$image" "$raw")
  kubevirt_manifest=$(fetch_manifest "$image" "$kubevirt")
  jq -e '.artifactType == "application/vnd.confos.image.v1" and
    ([.layers[].annotations["org.opencontainers.image.title"] | select(. == "manifest.json")] | length == 1) and
    ([.layers[].annotations["org.opencontainers.image.title"] | select(. == "disk.raw")] | length == 1)' \
    "$raw_manifest" >/dev/null ||
    die "$image@$raw is not a guest artifact with one manifest.json and one disk.raw"
  jq -e '.mediaType == "application/vnd.oci.image.manifest.v1+json" and
    .config.mediaType == "application/vnd.oci.image.config.v1+json" and (.layers | length == 1)' \
    "$kubevirt_manifest" >/dev/null ||
    die "$image@$kubevirt is not an OCI image with one layer"
  jq -c --arg raw "$image@$raw" --arg kubevirt "$image@$kubevirt" '
    def layer($title): .layers[] | select(.annotations["org.opencontainers.image.title"] == $title) | .digest;
    {raw: $raw, kubevirt: $kubevirt, manifestJson: layer("manifest.json"), diskRaw: layer("disk.raw")}' \
    "$raw_manifest"
}

write_statement() {
  local tag=$1 commit=$2 dir=$3 out=$4 branch worker_tdx worker_snp ta push
  require_release_tag "$tag"
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "$commit is not a full commit SHA"
  branch=$(release_branch "$tag")
  require_on_branch "$commit" "$branch"
  require_release_statement "$tag" "$commit" "$branch"
  require_digest_files "$dir"
  worker_tdx=$(guest worker-tdx "$dir")
  worker_snp=$(guest worker-sev-snp "$dir")
  ta=$(guest ta "$dir")
  for push in "${pushes[@]}"; do
    require_alias "$(image_of "$push")" "$tag$(suffix_of "$push")" "$(recorded_digest "$dir" "$push")"
  done
  mkdir -p "$out"
  jq -cnS \
    --arg repository "$repository" --arg tag "$tag" --arg commit "$commit" \
    --argjson tdx "$worker_tdx" --argjson snp "$worker_snp" --argjson ta "$ta" \
    '{repository: $repository, tag: $tag, commit: $commit, guests: {worker: {tdx: $tdx, "sev-snp": $snp}, ta: $ta}}' \
    >"$out/$statement"
  cat "$out/$statement"
}

verify_guest_statement() {
  bounded cosign verify-blob \
    --bundle "$1" \
    --certificate-identity "$guest_signer" \
    --certificate-oidc-issuer "$issuer" \
    "$2" ||
    die "$1 is not a signature of $2 by $guest_signer"
}

publish() {
  local tag=$1 out=$2 assets
  require_release_tag "$tag"
  jq -e --arg repository "$repository" --arg tag "$tag" '.repository == $repository and .tag == $tag' \
    "$out/$statement" >/dev/null 2>&1 ||
    die "$out/$statement is not the guest statement of $tag; run statement first"
  assets=$(bounded gh release view "$tag" --repo "$repository" --json assets --jq '.assets[].name') ||
    die "there is no release $tag"
  if grep -Fxq "$statement" <<<"$assets" && grep -Fxq "$bundle" <<<"$assets"; then
    bounded gh release download "$tag" --repo "$repository" --dir "$work/published" \
      --pattern "$statement" --pattern "$bundle"
    cmp -s "$out/$statement" "$work/published/$statement" ||
      die "the $statement on release $tag is not the one written; see Recovery in docs/releases.md"
    verify_guest_statement "$work/published/$bundle" "$out/$statement"
    echo "release $tag already carries this guest statement"
  elif grep -Fxq -e "$statement" -e "$bundle" <<<"$assets"; then
    die "release $tag carries one of $statement and $bundle; a maintainer deletes it, then re-run"
  else
    bounded cosign sign-blob --yes --bundle "$out/$bundle" "$out/$statement"
    verify_guest_statement "$out/$bundle" "$out/$statement"
    bounded gh release upload "$tag" "$out/$bundle" "$out/$statement" --repo "$repository"
    echo "signed and uploaded $statement to release $tag"
  fi
}

case "${1:-}" in
  promote) [[ $# -eq 3 ]] || usage; promote "$2" "$3" ;;
  statement) [[ $# -eq 5 ]] || usage; write_statement "$2" "$3" "$4" "$5" ;;
  publish) [[ $# -eq 3 ]] || usage; publish "$2" "$3" ;;
  *) usage ;;
esac
