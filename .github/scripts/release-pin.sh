#!/usr/bin/env bash
# Resolve a GitHub release tag to the commit it names.
#
#   release-pin.sh OWNER/REPO        the repository's latest release
#   release-pin.sh OWNER/REPO TAG    that release tag
#
# Prints "TAG SHA". Annotated tags are dereferenced to their commit. A tag
# that is not a release (vMAJOR.MINOR.PATCH), does not exist, or does not end
# at a commit is an error. Needs gh with a token that can read the repository.

set -euo pipefail

die() {
  echo "release-pin: $*" >&2
  exit 1
}

(($# == 1 || $# == 2)) || die "usage: release-pin.sh OWNER/REPO [TAG]"
repo=$1
tag=${2:-}
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "not an OWNER/REPO: $repo"

if [[ -z "$tag" ]]; then
  # /releases/latest excludes drafts and prereleases.
  tag=$(gh api "repos/$repo/releases/latest" --jq .tag_name)
fi
[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
  die "$repo: $tag is not a release tag (vMAJOR.MINOR.PATCH)"

object=$(gh api "repos/$repo/git/ref/tags/$tag" --jq '.object | "\(.type) \(.sha)"') ||
  die "$repo: tag $tag not found"
read -r type sha <<<"$object"
# An annotated tag points at a tag object; follow it to the commit.
while [[ "$type" == tag ]]; do
  read -r type sha < <(gh api "repos/$repo/git/tags/$sha" --jq '.object | "\(.type) \(.sha)"')
done
[[ "$type" == commit && "$sha" =~ ^[0-9a-f]{40}$ ]] ||
  die "$repo: tag $tag does not end at a commit ($type $sha)"
printf '%s %s\n' "$tag" "$sha"
