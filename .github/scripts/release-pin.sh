#!/usr/bin/env bash
# Resolve a GitHub release tag to the commit it names.
#
#   release-pin.sh OWNER/REPO [TAG] [--floor TAG]
#
# Without TAG, the repository's latest release (GitHub leaves drafts and
# prereleases out of it). Prints "TAG SHA"; annotated tags are dereferenced to
# their commit. With --floor, a release that is not newer than the floor tag
# prints nothing and exits 0, so a watcher never proposes a downgrade or a
# no-op. A tag that is not a release (vMAJOR.MINOR.PATCH), does not exist, or
# does not end at a commit is an error. Needs gh with a token that can read
# the repository.

set -euo pipefail

die() {
  echo "release-pin: $*" >&2
  exit 1
}

is_release_tag() {
  [[ "$1" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

# Numeric per component, so v0.10.0 is newer than v0.9.0.
newer_than() {
  local a=${1#v} b=${2#v}
  local -a x y
  IFS=. read -r -a x <<<"$a"
  IFS=. read -r -a y <<<"$b"
  local i
  for i in 0 1 2; do
    ((x[i] > y[i])) && return 0
    ((x[i] < y[i])) && return 1
  done
  return 1
}

repo=
tag=
floor=
while (($# > 0)); do
  case "$1" in
    --floor)
      (($# >= 2)) || die "--floor needs a tag"
      floor=$2
      shift 2
      ;;
    -*) die "unknown option $1" ;;
    *)
      if [[ -z "$repo" ]]; then repo=$1
      elif [[ -z "$tag" ]]; then tag=$1
      else die "usage: release-pin.sh OWNER/REPO [TAG] [--floor TAG]"
      fi
      shift
      ;;
  esac
done
[[ -n "$repo" ]] || die "usage: release-pin.sh OWNER/REPO [TAG] [--floor TAG]"
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "not an OWNER/REPO: $repo"
[[ -z "$floor" ]] || is_release_tag "$floor" || die "--floor $floor is not a release tag"

if [[ -z "$tag" ]]; then
  tag=$(gh api "repos/$repo/releases/latest" --jq .tag_name) ||
    die "$repo has no release"
fi
is_release_tag "$tag" || die "$repo: $tag is not a release tag (vMAJOR.MINOR.PATCH)"

if [[ -n "$floor" ]] && ! newer_than "$tag" "$floor"; then
  exit 0
fi

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
