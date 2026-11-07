#!/usr/bin/env bash
# Release and importer checks for the nested pkg/launchfile module, which is
# versioned by pkg/launchfile/vX.Y.Z tags. See docs/releases.md.
#
#   launchfile-module.sh release-plan
#     Run from the release commit's checkout with full history and tags.
#     Needs TARGET_SHA, VERSION (the root release without its "v") and
#     GITHUB_OUTPUT. Writes launchfile-require (the version go.mod requires),
#     launchfile-tag (the module tag this release must create or verify, or
#     empty when the module is unchanged since its newest ancestor tag) and
#     launchfile-latest (the newest module tag once that one exists).
#
#   launchfile-module.sh downstream-build
#     Build the root as a module importing it would: without the replace, and
#     against the published module version. Passes with a notice while no
#     module tag exists and go.mod requires v0.0.0.

set -euo pipefail

readonly MODULE=github.com/confidential-dot-ai/c8s/pkg/launchfile
readonly MODULE_DIR=pkg/launchfile
readonly TAG_PREFIX=pkg/launchfile/

die() {
  echo "::error::$*" >&2
  exit 1
}

is_module_version() {
  [[ "$1" =~ ^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-beta[.][1-9][0-9]*)?$ ]]
}

required_version() {
  local version
  version="$(
    awk -v mod="$MODULE" '
      $1 == "require" && $2 == "(" { block = 1; next }
      block && $1 == ")" { block = 0; next }
      block && $1 == mod { print $2; n++ }
      !block && $1 == "require" && $2 == mod { print $3; n++ }
      END { if (n != 1) exit 1 }
    ' go.mod
  )" || die "go.mod must require $MODULE exactly once"
  is_module_version "$version" || die "go.mod requires $MODULE at non-release version $version"
  printf '%s\n' "$version"
}

tag_commit() {
  git rev-parse --verify --quiet "refs/tags/$1^{commit}"
}

module_tree() {
  git rev-parse --verify "$1:$MODULE_DIR"
}

release_plan() {
  : "${TARGET_SHA:?TARGET_SHA must be set}"
  : "${VERSION:?VERSION must be set}"
  : "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set}"
  test "$(git rev-parse HEAD)" = "$TARGET_SHA"
  is_module_version "v$VERSION" || die "release version $VERSION is not a module version"

  local require own own_sha last tag latest
  require="$(required_version)"
  own="${TAG_PREFIX}v$VERSION"
  own_sha="$(tag_commit "$own" || true)"
  last=""
  if [ -n "$(git tag --merged "$TARGET_SHA" --list "${TAG_PREFIX}v*")" ]; then
    last="$(git describe --abbrev=0 --match "${TAG_PREFIX}v*" "$TARGET_SHA")"
  fi

  if [ "$own_sha" = "$TARGET_SHA" ]; then
    tag="$own"
    echo "repairing or verifying $own for $TARGET_SHA"
  elif [ -z "$last" ] || [ "$(module_tree "$last^{commit}")" != "$(module_tree "$TARGET_SHA")" ]; then
    if [ -n "$own_sha" ]; then
      die "$MODULE_DIR changed after $own was cut at $own_sha, and the root release is still v$VERSION"
    fi
    tag="$own"
    echo "$MODULE_DIR changed since ${last:-its first tag}; this release cuts $own"
  else
    tag=""
    echo "$MODULE_DIR unchanged since $last"
  fi
  latest="${tag:-$last}"

  {
    echo "launchfile-require=$require"
    echo "launchfile-tag=$tag"
    echo "launchfile-latest=$latest"
  } >> "$GITHUB_OUTPUT"
}

downstream_build() {
  local require tags work
  require="$(required_version)"
  tags="$(
    git ls-remote --tags --refs origin "refs/tags/${TAG_PREFIX}v*" \
      | awk '{ print $2 }'
  )"

  if [ "$require" = v0.0.0 ]; then
    if [ -n "$tags" ]; then
      die "go.mod requires $MODULE v0.0.0, which importers cannot fetch; require a published ${TAG_PREFIX}v* tag"
    fi
    echo "::notice::no ${TAG_PREFIX}v* tag exists yet, so go.mod still requires v0.0.0 and the importer build is skipped; the first release cuts one (docs/releases.md)"
    return 0
  fi
  if ! grep -Fxq -- "refs/tags/$TAG_PREFIX$require" <<< "$tags"; then
    die "go.mod requires $MODULE $require, which has no $TAG_PREFIX$require tag; land the module change first and require the tag its release cuts"
  fi

  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  cp go.mod go.sum "$work/"
  go mod edit -dropreplace="$MODULE" "$work/go.mod"
  GOWORK=off GOFLAGS=-mod=mod GOOS=linux go build -modfile="$work/go.mod" ./...
  echo "root builds against $MODULE $require as an importer sees it"
}

case "${1:-}" in
  release-plan) release_plan ;;
  downstream-build) downstream_build ;;
  *) die "usage: launchfile-module.sh release-plan|downstream-build" ;;
esac
