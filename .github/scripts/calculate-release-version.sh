#!/usr/bin/env bash
# Calculate the next stable C8s version and write the release decision to
# GITHUB_OUTPUT for .github/workflows/semver-tag.yml.
#
# Inputs (env):
#   GIT_CLIFF_BIN   verified git-cliff executable.
#   RELEASE_MAJOR  release line that the candidate must remain within.
#   TARGET_SHA     full commit SHA whose Docker build passed.
#   GITHUB_OUTPUT  step output file.

set -euo pipefail

: "${GIT_CLIFF_BIN:?GIT_CLIFF_BIN must be set}"
: "${RELEASE_MAJOR:?RELEASE_MAJOR must be set}"
: "${TARGET_SHA:?TARGET_SHA must be set}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set}"

test "$(git rev-parse HEAD)" = "$TARGET_SHA"
candidate="$(
  NO_COLOR=1 "$GIT_CLIFF_BIN" \
    --config .github/c8s-cliff.toml \
    --bumped-version --use-branch-tags --no-exec
)"
if [[ ! "$candidate" =~ ^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$ ]]; then
  echo "::error::calculated tag is not a stable canonical SemVer: $candidate"
  exit 1
fi

version="${candidate#v}"
if [ "${version%%.*}" != "$RELEASE_MAJOR" ]; then
  echo "::error::$candidate crosses the configured v$RELEASE_MAJOR release line"
  echo "::error::graduating to v1 requires a deliberate release-policy change"
  exit 1
fi

publish=true
if git show-ref --verify --quiet "refs/tags/$candidate"; then
  tagged_sha="$(git rev-parse "$candidate^{commit}")"
  if [ "$tagged_sha" != "$TARGET_SHA" ]; then
    publish=false
    echo "no release-worthy commit since $candidate"
  else
    echo "repairing or verifying $candidate for $TARGET_SHA"
  fi
fi

series="${version%.*}"
latest_series_tag="$(
  {
    git tag --list "v$series.*"
    printf '%s\n' "$candidate"
  } \
    | grep -E "^v${series//./[.]}[.](0|[1-9][0-9]*)$" \
    | sort -Vu \
    | tail -n 1
)"
test -n "$latest_series_tag"
update_series=false
if [ "$latest_series_tag" = "$candidate" ]; then
  update_series=true
fi

latest_release_tag="$(
  {
    git tag --list 'v*'
    printf '%s\n' "$candidate"
  } \
    | grep -E '^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$' \
    | sort -Vu \
    | tail -n 1
)"
test -n "$latest_release_tag"
update_latest=false
if [ "$latest_release_tag" = "$candidate" ]; then
  update_latest=true
fi

{
  echo "publish=$publish"
  echo "tag=$candidate"
  echo "update-latest=$update_latest"
  echo "update-series=$update_series"
  echo "version=$version"
} >> "$GITHUB_OUTPUT"
