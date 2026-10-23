#!/usr/bin/env bash
# Calculate the next C8s version and write the release decision to
# GITHUB_OUTPUT for .github/workflows/semver-tag.yml.
#
# The stable channel (main) releases vX.Y.Z. The beta channel (the protected
# beta branch) releases vX.Y.Z-beta.N, where vX.Y.Z is the stable version the
# same commits would get and N counts the betas of that base. Beta tags never
# match the git-cliff tag_pattern, so they never move the stable baseline.
#
# Inputs (env):
#   GIT_CLIFF_BIN    verified git-cliff executable.
#   RELEASE_CHANNEL  "stable" (default) or "beta".
#   RELEASE_MAJOR    release line that the candidate must remain within.
#   TARGET_SHA       full commit SHA whose Docker build passed.
#   GITHUB_OUTPUT    step output file.

set -euo pipefail

: "${GIT_CLIFF_BIN:?GIT_CLIFF_BIN must be set}"
: "${RELEASE_MAJOR:?RELEASE_MAJOR must be set}"
: "${TARGET_SHA:?TARGET_SHA must be set}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set}"
RELEASE_CHANNEL="${RELEASE_CHANNEL:-stable}"
case "$RELEASE_CHANNEL" in
  stable|beta) ;;
  *)
    echo "::error::unknown release channel: $RELEASE_CHANNEL"
    exit 1
    ;;
esac

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

if [ "$RELEASE_CHANNEL" = beta ]; then
  # A beta needs a release-worthy commit after its stable baseline. A
  # candidate that is already a stable tag has none, even at TARGET_SHA.
  if git show-ref --verify --quiet "refs/tags/$candidate"; then
    publish=false
    echo "no release-worthy commit on beta since $candidate"
  fi
  beta_pattern="^v${version//./[.]}-beta[.]([1-9][0-9]*)$"
  mapfile -t own_betas < <(
    git tag --points-at "$TARGET_SHA" --list "v$version-beta.*" \
      | { grep -E "$beta_pattern" || true; } \
      | sort -V
  )
  if [ "${#own_betas[@]}" -gt 1 ]; then
    echo "::error::multiple beta tags name $TARGET_SHA"
    printf '%s\n' "${own_betas[@]}"
    exit 1
  fi
  if [ "${#own_betas[@]}" -eq 1 ]; then
    candidate="${own_betas[0]}"
    echo "repairing or verifying $candidate for $TARGET_SHA"
  else
    last="$(
      git tag --list "v$version-beta.*" \
        | { grep -E "$beta_pattern" || true; } \
        | sed -E 's/.*-beta[.]//' \
        | sort -n \
        | tail -n 1
    )"
    candidate="v$version-beta.$((${last:-0} + 1))"
  fi
  {
    echo "channel=beta"
    echo "publish=$publish"
    echo "tag=$candidate"
    echo "update-latest=false"
    echo "update-series=false"
    echo "version=${candidate#v}"
  } >> "$GITHUB_OUTPUT"
  exit 0
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
  echo "channel=stable"
  echo "publish=$publish"
  echo "tag=$candidate"
  echo "update-latest=$update_latest"
  echo "update-series=$update_series"
  echo "version=$version"
} >> "$GITHUB_OUTPUT"
