#!/usr/bin/env bash
# List or rewrite the chart's third-party image digests.
#
#   chart-image-pins.sh list [VALUES_YAML]
#   chart-image-pins.sh resolve [VALUES_YAML]
#   chart-image-pins.sh set REPOSITORY:TAG sha256:HEX [VALUES_YAML]
#
# Every non-empty image digest in values.yaml is a third-party image the
# chart seeds into the allowlist floor (the attestation-api copy, pinnedDigest,
# belongs to chart-attestation-api-digest.sh). The line above each one names
# the tag it was resolved from:
#
#     # Resolve REPOSITORY:TAG to bump this digest.
#     digest: "sha256:..."
#
# list prints one "REPOSITORY TAG DIGEST" line per image, in file order, and
# fails on a digest without that line, a line not followed by its digest, or
# a line naming a repository other than the block's `repository:`. resolve
# asks the registry (crane, HEAD requests) and prints "REPOSITORY TAG DIGEST
# CURRENT", CURRENT being what the tag names today; a pinned digest or a tag
# the registry no longer serves is an error, and the other rows still print.
# set rewrites the digest under the one line naming REPOSITORY:TAG, in place,
# so the comments survive; pin-watch runs it for a rebuilt tag, and a version
# bump edits the tag on that line, then runs set with the new tag's digest.

set -euo pipefail

die() {
  echo "chart-image-pins: $*" >&2
  exit 1
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
default_values="$script_dir/../../internal/helmchart/c8s/values.yaml"

list_pins() {
  local values=$1
  [[ -f "$values" ]] || die "no such file: $values"
  awk '
    function fail(msg) {
      printf "chart-image-pins: %s:%d: %s\n", FILENAME, NR, msg > "/dev/stderr"
      bad = 1
    }
    /^[[:space:]]*repository:[[:space:]]*/ {
      repo = $2
      gsub(/["'"'"']/, "", repo)
    }
    /^[[:space:]]*# Resolve [^[:space:]]+ to bump this digest\.$/ {
      if (split($3, parts, ":") != 2 || parts[1] == "" || parts[2] == "") {
        fail("\"" $3 "\" is not REPOSITORY:TAG")
        next
      }
      pending_repo = parts[1]
      pending_tag = parts[2]
      pending = NR
      next
    }
    /^[[:space:]]*digest:[[:space:]]*"?sha256:[0-9a-f]+"?[[:space:]]*$/ {
      digest = $2
      gsub(/"/, "", digest)
      if (length(digest) != 71) {
        fail(digest " is not an OCI digest (sha256:<64 lowercase hex>)")
        next
      }
      if (pending != NR - 1) {
        fail(digest " names no tag: put \"# Resolve REPOSITORY:TAG to bump this digest.\" on the line above it")
        next
      }
      pending = 0
      if (pending_repo != repo) {
        fail("the Resolve line names " pending_repo " but the block'"'"'s repository is " repo)
        next
      }
      print pending_repo, pending_tag, digest
      next
    }
    pending && pending == NR - 1 {
      fail("the Resolve line is not followed by its digest")
      pending = 0
    }
    END { exit bad }
  ' "$values"
}

case "${1:-}" in
  list)
    [[ $# -le 2 ]] || die "usage: list [VALUES_YAML]"
    list_pins "${2:-$default_values}"
    ;;
  resolve)
    [[ $# -le 2 ]] || die "usage: resolve [VALUES_YAML]"
    rows=$(list_pins "${2:-$default_values}")
    bad=0
    while read -r repo tag digest; do
      if ! crane digest "$repo@$digest" >/dev/null; then
        echo "chart-image-pins: $repo@$digest is not in the registry" >&2
        bad=1
        continue
      fi
      if ! current=$(crane digest "$repo:$tag"); then
        echo "chart-image-pins: $repo:$tag does not resolve; the Resolve line above its digest names no published tag" >&2
        bad=1
        continue
      fi
      [[ "$current" =~ ^sha256:[0-9a-f]{64}$ ]] || die "crane digest $repo:$tag printed $current, not a digest"
      printf '%s %s %s %s\n' "$repo" "$tag" "$digest" "$current"
    done <<<"$rows"
    exit "$bad"
    ;;
  set)
    [[ $# -ge 3 && $# -le 4 ]] || die "usage: set REPOSITORY:TAG sha256:HEX [VALUES_YAML]"
    ref=$2 digest=$3 values=${4:-$default_values}
    [[ "$ref" =~ ^[a-z0-9./_-]+:[A-Za-z0-9._-]+$ ]] || die "$ref is not REPOSITORY:TAG"
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$digest is not an OCI digest (sha256:<64 lowercase hex>)"
    repo=${ref%%:*} tag=${ref#*:}
    rows=$(list_pins "$values")
    matches=$(awk -v repo="$repo" -v tag="$tag" '$1 == repo && $2 == tag' <<<"$rows" | wc -l)
    [[ "$matches" -eq 1 ]] || die "$values pins $ref $matches times, not once; a version bump edits the tag on the Resolve line first"
    ref_re=${ref//./\\.}
    line=$(grep -nE "^[[:space:]]*# Resolve ${ref_re} to bump this digest\.$" "$values" | cut -d: -f1)
    sed -i -E "$((line + 1))s|sha256:[0-9a-f]+|${digest}|" "$values"
    [[ "$(list_pins "$values" | awk -v repo="$repo" -v tag="$tag" '$1 == repo && $2 == tag {print $3}')" == "$digest" ]] ||
      die "the digest under $ref in $values was not rewritten to $digest"
    ;;
  *)
    die "usage: list [VALUES_YAML] | resolve [VALUES_YAML] | set REPOSITORY:TAG sha256:HEX [VALUES_YAML]"
    ;;
esac
