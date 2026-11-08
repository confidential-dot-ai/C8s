#!/usr/bin/env bash
# List or rewrite the chart's third-party image digests.
#
#   chart-image-pins.sh list [FILE]
#   chart-image-pins.sh resolve [FILE]
#   chart-image-pins.sh check [FILE]
#   chart-image-pins.sh set REPOSITORY:TAG sha256:HEX [FILE]
#
# The default FILE is the chart file holding the pins: c8s-lib's
# components.yaml (the router's nginx).
#
# Every non-empty image digest in a FILE is a third-party image the chart
# seeds into the allowlist floor (the attestation-api copy, pinnedDigest,
# belongs to chart-attestation-api-digest.sh). The line above each one names
# the tag it was resolved from:
#
#     # Resolve REPOSITORY:TAG to bump this digest.
#     digest: "sha256:..."
#
# A file holding no third-party pin lists nothing and resolve and check over
# it do nothing.
#
# list prints one "REPOSITORY TAG DIGEST" line per image, in file order, and
# fails on a digest without that line, a line not followed by its digest, or
# a line naming a repository other than the block's `repository:`. resolve
# asks the registry (crane, HEAD requests) and prints "REPOSITORY TAG DIGEST
# CURRENT", CURRENT being what the tag names today; a pinned digest or a tag
# the registry no longer serves is an error, and the other rows still print.
# check reads each pinned image's config (crane, linux/amd64) and requires
# the `entrypoint` declared beside the digest to be a prefix of its
# ENTRYPOINT+CMD and the `imageEnv` to equal its Env, as `c8s install
# --resolve-digests` requires for the components it pins; a block that
# declares no entrypoint is seeded argv-pinned and is skipped. Needs yq.
# set rewrites the digest under the one line naming REPOSITORY:TAG, in place,
# so the comments survive; pin-watch runs it for a rebuilt tag, and a version
# bump edits the tag on that line, then runs set with the new tag's digest.

set -euo pipefail

die() {
  echo "chart-image-pins: $*" >&2
  exit 1
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
pins_file="$script_dir/../../internal/helmchart/lib/files/components.yaml"

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

# resolve_pins asks the registry for each pin in one file and prints
# "REPOSITORY TAG DIGEST CURRENT".
resolve_pins() {
  local values=$1 rows bad=0 repo tag digest current
  rows=$(list_pins "$values") || return 1
  [[ -n "$rows" ]] || return 0
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
  return "$bad"
}

# check_pins reads each pinned image's config and holds it to the entrypoint
# and imageEnv declared beside its digest in one file.
check_pins() {
  local values=$1 rows bad=0 repo tag digest blocks want cfg verdict
  rows=$(list_pins "$values") || return 1
  [[ -n "$rows" ]] || return 0
  while read -r repo tag digest; do
    blocks=$(yq -o=json -I0 "[.. | select(type == \"!!map\" and has(\"image\") and (.image | type == \"!!map\") and .image.digest == \"$digest\")] | map({\"entrypoint\": .entrypoint, \"imageEnv\": .imageEnv})" "$values")
    [[ "$(jq length <<<"$blocks")" -eq 1 ]] || die "$values has $(jq length <<<"$blocks") blocks pinning $digest, not one"
    want=$(jq -c '.[0]' <<<"$blocks")
    if [[ "$(jq -r '.entrypoint | length' <<<"$want")" -eq 0 ]]; then
      echo "$repo $tag argv-pinned"
      continue
    fi
    if ! cfg=$(crane config --platform linux/amd64 "$repo@$digest"); then
      echo "chart-image-pins: could not read the config of $repo@$digest" >&2
      bad=1
      continue
    fi
    verdict=$(jq -r --argjson want "$want" '
      def envmap: ((.config.Env // []) | map(split("=") | {key: .[0], value: (.[1:] | join("="))}) | from_entries);
      ((.config.Entrypoint // []) + (.config.Cmd // [])) as $argv
      | $want.entrypoint as $ep
      | ($want.imageEnv // {} | with_entries(select(.value != null) | .value |= tostring)) as $env
      | if $argv[:($ep | length)] != $ep then "starts with \($argv | tojson), not the seeded entrypoint \($ep | tojson)"
        elif envmap != $env then "sets env \(envmap | tojson), not the seeded imageEnv \($env | tojson)"
        else "ok" end' <<<"$cfg")
    if [[ "$verdict" == ok ]]; then
      echo "$repo $tag ok"
    else
      echo "chart-image-pins: $repo@$digest $verdict; align the block beside the digest" >&2
      bad=1
    fi
  done <<<"$rows"
  return "$bad"
}

case "${1:-}" in
  list)
    list_pins "${2:-$pins_file}"
    ;;
  resolve)
    resolve_pins "${2:-$pins_file}"
    ;;
  check)
    check_pins "${2:-$pins_file}"
    ;;
  set)
    [[ $# -ge 3 && $# -le 4 ]] || die "usage: set REPOSITORY:TAG sha256:HEX [FILE]"
    ref=$2 digest=$3
    [[ "$ref" =~ ^[a-z0-9./_-]+:[A-Za-z0-9._-]+$ ]] || die "$ref is not REPOSITORY:TAG"
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$digest is not an OCI digest (sha256:<64 lowercase hex>)"
    repo=${ref%%:*} tag=${ref#*:}
    values=${4:-$pins_file}
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
    die "usage: list [FILE] | resolve [FILE] | check [FILE] | set REPOSITORY:TAG sha256:HEX [FILE]"
    ;;
esac
