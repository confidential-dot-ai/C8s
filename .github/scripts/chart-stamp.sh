#!/usr/bin/env bash
# Stamp the release image digests into a packaging copy of the cloud chart, or
# check that a packaged chart carries them.
#
#   chart-stamp.sh stamp CHART_COPY DIGESTS_TSV
#   chart-stamp.sh check CHART_DIR DIGESTS_TSV
#
# DIGESTS_TSV holds one "<image repository>\t<sha256 digest>" line per image
# the release built. Each component in the chart's c8s-lib table gets its
# pinnedDigest, or the digest of the one line naming the repository its values
# name. CHART_COPY is a copy of the chart, dependencies included (cp -rL),
# outside this repository. stamp requires each image's config (crane,
# linux/amd64) to match the entrypoint and imageEnv its component declares,
# which the seeded allowlist entry pins, then writes each empty digest. check
# requires every digest in place. Needs yq v4, jq and crane.

set -euo pipefail
shopt -s inherit_errexit

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/../.." && pwd -P)
usage="usage: stamp CHART_COPY DIGESTS_TSV | check CHART_DIR DIGESTS_TSV"

die() {
  echo "chart-stamp: $*" >&2
  exit 1
}

components_file() {
  local table="$1/charts/c8s-lib/files/components.yaml"
  [[ -f "$table" ]] || die "$table is missing: vendor the chart's c8s-lib dependency (helm dependency build, or cp -rL)"
  echo "$table"
}

# repository_digest DIGESTS_TSV REPOSITORY PATH: the digest on the one line
# naming REPOSITORY.
repository_digest() {
  local digests=$1 repository=$2 path=$3 count digest
  read -r count digest < <(awk -F'\t' -v repo="$repository" '$1 == repo { n++; d = $2 } END { print n + 0, d }' "$digests")
  [[ "$count" -eq 1 ]] || die "$digests has $count lines for $path's repository $repository, want one"
  echo "$digest"
}

# release_digests CHART_DIR DIGESTS_TSV: "<valuePath>\t<repository>\t<digest>"
# per component.
release_digests() {
  local chart=$1 digests=$2 table rows path pinned repository digest
  table=$(components_file "$chart")
  rows=$(yq -r '.components[] | [.valuePath, .pinnedDigest // ""] | @tsv' "$table")
  while IFS=$'\t' read -r path pinned; do
    repository=$(yq -r ".$path.repository" "$chart/values.yaml")
    digest=$pinned
    [[ -n "$digest" ]] || digest=$(repository_digest "$digests" "$repository" "$path")
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$path's release digest $digest is not sha256:<64 hex>"
    printf '%s\t%s\t%s\n' "$path" "$repository" "$digest"
  done <<<"$rows"
}

require_packaging_copy() {
  local chart
  chart=$(cd -- "$1" && pwd -P)
  [[ "$chart/" != "$repo_dir/"* ]] || die "$1 is inside $repo_dir: stamp a copy of the chart (cp -rL)"
}

# require_image_config CHART_DIR PATH IMAGE: an argv-pinned component declares
# no entrypoint and is skipped.
require_image_config() {
  local chart=$1 path=$2 image=$3 table want cfg verdict
  table=$(components_file "$chart")
  want=$(yq -o=json -I0 ".components[] | select(.valuePath == \"$path\") | {\"entrypoint\": .entrypoint, \"imageEnv\": .imageEnv}" "$table")
  [[ "$(jq -r '.entrypoint | length' <<<"$want")" -gt 0 ]] || return 0
  cfg=$(crane config --platform linux/amd64 "$image") || die "could not read the config of $image"
  verdict=$(jq -r --argjson want "$want" -f "$script_dir/image-config-verdict.jq" <<<"$cfg")
  [[ "$verdict" == ok ]] || die "$image $verdict; align $path in components.yaml"
}

stamp_digest() {
  local values=$1 path=$2 digest=$3
  [[ -z "$(yq -r ".$path.digest" "$values")" ]] || die "$values has no empty $path.digest"
  yq -i ".$path.digest = \"$digest\"" "$values"
}

stamp_chart() {
  local chart=$1 digests=$2 expected path repository digest
  require_packaging_copy "$chart"
  expected=$(release_digests "$chart" "$digests")
  while IFS=$'\t' read -r path repository digest; do
    require_image_config "$chart" "$path" "$repository@$digest"
    stamp_digest "$chart/values.yaml" "$path" "$digest"
  done <<<"$expected"
}

check_chart() {
  local chart=$1 digests=$2 expected path repository digest got
  expected=$(release_digests "$chart" "$digests")
  while IFS=$'\t' read -r path repository digest; do
    got=$(yq -r ".$path.digest" "$chart/values.yaml")
    [[ "$got" == "$digest" ]] || die "$path.digest is $got, want $digest"
  done <<<"$expected"
}

[[ $# -eq 3 ]] || die "$usage"
case "$1" in
  stamp) stamp_chart "$2" "$3" ;;
  check) check_chart "$2" "$3" ;;
  *) die "$usage" ;;
esac
