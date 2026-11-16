#!/usr/bin/env bash
# Print the manifest digest a ghcr.io tag names.
#
#   ghcr-digest.sh OWNER/REPO TAG
#
# Prints "sha256:<64 hex>". Anonymous pull token, four attempts on transient
# answers, a 404 is an error naming the tag. The same request the metal lanes
# make inline for the node and CDS images.

set -euo pipefail

die() {
  echo "ghcr-digest: $*" >&2
  exit 1
}

[[ $# -eq 2 ]] || die "usage: ghcr-digest.sh OWNER/REPO TAG"
repo=$1 tag=$2
[[ "$repo" =~ ^[a-z0-9_.-]+/[a-z0-9_.-]+$ ]] || die "not an OWNER/REPO: $repo"
[[ "$tag" =~ ^[A-Za-z0-9_.-]{1,128}$ ]] || die "not an image tag: $tag"

tok=$(curl -fsSL --retry 3 --max-time 20 "https://ghcr.io/token?scope=repository:$repo:pull" | jq -er .token) ||
  die "no pull token for $repo"
accept='application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json'
digest="" code=""
for attempt in 1 2 3 4; do
  hdr=$(curl -sI --max-time 20 -H "Authorization: Bearer $tok" -H "Accept: $accept" \
    "https://ghcr.io/v2/$repo/manifests/$tag" | tr -d '\r')
  code=$(awk 'NR==1{print $2}' <<<"$hdr")
  case "$code" in
    200) digest=$(awk 'tolower($1)=="docker-content-digest:"{print $2}' <<<"$hdr"); break ;;
    404) die "$repo:$tag is not published" ;;
    *) sleep $((attempt * 3)) ;;
  esac
done
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  die "ghcr answered ${code:-nothing} for $repo:$tag on 4 attempts"
printf '%s\n' "$digest"
