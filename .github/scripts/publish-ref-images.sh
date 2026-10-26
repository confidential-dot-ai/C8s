#!/usr/bin/env bash
# Publish the component images and the node image for one commit, from one
# command, so a manual image build cannot pair one commit's binaries with
# another commit's image profile and cannot start before its components exist.
#
# The two failures this prevents, both seen on 2026-10-22/23:
#   - c8s-image-manual.yml dispatched on a branch whose image profile was not
#     the commit named by c8s_ref (mixed-source images that exit at boot);
#   - c8s-image-manual.yml dispatched before docker.yml had published the
#     component tags for that commit, or with an 8-character c8s_ref when the
#     published tags carry the 7-character short SHA.
#
# What it does, given the full 40-hex SHA of a commit that is already on the
# remote (pushed to any branch):
#   1. ensures a build branch points at exactly that commit (creates it, or
#      refuses if it exists at another commit);
#   2. checks the component tags the node image syncs (:<short-sha>) in ghcr;
#      if any is missing, dispatches docker.yml on the build branch and waits;
#   3. dispatches c8s-image-manual.yml on the build branch with c8s_ref set to
#      the same short SHA (plus --dev / --confos-ref when given) and waits;
#   4. prints the run URLs and the published image tags.
#
# Who may run it: anyone who can push a branch and dispatch workflows in the
# repository. Nothing here changes who holds the signing material; the
# workflows run exactly as a manual dispatch from the Actions UI would.
#
# Usage:
#   publish-ref-images.sh --sha <40-hex> [--dev] [--confos-ref <ref>]
#       [--branch <name>] [--repo <owner/name>] [--dry-run]
#
#   --dev          build the rke2-dev variant (different measurement; never ship)
#   --confos-ref   build with this confos commit instead of the pinned one
#   --branch       build branch name (default: build/<short-sha>)
#   --repo         GitHub repository (default: confidential-dot-ai/C8s)
#   --dry-run      resolve and check, print what would be dispatched, exit 0
#
# Needs: gh (authenticated), curl, jq. GH_TOKEN (or gh's own token) is used for
# the ghcr token exchange so private component packages resolve too.

set -euo pipefail

registry_host=ghcr.io
registry_namespace=confidential-dot-ai
# The repositories node-guest-image/c8s/mkosi.sync resolves at C8S_REF.
components=(c8s-operator nri-image-policy cds armtls-mesh)
image_repo=node-guest-base
docker_workflow=docker.yml
image_workflow=c8s-image-manual.yml
poll_seconds="${PUBLISH_REF_IMAGES_POLL_SECONDS:-30}"
find_run_attempts="${PUBLISH_REF_IMAGES_FIND_ATTEMPTS:-20}"

repo=confidential-dot-ai/C8s
sha=""
dev=false
confos_ref=""
branch=""
dry_run=false

die() {
  echo "publish-ref-images: $*" >&2
  exit 1
}

usage() {
  sed -n '/^# Usage:/,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --sha) sha="${2:-}"; shift 2 ;;
    --dev) dev=true; shift ;;
    --confos-ref) confos_ref="${2:-}"; shift 2 ;;
    --branch) branch="${2:-}"; shift 2 ;;
    --repo) repo="${2:-}"; shift 2 ;;
    --dry-run) dry_run=true; shift ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$sha" =~ ^[0-9a-f]{40}$ ]] \
  || die "--sha must be the full 40-hex commit SHA (component tags and c8s_ref derive their 7-character form from it)"
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "--repo must be owner/name"
if [ -n "$confos_ref" ] && [[ ! "$confos_ref" =~ ^[0-9A-Za-z][0-9A-Za-z._/-]{0,254}$ ]]; then
  die "--confos-ref is not a safe Git ref"
fi
short="${sha:0:7}"
branch="${branch:-build/$short}"
if [[ ! "$branch" =~ ^[0-9A-Za-z][0-9A-Za-z._/-]{0,254}$ ]] || [[ "$branch" == *..* ]]; then
  die "--branch is not a safe branch name"
fi

for tool in gh curl jq; do
  command -v "$tool" >/dev/null || die "$tool is required"
done

# --- build branch -----------------------------------------------------------

# commit_exists: the commit must already be on the remote; this script never
# pushes code, only names a commit that a maintainer already pushed.
commit_exists() {
  gh api "repos/$repo/git/commits/$sha" --jq .sha >/dev/null 2>&1
}

branch_sha() {
  gh api "repos/$repo/git/ref/heads/$branch" --jq .object.sha 2>/dev/null || true
}

ensure_branch() {
  local current
  current=$(branch_sha)
  if [ -n "$current" ]; then
    [ "$current" = "$sha" ] \
      || die "branch $branch exists at $current, not $sha; pick another --branch or move it deliberately"
    echo "branch $branch already at $short"
    return
  fi
  commit_exists || die "commit $sha is not on $repo; push it to a branch first"
  if [ "$dry_run" = true ]; then
    echo "would create branch $branch at $short"
    return
  fi
  gh api -X POST "repos/$repo/git/refs" -f ref="refs/heads/$branch" -f sha="$sha" --jq .ref >/dev/null
  echo "created branch $branch at $short"
}

# --- component tags ---------------------------------------------------------

registry_token() {
  local scope=$1 token auth=()
  token=$(gh auth token 2>/dev/null || true)
  if [ -n "$token" ]; then
    auth=(-u "token:$token")
  fi
  curl -fsS "${auth[@]}" "https://$registry_host/token?service=$registry_host&scope=repository:$registry_namespace/$scope:pull" \
    | jq -r '.token // empty'
}

# tag_exists <repository> <tag>: HEAD on the manifest, any media type.
tag_exists() {
  local repository=$1 tag=$2 token code
  token=$(registry_token "$repository")
  [ -n "$token" ] || die "no registry token for $registry_namespace/$repository"
  code=$(curl -s -o /dev/null -w '%{http_code}' -I \
    -H "Authorization: Bearer $token" \
    -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json' \
    "https://$registry_host/v2/$registry_namespace/$repository/manifests/$tag")
  case "$code" in
    200) return 0 ;;
    404) return 1 ;;
    *) die "registry returned HTTP $code for $repository:$tag" ;;
  esac
}

missing_components() {
  local component
  for component in "${components[@]}"; do
    tag_exists "$component" "$short" || printf '%s\n' "$component"
  done
}

# --- workflow runs ----------------------------------------------------------

# dispatch_and_wait <workflow> [-f key=value ...]: dispatches on the build
# branch, finds the run that dispatch created, waits for it, and prints its
# URL. Fails if the run fails.
dispatch_and_wait() {
  local workflow=$1; shift
  local since run_id url attempt
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  gh workflow run "$workflow" --repo "$repo" --ref "$branch" "$@"
  run_id=""
  for ((attempt = 0; attempt < find_run_attempts; attempt++)); do
    sleep "$poll_seconds"
    # shellcheck disable=SC2016 # $since is a jq variable
    run_id=$(gh run list --repo "$repo" --workflow "$workflow" --branch "$branch" --limit 5 --json databaseId,createdAt \
      | jq -r --arg since "$since" '[.[] | select(.createdAt >= $since)] | sort_by(.createdAt) | last | .databaseId // empty')
    [ -n "$run_id" ] && break
  done
  [ -n "$run_id" ] || die "no $workflow run appeared on $branch after dispatch"
  url="https://github.com/$repo/actions/runs/$run_id"
  echo "waiting for $workflow run $url"
  gh run watch "$run_id" --repo "$repo" --exit-status --interval "$poll_seconds" >/dev/null \
    || die "$workflow run failed: $url"
  echo "$workflow run succeeded: $url"
}

# --- main -------------------------------------------------------------------

ensure_branch

missing=()
while IFS= read -r component; do
  [ -n "$component" ] && missing+=("$component")
done < <(missing_components)

if [ "${#missing[@]}" -eq 0 ]; then
  echo "component tags present: ${components[*]} at :$short"
else
  echo "component tags missing at :$short: ${missing[*]}"
  if [ "$dry_run" = true ]; then
    echo "would dispatch $docker_workflow on $branch"
  else
    dispatch_and_wait "$docker_workflow"
    still_missing=$(missing_components)
    [ -z "$still_missing" ] || die "$docker_workflow finished but tags are still missing: $still_missing"
  fi
fi

image_args=(-f "c8s_ref=$short")
variant_suffix=""
if [ "$dev" = true ]; then
  image_args+=(-f dev=true)
  variant_suffix="-dev"
fi
if [ -n "$confos_ref" ]; then
  image_args+=(-f "confos_ref=$confos_ref")
fi

if [ "$dry_run" = true ]; then
  echo "would dispatch $image_workflow on $branch with: ${image_args[*]}"
else
  dispatch_and_wait "$image_workflow" "${image_args[@]}"
fi

echo "images for $short (profile and components from the same commit):"
for platform in tdx snp; do
  echo "  $registry_host/$registry_namespace/$image_repo:rke2-$platform$variant_suffix-$short"
  echo "  $registry_host/$registry_namespace/$image_repo:rke2-$platform$variant_suffix-cdi-$short"
done
