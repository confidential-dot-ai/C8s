#!/usr/bin/env bash
# Open the PR a pin watcher proposes, carrying the staged files as one
# GitHub-verified commit.
#
#   pin-watch-pr.sh --branch NAME --prefix PREFIX --title TITLE --body TEXT [--allow PATH]...
#
# The caller stages the files the PR carries (git add); nothing else in the
# tree may have changed. One open PR per PREFIX: when a non-fork branch
# starting with PREFIX already has one, this returns 0 and leaves that review
# branch alone. NAME is created at HEAD, or reset there when a PR closed
# without merging left it behind differing from HEAD only in --allow paths
# (default: the staged paths); any other difference is someone's work and
# refuses. The staged files are committed with createCommitOnBranch, so
# GitHub signs the commit with the token's identity; a commit GitHub does not
# report verified is refused before the PR opens.
#
# Needs GH_TOKEN and GITHUB_REPOSITORY; appends to GITHUB_STEP_SUMMARY when set.

set -euo pipefail

die() {
  echo "pin-watch-pr: $*" >&2
  exit 1
}
note() {
  echo "$*"
  [ -z "${GITHUB_STEP_SUMMARY:-}" ] || echo "$*" >>"$GITHUB_STEP_SUMMARY"
}

branch="" prefix="" title="" body="" allow=()
while [ $# -gt 0 ]; do
  case "$1" in
    --branch) branch=$2 ;;
    --prefix) prefix=$2 ;;
    --title) title=$2 ;;
    --body) body=$2 ;;
    --allow) allow+=("$2") ;;
    *) die "unknown argument: $1" ;;
  esac
  [ $# -ge 2 ] || die "$1 needs a value"
  shift 2
done
[ -n "$branch" ] && [ -n "$prefix" ] && [ -n "$title" ] && [ -n "$body" ] ||
  die "usage: pin-watch-pr.sh --branch NAME --prefix PREFIX --title TITLE --body TEXT [--allow PATH]..."
[ -n "${GH_TOKEN:-}" ] || die "GH_TOKEN is not set"
[ -n "${GITHUB_REPOSITORY:-}" ] || die "GITHUB_REPOSITORY is not set"

mapfile -t files < <(git diff --cached --name-only)
[ "${#files[@]}" -gt 0 ] || die "nothing is staged"
if git status --porcelain --untracked-files=all | grep -qv '^M  '; then
  echo "::error::pin updater changed an unexpected path"
  git status --porcelain --untracked-files=all
  exit 1
fi
[ "${#allow[@]}" -gt 0 ] || allow=("${files[@]}")
allow_args=()
for path in "${allow[@]}"; do allow_args+=(-e "$path"); done

open_pr=$(
  gh pr list --state open --limit 100 \
    --json headRefName,isCrossRepository,number |
    jq -r --arg prefix "$prefix" \
      '[.[] | select(.isCrossRepository == false and (.headRefName | startswith($prefix)))][0].number // empty'
)
if [ -n "$open_pr" ]; then
  note "pin-watch PR #$open_pr is already open; leaving its review branch untouched"
  exit 0
fi

desired_tree=$(git write-tree)
base_oid=$(git rev-parse HEAD)
base_tree=$(git rev-parse 'HEAD^{tree}')

remote_oid=""
remote_tree=""
if remote_ref=$(git ls-remote --exit-code --heads origin "refs/heads/$branch"); then
  remote_oid=${remote_ref%%[[:space:]]*}
  git fetch --no-tags origin "+refs/heads/$branch:refs/remotes/origin/$branch"
  remote_tree=$(git rev-parse "${remote_oid}^{tree}")
else
  remote_status=$?
  [ "$remote_status" -eq 2 ] || exit "$remote_status"
  gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" \
    -f ref="refs/heads/$branch" -f sha="$base_oid" >/dev/null
  remote_oid=$base_oid
  remote_tree=$base_tree
fi

if [ "$remote_tree" = "$desired_tree" ]; then
  new_oid=$remote_oid
else
  if [ "$remote_tree" != "$base_tree" ]; then
    if git diff-tree -r --name-only "$base_tree" "$remote_tree" | grep -qvxF "${allow_args[@]}"; then
      echo "::error::candidate branch $branch carries changes beyond ${allow[*]}; refusing to overwrite it (delete the branch to let pin-watch recreate it)"
      exit 1
    fi
    note "resetting stale pin-watch branch $branch to $base_oid"
    gh api --method PATCH "repos/${GITHUB_REPOSITORY}/git/refs/heads/$branch" \
      -f sha="$base_oid" -F force=true >/dev/null
    remote_oid=$base_oid
  fi
  mutation=$(cat <<'GRAPHQL'
mutation($repository: String!, $branch: String!, $expected: GitObjectID!, $headline: String!, $additions: [FileAddition!]!) {
  createCommitOnBranch(input: {
    branch: {repositoryNameWithOwner: $repository, branchName: $branch}
    expectedHeadOid: $expected
    message: {headline: $headline}
    fileChanges: {additions: $additions}
  }) {
    commit { oid }
  }
}
GRAPHQL
  )
  additions=$(for f in "${files[@]}"; do
    jq -n --arg path "$f" --arg contents "$(base64 <"$f" | tr -d '\n')" '{path: $path, contents: $contents}'
  done | jq -s .)
  commit_json=$(jq -n \
    --arg query "$mutation" \
    --arg repository "$GITHUB_REPOSITORY" \
    --arg branch "$branch" \
    --arg expected "$remote_oid" \
    --arg headline "$title" \
    --argjson additions "$additions" \
    '{query: $query, variables: {repository: $repository, branch: $branch, expected: $expected, headline: $headline, additions: $additions}}' |
    gh api graphql --input -)
  new_oid=$(jq -er '.data.createCommitOnBranch.commit.oid' <<<"$commit_json")
fi

verified=$(gh api "repos/${GITHUB_REPOSITORY}/commits/${new_oid}" \
  --jq '.commit.verification.verified')
if [ "$verified" != true ]; then
  echo "::error::GitHub did not verify pin-watch commit $new_oid; refusing to open the PR"
  exit 1
fi
gh pr create --head "$branch" --title "$title" --body "$body"
