#!/usr/bin/env bash
# pin-watch-pr.sh against a bare origin and a fake gh that logs what it is
# asked: a fresh branch, an open PR, a dirty tree, a stale branch with and
# without foreign changes, an unchanged branch, an unverified commit.

set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$test_dir/../pin-watch-pr.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

tests=0
pass() { tests=$((tests + 1)); }
fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# gh: every call is one line of gh.log; graphql input lands in graphql.json.
mkdir -p "$work/bin"
cat >"$work/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$GH_LOG"
case "$1 $2" in
  "pr list") echo "${GH_OPEN_PRS:-[]}" ;;
  "api graphql") cat >"$GH_GRAPHQL"; echo '{"data":{"createCommitOnBranch":{"commit":{"oid":"c0ffee"}}}}' ;;
  "api --method") echo '{}' ;;
  "api repos"*) echo "${GH_VERIFIED:-true}" ;;
  "pr create") echo "https://example.invalid/pull/1" ;;
  *) echo "unexpected gh call: $*" >&2; exit 1 ;;
esac
EOF
chmod +x "$work/bin/gh"
export PATH="$work/bin:$PATH"
export GH_TOKEN=t0k GITHUB_REPOSITORY=acme/widget
export GH_LOG="$work/gh.log" GH_GRAPHQL="$work/graphql.json" GITHUB_STEP_SUMMARY="$work/summary"

git init -q --bare "$work/origin"
git clone -q "$work/origin" "$work/repo" 2>/dev/null
cd "$work/repo"
git config user.email test@example.invalid
git config user.name test
git config commit.gpgsign false
printf '{"pin": 1}\n' >pins.json
printf 'a\n' >other.txt
git add pins.json other.txt
git commit -qm base
git push -q origin HEAD:main
base_oid=$(git rev-parse HEAD)

reset() {
  git reset -q --hard
  git clean -qfd
  : >"$GH_LOG"
  : >"$GITHUB_STEP_SUMMARY"
  rm -f "$GH_GRAPHQL"
  git push -q origin --delete "$1" 2>/dev/null || true
}
stage_bump() {
  printf '{"pin": 2}\n' >pins.json
  git add pins.json
}
run() {
  bash "$script" --branch "$1" --prefix pin-watch/ --title "bump" --body "the body" "${@:2}"
}

# A fresh branch: created at HEAD, the staged file committed, the PR opened.
reset pin-watch/one
stage_bump
run pin-watch/one >/dev/null
grep -qF "api --method POST repos/acme/widget/git/refs -f ref=refs/heads/pin-watch/one -f sha=$base_oid" "$GH_LOG" ||
  fail "the branch was not created at HEAD"
[[ $(jq -r '.variables.additions | length' "$GH_GRAPHQL") == 1 ]] || fail "one staged file, one addition"
[[ $(jq -r '.variables.additions[0].path' "$GH_GRAPHQL") == pins.json ]] || fail "the addition is not the staged file"
[[ $(jq -r '.variables.additions[0].contents' "$GH_GRAPHQL" | base64 -d) == '{"pin": 2}' ]] ||
  fail "the addition does not carry the staged contents"
[[ $(jq -r '.variables.expected' "$GH_GRAPHQL") == "$base_oid" ]] || fail "the commit does not expect the new branch's head"
grep -qF "pr create --head pin-watch/one --title bump --body the body" "$GH_LOG" || fail "the PR was not opened"
pass

# An open PR under the prefix stops the run before anything is written.
reset pin-watch/two
stage_bump
GH_OPEN_PRS='[{"headRefName":"pin-watch/old","isCrossRepository":false,"number":7}]' run pin-watch/two >/dev/null
grep -q '#7 is already open' "$GITHUB_STEP_SUMMARY" || fail "the open PR was not reported"
! grep -q 'api' "$GH_LOG" || fail "an open PR still led to API writes"
# A fork's branch under the prefix is not ours.
GH_OPEN_PRS='[{"headRefName":"pin-watch/old","isCrossRepository":true,"number":8}]' run pin-watch/two >/dev/null
grep -q 'pr create' "$GH_LOG" || fail "a fork PR under the prefix blocked the run"
pass

# Nothing staged, or anything beyond staged modifications, refuses.
reset pin-watch/three
if run pin-watch/three >"$work/err" 2>&1; then fail "an empty index was accepted"; fi
grep -q 'nothing is staged' "$work/err" || fail "an empty index was not named"
stage_bump
printf 'stray\n' >stray.txt
if run pin-watch/three >"$work/err" 2>&1; then fail "an untracked file was accepted"; fi
grep -q 'unexpected path' "$work/err" || fail "the untracked file was not named"
rm stray.txt
printf 'b\n' >other.txt
if run pin-watch/three >"$work/err" 2>&1; then fail "an unstaged change was accepted"; fi
pass

# A stale branch differing from HEAD only in allowed paths is reset and reused.
reset pin-watch/four
git checkout -q -b stale
printf '{"pin": 9}\n' >pins.json
git commit -qam stale
git push -q origin stale:pin-watch/four
git checkout -q main
git branch -qD stale
stage_bump
run pin-watch/four >/dev/null
grep -qF "api --method PATCH repos/acme/widget/git/refs/heads/pin-watch/four -f sha=$base_oid -F force=true" "$GH_LOG" ||
  fail "the stale branch was not reset"
[[ $(jq -r '.variables.expected' "$GH_GRAPHQL") == "$base_oid" ]] || fail "the commit does not expect the reset head"
pass

# A stale branch carrying someone else's change is refused, by default and
# when --allow names only the staged path.
reset pin-watch/five
git checkout -q -b foreign
printf 'c\n' >other.txt
git commit -qam foreign
git push -q origin foreign:pin-watch/five
git checkout -q main
git branch -qD foreign
stage_bump
if run pin-watch/five >"$work/err" 2>&1; then fail "a branch with foreign changes was overwritten"; fi
grep -q 'changes beyond pins.json' "$work/err" || fail "the foreign change was not named"
! grep -q 'PATCH' "$GH_LOG" || fail "the foreign branch was reset"
# Allowing that path makes it a stale branch again.
: >"$GH_LOG"
run pin-watch/five --allow pins.json --allow other.txt >/dev/null
grep -q 'PATCH' "$GH_LOG" || fail "an allowed foreign path still refused"
pass

# A branch already at the desired tree gets no new commit, only the PR.
reset pin-watch/six
git checkout -q -b same
printf '{"pin": 2}\n' >pins.json
git commit -qam same
same_oid=$(git rev-parse HEAD)
git push -q origin same:pin-watch/six
git checkout -q main
git branch -qD same
stage_bump
run pin-watch/six >/dev/null
[[ ! -e "$GH_GRAPHQL" ]] || fail "an unchanged branch was committed to again"
grep -qF "api repos/acme/widget/commits/$same_oid" "$GH_LOG" || fail "the existing head was not verified"
grep -q 'pr create' "$GH_LOG" || fail "the PR was not opened on the unchanged branch"
pass

# A commit GitHub does not verify never becomes a PR.
reset pin-watch/seven
stage_bump
if GH_VERIFIED=false run pin-watch/seven >"$work/err" 2>&1; then fail "an unverified commit opened a PR"; fi
grep -q 'did not verify' "$work/err" || fail "the unverified commit was not named"
! grep -q 'pr create' "$GH_LOG" || fail "the PR was opened on an unverified commit"
pass

# Missing arguments and credentials are named.
reset pin-watch/eight
stage_bump
if bash "$script" --branch x --prefix p --title t >"$work/err" 2>&1; then fail "a missing --body was accepted"; fi
grep -q 'usage' "$work/err" || fail "the usage was not shown"
if GH_TOKEN='' run pin-watch/eight >"$work/err" 2>&1; then fail "a missing token was accepted"; fi
grep -q 'GH_TOKEN' "$work/err" || fail "the missing token was not named"
pass

echo "pin-watch-pr: $tests tests passed"
