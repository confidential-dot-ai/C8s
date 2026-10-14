#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
calculator="$script_dir/../calculate-release-version.sh"
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/test-release-version.XXXXXXXX")
trap 'rm -rf "$test_dir"' EXIT

# Keep git-cliff's version selection separate from the publication policy.
cat > "$test_dir/git-cliff" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$TEST_CANDIDATE"
EOF
chmod +x "$test_dir/git-cliff"
export GIT_CLIFF_BIN="$test_dir/git-cliff" RELEASE_MAJOR=0

new_case() {
  local name=$1
  mkdir "$test_dir/$name"
  cd "$test_dir/$name"
  git init -q
  git config user.name 'Release test'
  git config user.email 'release-test@example.invalid'
  printf 'baseline\n' > source
  git add source
  git -c commit.gpgsign=false commit -qm 'fix: baseline'
  git tag v0.44.5
  export TEST_CANDIDATE=v0.44.5
}

run_case() {
  export RELEASE_CHANNEL=$1 TARGET_SHA GITHUB_OUTPUT="$test_dir/output"
  TARGET_SHA=$(git rev-parse HEAD)
  : > "$GITHUB_OUTPUT"
  bash "$calculator" > "$test_dir/log"
}

expect() {
  if ! grep -Fxq "$1=$2" "$GITHUB_OUTPUT"; then
    cat "$GITHUB_OUTPUT" >&2
    echo "expected $1=$2" >&2
    exit 1
  fi
}

new_case ci_source_change
printf 'snapshot mirror fix\n' >> source
git add source
git -c commit.gpgsign=false commit -qm 'ci: fix snapshot mirror'
run_case beta
expect publish true
expect tag v0.44.5-beta.1
expect update-latest false
expect update-series false
run_case stable
expect publish false
expect tag v0.44.5

new_case identical_tree
git -c commit.gpgsign=false commit --allow-empty -qm 'chore: merge current source'
run_case beta
expect publish false

new_case existing_beta_retry
printf 'snapshot mirror fix\n' >> source
git add source
git -c commit.gpgsign=false commit -qm 'ci: fix snapshot mirror'
git tag v0.44.5-beta.1
run_case beta
expect publish true
expect tag v0.44.5-beta.1
# A later stable tag can contain the same tree. Keep the existing beta repairable.
git tag -f v0.44.5 > /dev/null
run_case beta
expect publish true
expect tag v0.44.5-beta.1

new_case fix_release
printf 'runtime fix\n' >> source
git add source
git -c commit.gpgsign=false commit -qm 'fix: runtime fix'
export TEST_CANDIDATE=v0.44.6
run_case beta
expect publish true
expect tag v0.44.6-beta.1
run_case stable
expect publish true
expect tag v0.44.6

new_case feature_release
printf 'runtime feature\n' >> source
git add source
git -c commit.gpgsign=false commit -qm 'feat: runtime feature'
export TEST_CANDIDATE=v0.45.0
git tag v0.45.0-beta.1 v0.44.5
run_case beta
expect publish true
expect tag v0.45.0-beta.2

echo 'release version publication tests passed'
