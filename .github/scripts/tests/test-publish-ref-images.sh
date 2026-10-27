#!/usr/bin/env bash
# Offline tests for publish-ref-images.sh: gh and curl are fakes on PATH that
# log their calls and answer from a per-test fixture.

set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "$test_dir/../../.." && pwd)
script="$repo_dir/.github/scripts/publish-ref-images.sh"
fixture_dir=$(mktemp -d)
trap 'rm -rf -- "$fixture_dir"' EXIT

tests=0
pass() {
  tests=$((tests + 1))
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

sha=c7cf2f38de3b035fbce00fe22d2451e77cdcefa0
other=3eddfb9ed4909133cfc0844ad4913b3b02d6a9fe
calls="$fixture_dir/calls"
state="$fixture_dir/state"

mkdir -p "$fixture_dir/bin" "$state"
export PATH="$fixture_dir/bin:$PATH"
export FAKE_CALLS="$calls" FAKE_STATE="$state"
export PUBLISH_REF_IMAGES_POLL_SECONDS=0 PUBLISH_REF_IMAGES_FIND_ATTEMPTS=2

# Fixture files under $state:
#   branch-sha        sha the build branch points at (absent: no branch)
#   commit-known      present when the commit exists on the remote
#   present-tags      one "<repository>:<tag>" per line that exists in ghcr
#   run-conclusion    success|failure for every watched run
#   runs              created on dispatch; consumed by `gh run list`
cat >"$fixture_dir/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'gh %s\n' "$*" >>"$FAKE_CALLS"
case "$1 $2" in
  "auth token") echo fixture-token ;;
  "api repos/"*)
    path=$2
    case "$path" in
      */git/commits/*) [ -e "$FAKE_STATE/commit-known" ] || { echo "Not Found" >&2; exit 1; } ; echo "${path##*/}" ;;
      */git/ref/heads/*) [ -e "$FAKE_STATE/branch-sha" ] || { echo "Not Found" >&2; exit 1; } ; cat "$FAKE_STATE/branch-sha" ;;
      *) echo "unexpected api path $path" >&2; exit 1 ;;
    esac ;;
  "api -X")
    # POST repos/<repo>/git/refs -f ref=... -f sha=...
    sha=""; for arg in "$@"; do case "$arg" in sha=*) sha=${arg#sha=} ;; esac; done
    printf '%s' "$sha" >"$FAKE_STATE/branch-sha"; echo "refs/heads/created" ;;
  "workflow run")
    workflow=$3
    printf '%s\n' "$workflow" >>"$FAKE_STATE/runs"
    # docker publishes every component tag for the short sha; the image
    # workflow publishes nothing this fake checks.
    if [ "$workflow" = docker.yml ]; then
      for c in c8s-operator nri-image-policy cds armtls-mesh; do echo "$c:c7cf2f3" >>"$FAKE_STATE/present-tags"; done
    fi ;;
  "run list")
    # One run per dispatched workflow, created "now".
    workflow=""; for ((i = 1; i <= $#; i++)); do [ "${!i}" = --workflow ] && { j=$((i + 1)); workflow=${!j}; }; done
    if [ -e "$FAKE_STATE/runs" ] && grep -qx "$workflow" "$FAKE_STATE/runs"; then
      n=$(grep -cx "$workflow" "$FAKE_STATE/runs")
      echo "[{\"databaseId\": 4000$n, \"createdAt\": \"2999-01-01T00:00:00Z\"}]"
    else
      echo "[]"
    fi ;;
  "run watch")
    [ "$(cat "$FAKE_STATE/run-conclusion" 2>/dev/null || echo success)" = success ] ;;
  *) echo "unexpected gh call: $*" >&2; exit 1 ;;
esac
EOF
cat >"$fixture_dir/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'curl %s\n' "$*" >>"$FAKE_CALLS"
url=${*: -1}
case "$url" in
  *"/token?"*) echo '{"token":"registry-token"}' ;;
  *"/v2/"*"/manifests/"*)
    repository=${url#*/v2/confidential-dot-ai/}; repository=${repository%%/manifests/*}
    tag=${url##*/manifests/}
    if [ -e "$FAKE_STATE/present-tags" ] && grep -qx "$repository:$tag" "$FAKE_STATE/present-tags"; then echo -n 200; else echo -n 404; fi ;;
  *) echo "unexpected curl url $url" >&2; exit 1 ;;
esac
EOF
chmod +x "$fixture_dir/bin/gh" "$fixture_dir/bin/curl"

reset() {
  rm -rf -- "$state" "$calls"
  mkdir -p "$state"
  : >"$calls"
}

expect_failure() {
  if "$@" >"$fixture_dir/unexpected.stdout" 2>"$fixture_dir/unexpected.stderr"; then
    fail "command unexpectedly succeeded: $*"
  fi
  cat "$fixture_dir/unexpected.stderr"
}

# --- argument validation ----------------------------------------------------

reset
expect_failure bash "$script" --sha c7cf2f38 | grep -q 'full 40-hex' || fail "short --sha accepted"
expect_failure bash "$script" --sha "$sha" --branch '../x' | grep -q 'safe branch' || fail "unsafe branch accepted"
expect_failure bash "$script" --sha "$sha" --confos-ref '@{bad}' | grep -q 'safe Git ref' || fail "unsafe confos ref accepted"
[ ! -s "$calls" ] || fail "argument errors reached gh or curl"
pass

# --- the commit must already be on the remote --------------------------------

reset
expect_failure bash "$script" --sha "$sha" | grep -q 'push it to a branch first' || fail "unknown commit did not fail"
grep -q 'gh api repos/confidential-dot-ai/C8s/git/commits/' "$calls" || fail "commit existence was not checked"
! grep -q 'workflow run' "$calls" || fail "a workflow was dispatched for an unknown commit"
pass

# --- a build branch at another commit is refused -----------------------------

reset
printf '%s' "$other" >"$state/branch-sha"
expect_failure bash "$script" --sha "$sha" | grep -q "exists at $other" || fail "branch at another commit was accepted"
! grep -q 'workflow run' "$calls" || fail "a workflow was dispatched despite the branch mismatch"
pass

# --- missing components: docker first, then the image, 7-character ref -------

reset
touch "$state/commit-known"
out=$(bash "$script" --sha "$sha" --dev --confos-ref af8cef0e937e4cc300ddd30c85af6ccd8cb9be91)
grep -q 'gh api -X POST repos/confidential-dot-ai/C8s/git/refs -f ref=refs/heads/build/c7cf2f3 -f sha='"$sha" "$calls" || fail "build branch was not created at the commit"
grep -q 'component tags missing at :c7cf2f3' <<<"$out" || fail "missing components not reported"
order=$(grep -o 'gh workflow run [a-z0-9.-]*' "$calls" | tr '\n' ' ')
[ "$order" = "gh workflow run docker.yml gh workflow run c8s-image-manual.yml " ] || fail "dispatch order: $order"
grep -q 'gh workflow run docker.yml --repo confidential-dot-ai/C8s --ref build/c7cf2f3$' "$calls" || fail "docker dispatch did not use the build branch"
grep -q 'gh workflow run c8s-image-manual.yml --repo confidential-dot-ai/C8s --ref build/c7cf2f3 -f c8s_ref=c7cf2f3 -f dev=true -f confos_ref=af8cef0e937e4cc300ddd30c85af6ccd8cb9be91$' "$calls" \
  || fail "image dispatch arguments differ: $(grep 'c8s-image-manual' "$calls")"
grep -q 'node-guest-base:rke2-tdx-dev-c7cf2f3$' <<<"$out" || fail "dev artifact tag not printed"
grep -q 'node-guest-base:rke2-snp-dev-cdi-c7cf2f3$' <<<"$out" || fail "dev CDI tag not printed"
pass

# --- components present: only the image build runs ---------------------------

reset
touch "$state/commit-known"
printf '%s' "$sha" >"$state/branch-sha"
for c in c8s-operator nri-image-policy cds armtls-mesh; do echo "$c:c7cf2f3" >>"$state/present-tags"; done
out=$(bash "$script" --sha "$sha")
grep -q 'branch build/c7cf2f3 already at c7cf2f3' <<<"$out" || fail "existing branch not reused"
! grep -q 'workflow run docker.yml' "$calls" || fail "docker dispatched although every tag exists"
grep -q 'gh workflow run c8s-image-manual.yml --repo confidential-dot-ai/C8s --ref build/c7cf2f3 -f c8s_ref=c7cf2f3$' "$calls" || fail "production image dispatch differs"
grep -q 'node-guest-base:rke2-tdx-c7cf2f3$' <<<"$out" || fail "production artifact tag not printed"
pass

# --- a failed run fails the script -------------------------------------------

reset
touch "$state/commit-known"
printf '%s' "$sha" >"$state/branch-sha"
for c in c8s-operator nri-image-policy cds armtls-mesh; do echo "$c:c7cf2f3" >>"$state/present-tags"; done
echo failure >"$state/run-conclusion"
expect_failure bash "$script" --sha "$sha" | grep -q 'c8s-image-manual.yml run failed' || fail "failed run not reported"
pass

# --- dry run dispatches nothing ---------------------------------------------

reset
touch "$state/commit-known"
out=$(bash "$script" --sha "$sha" --dry-run)
grep -q 'would create branch build/c7cf2f3' <<<"$out" || fail "dry run did not describe the branch"
grep -q 'would dispatch docker.yml' <<<"$out" || fail "dry run did not describe the docker dispatch"
grep -q 'would dispatch c8s-image-manual.yml on build/c7cf2f3 with: -f c8s_ref=c7cf2f3' <<<"$out" || fail "dry run did not describe the image dispatch: $out"
! grep -q 'workflow run\|api -X POST' "$calls" || fail "dry run dispatched or pushed"
pass

echo "ok: $tests publish-ref-images tests"
