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
export FAKE_REAL_JQ
FAKE_REAL_JQ=$(command -v jq)
export PATH="$fixture_dir/bin:$PATH"
export FAKE_CALLS="$calls" FAKE_STATE="$state"
export PUBLISH_REF_IMAGES_POLL_SECONDS=0

# Fixture files under $state:
#   branch-sha        sha the build branch points at (absent: no branch)
#   commit-known      present when the commit exists on the remote
#   present-tags      one "<repository>:<tag>" per line that exists in ghcr
#   image-publishes-nothing   the image workflow succeeds without publishing
#   listing-fails     the registry refuses to list a repository's tags
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
      */git/commits/*) [ -e "$FAKE_STATE/commit-known" ] || { echo "{\"message\":\"Not Found\",\"status\":\"404\"}"; exit 1; } ; echo "${path##*/}" ;;
      */git/ref/heads/*) [ -e "$FAKE_STATE/branch-sha" ] || { echo "{\"message\":\"Not Found\",\"status\":\"404\"}"; exit 1; } ; cat "$FAKE_STATE/branch-sha" ;;
      */contents/.github/workflows/c8s-image-manual.yml\?ref=*)
        [ -e "$FAKE_STATE/old-workflow" ] || printf 'expected_sha:\nneeds: verify-source\n' ;;
      */actions/runs/40001/attempts/1)
        sha=$(cat "$FAKE_STATE/dispatched-sha")
        [ ! -e "$FAKE_STATE/wrong-run-sha" ] || sha=3eddfb9ed4909133cfc0844ad4913b3b02d6a9fe
        status=completed
        if [ -e "$FAKE_STATE/attempt-pending" ]; then status=in_progress; rm "$FAKE_STATE/attempt-pending"; fi
        conclusion=$(cat "$FAKE_STATE/run-conclusion" 2>/dev/null || echo success)
        if [ -e "$FAKE_STATE/move-branch" ]; then
          echo 3eddfb9ed4909133cfc0844ad4913b3b02d6a9fe >"$FAKE_STATE/branch-sha"
        fi
        jq -nc --arg sha "$sha" --arg status "$status" --arg conclusion "$conclusion" '{head_sha:$sha,status:$status,conclusion:$conclusion,run_attempt:1}' ;;
      */actions/runs/40001) echo 'must not follow a mutable latest attempt' >&2; exit 1 ;;
      *) echo "unexpected api path $path" >&2; exit 1 ;;
    esac ;;
  "api -X")
    if [[ "$4" != */dispatches ]]; then
      sha=""; for arg in "$@"; do case "$arg" in sha=*) sha=${arg#sha=} ;; esac; done
      printf '%s' "$sha" >"$FAKE_STATE/branch-sha"; echo "refs/heads/created"
      exit 0
    fi
    workflow=${4%/dispatches}; workflow=${workflow##*/}
    cp "$FAKE_STATE/branch-sha" "$FAKE_STATE/dispatched-sha"
    printf '%s\n' "$workflow" >>"$FAKE_STATE/runs"
    # docker publishes every component tag for the short sha; the image
    # workflow publishes both formats of both platforms, unless the fixture
    # says it published nothing.
    if [ "$workflow" = docker.yml ]; then
      for c in c8s-operator nri-image-policy ta armtls-mesh volumed; do echo "$c:c7cf2f3" >>"$FAKE_STATE/present-tags"; done
    fi
    if [ "$workflow" = c8s-image-manual.yml ] && [ ! -e "$FAKE_STATE/image-publishes-nothing" ]; then
      for tee in tdx sev-snp; do
        echo "guests/worker:sha-c7cf2f3-$tee" >>"$FAKE_STATE/present-tags"
        echo "guests/worker:sha-c7cf2f3-$tee-kubevirt" >>"$FAKE_STATE/present-tags"
      done
      for tag in sha-c7cf2f3 sha-c7cf2f3-kubevirt; do
        [ "$tag" = "$(cat "$FAKE_STATE/missing-ta" 2>/dev/null || true)" ] || echo "guests/ta:$tag" >>"$FAKE_STATE/present-tags"
      done
    fi
    if [ -e "$FAKE_STATE/missing-run-id" ]; then echo null; else echo 40001; fi ;;
  "run list") echo 'must not guess a dispatched run from a list' >&2; exit 1 ;;
  "run view")
    [ "$3" = 40001 ] || exit 1
    [[ " $* " == *" --attempt 1 --log "* ]] || { echo 'logs must name the successful attempt' >&2; exit 1; }
    for tee in tdx sev-snp; do
      for suffix in "" -kubevirt; do echo "guests/worker:sha-c7cf2f3-$tee$suffix"; done
    done >"$FAKE_STATE/log-tags"
    printf '%s\n' guests/ta:sha-c7cf2f3 guests/ta:sha-c7cf2f3-kubevirt >>"$FAKE_STATE/log-tags"
    while read -r ref; do
      printf 'job\tstep\t2026-01-01T00:00:00Z Pushed [registry] ghcr.io/confidential-dot-ai/%s\n' "$ref"
      printf 'job\tstep\t2026-01-01T00:00:00Z Digest: sha256:%064d\n' 1
    done <"$FAKE_STATE/log-tags"
    if [ -e "$FAKE_STATE/conflicting-log" ]; then
      printf 'job\tstep\t2026-01-01T00:00:00Z Pushed [registry] ghcr.io/confidential-dot-ai/guests/worker:sha-c7cf2f3-tdx\n'
      printf 'job\tstep\t2026-01-01T00:00:00Z Digest: sha256:%064d\n' 2
    fi ;;
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
    [ ! -e "$FAKE_STATE/manifest-fails" ] || { echo -n 503; exit 0; }
    repository=${url#*/v2/confidential-dot-ai/}; repository=${repository%%/manifests/*}
    tag=${url##*/manifests/}
    if [[ " $* " == *" -fsSI "* ]]; then
      value=1; [ ! -e "$FAKE_STATE/moved-tag" ] || value=2
      printf 'Docker-Content-Digest: sha256:%064d\r\n' "$value"
      exit 0
    fi
    if [ -e "$FAKE_STATE/present-tags" ] && grep -qx "$repository:$tag" "$FAKE_STATE/present-tags"; then echo -n 200; else echo -n 404; fi ;;
  *"/v2/"*"/tags/list"*)
    [ ! -e "$FAKE_STATE/listing-fails" ] || exit 22
    repository=${url#*/v2/confidential-dot-ai/}; repository=${repository%%/tags/list*}
    tags=$( (grep "^$repository:" "$FAKE_STATE/present-tags" 2>/dev/null || true) | sed "s|^$repository:||" )
    jq -nc --arg tags "$tags" '{tags: ($tags | split("\n") | map(select(length > 0)))}' ;;
  *) echo "unexpected curl url $url" >&2; exit 1 ;;
esac
EOF
cat >"$fixture_dir/bin/jq" <<'EOF'
#!/usr/bin/env bash
if [ -e "$FAKE_STATE/receipt-fails" ] && [[ " $* " == *" --argjson images "* ]]; then
  printf '{'
  exit 1
fi
if [ -e "$FAKE_STATE/receipt-directory" ] && [[ " $* " == *" --argjson images "* ]]; then
  mkdir "$(cat "$FAKE_STATE/receipt-directory")"
fi
exec "$FAKE_REAL_JQ" "$@"
EOF
chmod +x "$fixture_dir/bin/gh" "$fixture_dir/bin/curl" "$fixture_dir/bin/jq"

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
touch "$fixture_dir/existing-receipt"
expect_failure bash "$script" --sha "$sha" --receipt "$fixture_dir/existing-receipt" | grep -q 'receipt already exists' || fail "existing receipt accepted"
ln -s "$fixture_dir/absent" "$fixture_dir/symlink-receipt"
expect_failure bash "$script" --sha "$sha" --receipt "$fixture_dir/symlink-receipt" | grep -q 'receipt already exists' || fail "receipt symlink accepted"
[ ! -s "$calls" ] || fail "argument errors reached gh or curl"
pass

# --- the commit must already be on the remote --------------------------------

reset
expect_failure bash "$script" --sha "$sha" | grep -q 'push it to a branch first' || fail "unknown commit did not fail"
grep -q 'gh api repos/confidential-dot-ai/confidential-kubernetes/git/commits/' "$calls" || fail "commit existence was not checked"
! grep -q '/dispatches' "$calls" || fail "a workflow was dispatched for an unknown commit"
pass

# --- a build branch at another commit is refused -----------------------------

reset
touch "$state/commit-known"
printf '%s' "$other" >"$state/branch-sha"
expect_failure bash "$script" --sha "$sha" | grep -q "exists at $other" || fail "branch at another commit was accepted"
! grep -q '/dispatches' "$calls" || fail "a workflow was dispatched despite the branch mismatch"
pass

# --- missing components: docker first, then the image, 7-character ref -------

reset
touch "$state/commit-known"
out=$(bash "$script" --sha "$sha" --confos-ref af8cef0e937e4cc300ddd30c85af6ccd8cb9be91)
grep -q 'gh api -X POST repos/confidential-dot-ai/confidential-kubernetes/git/refs -f ref=refs/heads/build/c7cf2f3 -f sha='"$sha" "$calls" || fail "build branch was not created at the commit"
grep -q 'component tags missing at :c7cf2f3' <<<"$out" || fail "missing components not reported"
order=$(sed -n 's|.*actions/workflows/\([^/]*\)/dispatches.*|\1|p' "$calls" | tr '\n' ' ')
[ "$order" = "docker.yml c8s-image-manual.yml " ] || fail "dispatch order: $order"
grep -Fq 'actions/workflows/docker.yml/dispatches -H X-GitHub-Api-Version: 2022-11-28 -f ref=build/c7cf2f3 -F return_run_details=true' "$calls" || fail "docker dispatch did not use the build branch"
grep -Fq 'actions/workflows/c8s-image-manual.yml/dispatches -H X-GitHub-Api-Version: 2022-11-28 -f ref=build/c7cf2f3 -F return_run_details=true -f inputs[c8s_ref]=c7cf2f3 -f inputs[expected_sha]=c7cf2f38de3b035fbce00fe22d2451e77cdcefa0 -f inputs[confos_ref]=af8cef0e937e4cc300ddd30c85af6ccd8cb9be91' "$calls" \
  || fail "image dispatch arguments differ: $(grep 'c8s-image-manual' "$calls")"
grep -q 'guests/worker:sha-c7cf2f3-tdx$' <<<"$out" || fail "artifact tag not printed"
grep -q 'guests/worker:sha-c7cf2f3-sev-snp-kubevirt$' <<<"$out" || fail "KubeVirt tag not printed"
pass

# --- a successful image run that published nothing is an error ---------------

reset
touch "$state/commit-known" "$state/image-publishes-nothing"
printf '%s' "$sha" >"$state/branch-sha"
for c in c8s-operator nri-image-policy ta armtls-mesh volumed; do echo "$c:c7cf2f3" >>"$state/present-tags"; done
expect_failure bash "$script" --sha "$sha" --receipt "$fixture_dir/failed-receipt" | grep -q 'missing expected image guests/worker:sha-c7cf2f3-tdx' \
  || fail "a repository without the commit's tags was reported as published"
[ ! -e "$fixture_dir/failed-receipt" ] || fail "failed publication wrote a receipt"
pass

# --- an incomplete tag set is an error ---------------------------------------

reset
touch "$state/commit-known" "$state/image-publishes-nothing"
printf '%s' "$sha" >"$state/branch-sha"
for c in c8s-operator nri-image-policy ta armtls-mesh volumed; do echo "$c:c7cf2f3" >>"$state/present-tags"; done
echo 'guests/worker:sha-c7cf2f3-tdx' >>"$state/present-tags"
expect_failure bash "$script" --sha "$sha" | grep -q 'missing expected image guests/worker:sha-c7cf2f3-tdx-kubevirt' \
  || fail "a partial tag set was accepted"
pass

# --- an unreadable manifest is an error, not an absent component -------------

reset
touch "$state/commit-known" "$state/manifest-fails"
printf '%s' "$sha" >"$state/branch-sha"
expect_failure bash "$script" --sha "$sha" | grep -q 'registry returned HTTP 503' \
  || fail "an unreadable manifest was swallowed"
! grep -q '/dispatches' "$calls" || fail "registry failure dispatched a build"
pass

# --- components present: only the image build runs ---------------------------

reset
touch "$state/commit-known"
printf '%s' "$sha" >"$state/branch-sha"
for c in c8s-operator nri-image-policy ta armtls-mesh volumed; do echo "$c:c7cf2f3" >>"$state/present-tags"; done
out=$(bash "$script" --sha "$sha" --receipt "$fixture_dir/receipt.json")
jq -e --arg sha "$sha" ' .source == $sha and .componentRun == "" and .componentAttempt == "" and .guestRun == "40001" and .guestAttempt == "1" and (.images | length) == 6 and ([.images[] | endswith("@sha256:" + ("0" * 63) + "1")] | all) ' "$fixture_dir/receipt.json" >/dev/null || fail "receipt did not identify dispatched build"
! grep -q '/tags/list' "$calls" || fail "publication depends on a paginated tag listing"
grep -q 'branch build/c7cf2f3 already at c7cf2f3' <<<"$out" || fail "existing branch not reused"
! grep -q 'actions/workflows/docker.yml/dispatches' "$calls" || fail "docker dispatched although every tag exists"
grep -Fq 'actions/workflows/c8s-image-manual.yml/dispatches -H X-GitHub-Api-Version: 2022-11-28 -f ref=build/c7cf2f3 -F return_run_details=true -f inputs[c8s_ref]=c7cf2f3 -f inputs[expected_sha]=c7cf2f38de3b035fbce00fe22d2451e77cdcefa0 --jq .workflow_run_id' "$calls" || fail "production image dispatch differs"
grep -q 'guests/worker:sha-c7cf2f3-tdx$' <<<"$out" || fail "production artifact tag not printed"
pass

# --- a missing split volumed image must trigger component publication --------

reset
touch "$state/commit-known"
printf '%s' "$sha" >"$state/branch-sha"
for c in c8s-operator nri-image-policy ta armtls-mesh; do echo "$c:c7cf2f3" >>"$state/present-tags"; done
out=$(bash "$script" --sha "$sha")
grep -q 'component tags missing at :c7cf2f3: volumed' <<<"$out" || fail "missing volumed was not checked"
order=$(sed -n 's|.*actions/workflows/\([^/]*\)/dispatches.*|\1|p' "$calls" | tr '\n' ' ')
[ "$order" = "docker.yml c8s-image-manual.yml " ] || fail "volumed dispatch order: $order"
pass

# --- a failed run fails the script -------------------------------------------

reset
touch "$state/commit-known"
printf '%s' "$sha" >"$state/branch-sha"
for c in c8s-operator nri-image-policy ta armtls-mesh volumed; do echo "$c:c7cf2f3" >>"$state/present-tags"; done
echo failure >"$state/run-conclusion"
expect_failure bash "$script" --sha "$sha" | grep -q 'c8s-image-manual.yml run failed' || fail "failed run not reported"
pass

# --- dry run dispatches nothing ---------------------------------------------

reset
touch "$state/commit-known"
out=$(bash "$script" --sha "$sha" --dry-run)
grep -q 'would create branch build/c7cf2f3' <<<"$out" || fail "dry run did not describe the branch"
grep -q 'would dispatch docker.yml' <<<"$out" || fail "dry run did not describe the docker dispatch"
grep -Fq 'would dispatch c8s-image-manual.yml on build/c7cf2f3 with: -f inputs[c8s_ref]=c7cf2f3' <<<"$out" || fail "dry run did not describe the image dispatch: $out"
! grep -q 'api -X POST' "$calls" || fail "dry run dispatched or pushed"
pass

# --- no returned ID must stop, never select a concurrent run -----------------

reset
touch "$state/commit-known" "$state/missing-run-id"
expect_failure bash "$script" --sha "$sha" | grep -q 'dispatch did not return a run ID' || fail "missing run ID accepted"
! grep -q 'gh run list\|gh run watch' "$calls" || fail "another run could be selected"
pass

# --- unsupported workflow versions cause no partial publication -------------

reset
touch "$state/commit-known" "$state/old-workflow"
expect_failure bash "$script" --sha "$sha" | grep -q 'target lacks the guest source guard' || fail "unsupported target accepted"
! grep -q 'api -X POST' "$calls" || fail "unsupported target mutated remote state"
pass

# --- attempt one stays pinned through polling and later reruns ----------------

reset
touch "$state/commit-known" "$state/attempt-pending"
bash "$script" --sha "$sha" --receipt "$fixture_dir/attempt-receipt" >/dev/null
jq -e '.componentAttempt == "1" and .guestAttempt == "1"' "$fixture_dir/attempt-receipt" >/dev/null || fail "attempt identity changed"
pass

# --- changed sources and missing TA formats fail -----------------------------

for failure in move-branch wrong-run-sha; do
  reset
  touch "$state/commit-known" "$state/$failure"
  expect_failure bash "$script" --sha "$sha" --receipt "$fixture_dir/source-receipt" \
    | grep -Eq 'branch changed|different source SHA|no longer successful' || fail "changed source or attempt was accepted"
  ! grep -q 'actions/workflows/c8s-image-manual.yml/dispatches' "$calls" || fail "changed source reached guest dispatch"
  [ ! -e "$fixture_dir/source-receipt" ] || fail "changed source wrote a receipt"
  pass
done

for missing in sha-c7cf2f3 sha-c7cf2f3-kubevirt; do
  reset
  touch "$state/commit-known"
  echo "$missing" >"$state/missing-ta"
  expect_failure bash "$script" --sha "$sha" --receipt "$fixture_dir/missing-ta-receipt" \
    | grep -q "missing expected image guests/ta:$missing" || fail "missing TA format accepted"
  [ ! -e "$fixture_dir/missing-ta-receipt" ] || fail "missing TA wrote a receipt"
  pass
done

# --- mutable tags and conflicting build evidence cannot produce a receipt ---

for failure in moved-tag conflicting-log; do
  reset
  touch "$state/commit-known" "$state/$failure"
  expect_failure bash "$script" --sha "$sha" --receipt "$fixture_dir/race-receipt" \
    | grep -Eq 'tag changed|conflicting publication digest' || fail "mismatched publication accepted"
  [ ! -e "$fixture_dir/race-receipt" ] || fail "mismatched publication wrote a receipt"
  pass
done

# --- an interrupted JSON writer leaves the receipt destination absent -------

reset
touch "$state/commit-known" "$state/receipt-fails"
expect_failure bash "$script" --sha "$sha" --receipt "$fixture_dir/partial-receipt"
[ ! -e "$fixture_dir/partial-receipt" ] || fail "partial JSON was installed"
pass

# --- an appeared directory remains empty when the atomic install fails -------

reset
touch "$state/commit-known"
echo "$fixture_dir/appeared-directory" >"$state/receipt-directory"
expect_failure bash "$script" --sha "$sha" --receipt "$fixture_dir/appeared-directory" \
  | grep -q 'FileExistsError' || fail "appeared directory was accepted"
[ -z "$(ls -A "$fixture_dir/appeared-directory")" ] || fail "file leaked into appeared directory"
pass

echo "ok: $tests publish-ref-images tests"
