#!/usr/bin/env bash
# confidential-inference-compat.sh against a small c8s repository, a
# confidential-inference tree that pins its first commit, and a fake curl that
# lists one model, records the chat call and answers it with $REPLY.

set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$test_dir/../confidential-inference-compat.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

tests=0
pass() { tests=$((tests + 1)); }
fail() {
  echo "FAIL: $*" >&2
  exit 1
}
# Runs the script on BEFORE..AFTER; stdout to $work/report, exit status to $status.
judge() {
  status=0
  bash "$script" --c8s "$work/c8s" --confidential-inference "$work/ci" \
    --before "$1" --after "$2" >"$work/report" || status=$?
}
commit() {
  git -C "$work/c8s" add -A
  git -C "$work/c8s" -c user.name=t -c user.email=t@t commit -qm "$1" --allow-empty
  git -C "$work/c8s" rev-parse HEAD
}

mkdir -p "$work/bin"
cat >"$work/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
  case "$arg" in
    */v1/models) echo '{"data": [{"id": "test-model"}]}'; exit 0 ;;
    @*) cp "${arg#@}" "$FAKE_REQUEST" ;;
  esac
done
printf '%s\n' "$@" >"$FAKE_ARGS"
jq -n --arg text "$REPLY" '{choices: [{message: {content: $text}}]}'
EOF
chmod +x "$work/bin/curl"
export PATH="$work/bin:$PATH" FAKE_REQUEST="$work/request" FAKE_ARGS="$work/args" \
  CONFIDENTIAL_INFERENCE_API_KEY=test

# The c8s repository: one hashed source file, one other source file, a test
# and a doc.
mkdir -p "$work/c8s/internal/cmds/cds" "$work/c8s/pkg/allowlist" "$work/c8s/docs"
git -C "$work/c8s" init -q
echo 'package cds' >"$work/c8s/internal/cmds/cds/routes.go"
echo 'package allowlist' >"$work/c8s/pkg/allowlist/allowlist.go"
echo 'package allowlist' >"$work/c8s/pkg/allowlist/allowlist_test.go"
echo '# c8s' >"$work/c8s/docs/README.md"
pinned=$(commit "pinned release")

# confidential-inference pins that commit and hashes routes.go.
mkdir -p "$work/ci/release/inputs" "$work/ci/docs" "$work/ci/scripts" \
  "$work/ci/helm/confidential-inference" "$work/ci/tools/c8s-allowlist-canonical"
printf 'c8s:\n  release: v1.0.0\n  sourceCommit: %s\n' "$pinned" >"$work/ci/release/spec.yaml"
jq -n --arg commit "$pinned" '{commits: [{commit: $commit, tag: "v1.0.0",
  attestationProtocol: "c8s/attest-pq/v1", requiredVerifierFlags: ["--allowlist"],
  capabilities: {}, files: {"internal/cmds/cds/routes.go": "sha256:0"}}]}' \
  >"$work/ci/release/inputs/c8s-source-lock.json"
for name in docs/network-ports.yaml scripts/bump-c8s.py scripts/c8s_release.py \
    scripts/check-c8s-admission.py scripts/fetch-node-manifest.py \
    scripts/generate-release-allowlist.py scripts/render-allowlist.py \
    helm/confidential-inference/values.yaml tools/c8s-allowlist-canonical/go.mod \
    tools/c8s-allowlist-canonical/main.go; do
  echo "contract $name" >"$work/ci/$name"
done

# A change to tests and docs alone is compatible without asking the model.
echo 'package allowlist // more' >"$work/c8s/pkg/allowlist/allowlist_test.go"
echo '# c8s, updated' >"$work/c8s/docs/README.md"
docs_only=$(commit "docs: update")
REPLY=unused judge "$pinned" "$docs_only"
[[ $status -eq 0 && $(head -n1 "$work/report") = COMPATIBLE ]] ||
  fail "a tests-and-docs change was not compatible: $(cat "$work/report")"
[ ! -e "$work/request" ] || fail "a tests-and-docs change asked the model"
pass

# A source change is judged by the served model: the request carries the
# commit, the diff and the contract files; the verdict is the reply's first line.
echo 'package allowlist; func Parse() {}' >"$work/c8s/pkg/allowlist/allowlist.go"
api_change=$(commit "feat(allowlist): add Parse")
REPLY=$'INCOMPATIBLE\n\n- pkg/allowlist gained Parse' judge "$docs_only" "$api_change"
[ "$status" -eq 1 ] || fail "INCOMPATIBLE did not exit 1 (exit $status)"
grep -q 'pkg/allowlist gained Parse' "$work/report" || fail "the report is not the model's reply"
grep -qx 'https://api.confidential.ai/v1/chat/completions' "$work/args" || fail "the request did not go to chat completions"
grep -qx 'Authorization: Bearer test' "$work/args" || fail "the request lacks the bearer key"
[ "$(jq -r '.model' "$work/request")" = test-model ] || fail "the request does not name the served model"
user=$(jq -r '.messages[1].content' "$work/request")
grep -q 'feat(allowlist): add Parse' <<<"$user" || fail "the request lacks the commit subject"
grep -q '+package allowlist; func Parse' <<<"$user" || fail "the request lacks the diff"
system=$(jq -r '.messages[0].content' "$work/request")
grep -q 'contract scripts/bump-c8s.py' <<<"$system" || fail "the request lacks a contract file"
grep -q '"internal/cmds/cds/routes.go"' <<<"$system" || fail "the request lacks the hashed source files"
grep -q 'sha256:0' <<<"$system" && fail "the request carries the source hashes"
pass

REPLY=$'COMPATIBLE\n\nOnly a new function.' judge "$docs_only" "$api_change"
[ "$status" -eq 0 ] || fail "COMPATIBLE did not exit 0 (exit $status)"
pass

# The verdict is the reply's first word: a reason run onto its line, or
# emphasis around it, moves below a first line that is the bare verdict.
REPLY=$'COMPATIBLE: the change only adds `Parse`.' judge "$docs_only" "$api_change"
[[ $status -eq 0 && $(cat "$work/report") = $'COMPATIBLE\n\nthe change only adds `Parse`.' ]] ||
  fail "a verdict with its reason on the same line was not read (exit $status): $(cat "$work/report")"
pass

REPLY=$'\n**INCOMPATIBLE**\n\n- pkg/allowlist gained Parse' judge "$docs_only" "$api_change"
[[ $status -eq 1 && $(cat "$work/report") = $'INCOMPATIBLE\n\n- pkg/allowlist gained Parse' ]] ||
  fail "an emphasised verdict was not read (exit $status): $(cat "$work/report")"
pass

for reply in 'I am not sure.' 'COMPATIBLEish.' 'Not INCOMPATIBLE.'; do
  REPLY=$reply judge "$docs_only" "$api_change"
  [[ $status -eq 2 && $(head -n1 "$work/report") = *'no verdict'* ]] ||
    fail "the reply '$reply' was not a failed check: $(cat "$work/report")"
done
pass

# Deleting a hashed source file is incompatible without asking the model.
rm "$work/request"
git -C "$work/c8s" mv internal/cmds/cds/routes.go internal/cmds/cds/handlers.go
renamed=$(commit "refactor(cds): rename routes.go")
REPLY=unused judge "$api_change" "$renamed"
[[ $status -eq 1 && $(head -n1 "$work/report") = INCOMPATIBLE && $(cat "$work/report") = *internal/cmds/cds/routes.go* ]] ||
  fail "renaming a hashed file was not incompatible: $(cat "$work/report")"
[ ! -e "$work/request" ] || fail "a deleted hashed file asked the model"
pass

# The deletion counts only in the change that made it.
echo 'package cds // later' >"$work/c8s/pkg/allowlist/allowlist.go"
later=$(commit "chore: later change")
REPLY=$'COMPATIBLE\n\nFine.' judge "$renamed" "$later"
[ "$status" -eq 0 ] || fail "an earlier deletion was reported again (exit $status): $(cat "$work/report")"
pass

# A contract file that confidential-inference no longer has fails the check.
rm "$work/ci/scripts/render-allowlist.py"
REPLY=unused judge "$docs_only" "$api_change"
[[ $status -eq 2 && $(cat "$work/report") = *scripts/render-allowlist.py* ]] ||
  fail "a missing contract file was not a failed check: $(cat "$work/report")"
pass

echo "ok: $tests tests"
