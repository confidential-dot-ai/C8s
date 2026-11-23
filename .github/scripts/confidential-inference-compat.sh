#!/usr/bin/env bash
# Judge whether one change to c8s breaks confidential-inference.
#
#   confidential-inference-compat.sh --c8s DIR --confidential-inference DIR \
#     --before SHA --after SHA
#
# The change is BEFORE..AFTER in the c8s checkout. confidential-inference is a
# checkout of its main: the files it reads c8s with (CONTRACT_FILES, plus the
# source files its lock hashes at the pinned c8s commit) are what the change
# is judged against. A change is INCOMPATIBLE when confidential-inference would
# have to change to move its c8s pin onto AFTER.
#
# Two judges, in order: a hashed source file that the change deletes or renames
# is INCOMPATIBLE on its own (the lock needs an edit); otherwise a model reads
# the commits, the diff without tests and docs, and the contract files. Needs
# CONFIDENTIAL_INFERENCE_API_KEY for the model, git, jq and curl.
#
# Prints the report; its first line is COMPATIBLE or INCOMPATIBLE. Exits 0 for
# COMPATIBLE, 1 for INCOMPATIBLE and 2 when the check itself failed.

set -euo pipefail

usage="usage: confidential-inference-compat.sh --c8s DIR --confidential-inference DIR --before SHA --after SHA"

api=https://api.confidential.ai

# The confidential-inference files that read c8s: its pins, the scripts that
# run the c8s CLI and read c8s source and artifacts, the chart values that name
# c8s labels, ports and secrets, and the Go tool that imports pkg/allowlist.
CONTRACT_FILES=(
  release/spec.yaml
  docs/network-ports.yaml
  scripts/bump-c8s.py
  scripts/c8s_release.py
  scripts/check-c8s-admission.py
  scripts/fetch-node-manifest.py
  scripts/generate-release-allowlist.py
  scripts/render-allowlist.py
  helm/confidential-inference/values.yaml
  tools/c8s-allowlist-canonical/go.mod
  tools/c8s-allowlist-canonical/main.go
)
SOURCE_LOCK=release/inputs/c8s-source-lock.json

# Pathspecs excluding the c8s paths that no contract file observes.
UNOBSERVED=(
  ':(exclude,glob)**/*_test.go'
  ':(exclude,glob)**/testdata/**'
  ':(exclude,glob)**/*.md'
  ':(exclude)docs'
  ':(exclude)test'
  ':(exclude)go.sum'
  ':(exclude)go.work.sum'
)

fail() {
  echo "CHECK FAILED: $*"
  exit 2
}

c8s='' consumer='' before='' after=''
while [ $# -gt 0 ]; do
  case "$1" in
    --c8s) c8s=$2; shift 2 ;;
    --confidential-inference) consumer=$2; shift 2 ;;
    --before) before=$2; shift 2 ;;
    --after) after=$2; shift 2 ;;
    *) fail "$usage" ;;
  esac
done
[[ -n $c8s && -n $consumer && -n $before && -n $after ]] || fail "$usage"
for name in "${CONTRACT_FILES[@]}" "$SOURCE_LOCK"; do
  [ -f "$consumer/$name" ] || fail "confidential-inference has no $name; update CONTRACT_FILES"
done

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

git -C "$c8s" diff "$before" "$after" -- . "${UNOBSERVED[@]}" >"$work/diff" ||
  fail "cannot diff $before..$after in $c8s"
if [ ! -s "$work/diff" ]; then
  printf 'COMPATIBLE\n\nThe change touches only tests, docs and go.sum.\n'
  exit 0
fi

pinned=$(sed -n 's/^ *sourceCommit: *\([0-9a-f]\{40\}\) *$/\1/p' "$consumer/release/spec.yaml")
[[ $pinned =~ ^[0-9a-f]{40}$ ]] || fail "release/spec.yaml does not pin exactly one c8s sourceCommit"
jq --arg commit "$pinned" '
  first(.commits[] | select(.commit == $commit))
  | {tag, attestationProtocol, requiredVerifierFlags, capabilities, hashedSourceFiles: (.files | keys)}
  ' "$consumer/$SOURCE_LOCK" >"$work/lock"
[ -s "$work/lock" ] || fail "$SOURCE_LOCK has no entry for the pinned commit $pinned"

mapfile -t hashed < <(jq -r '.hashedSourceFiles[]' "$work/lock")
# --no-renames: the lock names a file by path, so a renamed one is a deleted one.
mapfile -t gone < <(git -C "$c8s" diff --name-only --diff-filter=D --no-renames "$before" "$after" -- "${hashed[@]}")
if [ "${#gone[@]}" -gt 0 ]; then
  printf 'INCOMPATIBLE\n\nThe change deletes or renames source files that confidential-inference hashes in %s; its next bump needs a lock edit (bump-c8s.py SOURCE_SUCCESSORS):\n\n' "$SOURCE_LOCK"
  printf -- '- %s\n' "${gone[@]}"
  exit 1
fi

[ -n "${CONFIDENTIAL_INFERENCE_API_KEY:-}" ] || fail "CONFIDENTIAL_INFERENCE_API_KEY is not set"

{
  cat <<EOF
You judge whether one change to c8s (confidential Kubernetes) breaks confidential-inference, a public repository that pins one c8s release and consumes it through the files quoted below.

The change is INCOMPATIBLE when confidential-inference's main would have to change to move its c8s pin onto the commit after this change. Otherwise it is COMPATIBLE.

What makes confidential-inference change, as the quoted files show:
- a c8s file they read moved or changed shape: the chart component inventory and values, .github/build-pins.json, the worker image's mkosi.sync; a changed body of a hashed source file does not count, the bump re-hashes it;
- a c8s CLI subcommand, flag, output or lint message they run or parse changed: c8s node-image render, c8s allowlist derive, c8s allowlist lint --strict;
- the Go API of pkg/allowlist that tools/c8s-allowlist-canonical imports changed;
- the worker or Trust Authority (TA) guest image names, tags, manifest artifact layout or measurement fields changed;
- the signed release statement, its asset names, its CLI asset map or the signer identity (.github/workflows/semver-tag.yml) changed;
- the allowlist document schema, rule shapes, the injected sidecar names and entrypoints, platform mounts or the seed render changed;
- the TA port, the attestation protocol or bundle fields, the required verifier flags, or the front-door labels and namespaces changed.

A change to c8s internals that none of the quoted files observe is COMPATIBLE, however large. A refactor that keeps the observed behaviour is COMPATIBLE. The quoted files describe the pinned release $(jq -r .tag "$work/lock"); the change may build on later commits, so judge only what this change alters.

Reply format: the first line is exactly COMPATIBLE or INCOMPATIBLE. Then, for INCOMPATIBLE, one bullet per break: what c8s changed (file), what in confidential-inference must change (file), why. For COMPATIBLE, one or two sentences on what you checked. Markdown, no preamble.

# confidential-inference, as its main reads c8s

## $SOURCE_LOCK (entry of the pinned commit, hashes left out)

EOF
  cat "$work/lock"
  for name in "${CONTRACT_FILES[@]}"; do
    printf '\n## %s\n\n' "$name"
    cat "$consumer/$name"
  done
} >"$work/system"

{
  printf '# The c8s change %s..%s\n\n## Commits, first parent\n\n' "$before" "$after"
  git -C "$c8s" log --first-parent --format='### %h %s%n%n%b' "$before..$after"
  printf '\n## Diff, without tests, docs and go.sum\n\n'
  cat "$work/diff"
} >"$work/user"

# The API serves the one model its deployment pins; the name moves with it.
model=$(curl -sS --fail-with-body --max-time 60 "$api/v1/models" | jq -er '.data[0].id') ||
  fail "cannot list the models of $api"
jq -n --arg model "$model" --rawfile system "$work/system" --rawfile user "$work/user" '{
  model: $model,
  max_tokens: 2000,
  messages: [{role: "system", content: $system}, {role: "user", content: $user}]
}' >"$work/request"

if ! curl -sS --fail-with-body --max-time 600 "$api/v1/chat/completions" \
    -H "Authorization: Bearer $CONFIDENTIAL_INFERENCE_API_KEY" \
    -H 'content-type: application/json' --data-binary "@$work/request" >"$work/reply"; then
  fail "the model API refused the request: $(head -c 400 "$work/reply")"
fi
report=$(jq -r '.choices[0].message.content' "$work/reply")

# The verdict is the reply's first word. Models put emphasis around it or run
# the reason onto its line; the report still opens with the bare verdict.
report=${report#"${report%%[![:space:]]*}"}
first=${report%%$'\n'*}
verdict_line='^[*_#[:space:]]*(INCOMPATIBLE|COMPATIBLE)([^[:alnum:]].*)?$'
[[ $first =~ $verdict_line ]] ||
  fail "the model gave no verdict on its first line: $(head -c 300 <<<"$report")"
verdict=${BASH_REMATCH[1]}
[[ ${BASH_REMATCH[2]} =~ ^[*_]*[[:space:]]*[:.,-]?[[:space:]]*(.*)$ ]]
reason=${BASH_REMATCH[1]}

printf '%s\n' "$verdict"
[ -z "$reason" ] || printf '\n%s\n' "$reason"
[ "$first" = "$report" ] || printf '%s\n' "${report#*$'\n'}"
[ "$verdict" = COMPATIBLE ] || exit 1
