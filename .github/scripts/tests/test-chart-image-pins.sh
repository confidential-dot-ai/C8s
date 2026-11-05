#!/usr/bin/env bash
# chart-image-pins.sh lists the chart's third-party digests by the Resolve
# line above each, and rewrites one in a values.yaml copy; the production file
# is read, never written.
set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "$test_dir/../../.." && pwd)
script="$repo_dir/.github/scripts/chart-image-pins.sh"
values="$repo_dir/internal/helmchart/c8s/values.yaml"
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
tests=0
cp "$values" "$fixture/values.before"

fail() { echo "FAIL: $*" >&2; exit 1; }
expect_failure() {
  if "$@" >"$fixture/unexpected.stdout" 2>"$fixture/unexpected.stderr"; then
    fail "command unexpectedly succeeded: $*"
  fi
}
expect_failure_naming() {
  local needle=$1
  shift
  expect_failure "$@"
  grep -qF -- "$needle" "$fixture/unexpected.stderr" || fail "expected \"$needle\" in: $(cat "$fixture/unexpected.stderr")"
}

# Every non-empty digest in the production chart names its tag, and nothing
# else is listed: the count of listed rows is the count of digest lines.
rows=$(bash "$script" list)
digest_lines=$(grep -cE '^[[:space:]]*digest:[[:space:]]*"?sha256:' "$values")
[[ $(wc -l <<<"$rows") -eq "$digest_lines" ]] || fail "listed $(wc -l <<<"$rows") rows for $digest_lines digest lines"
for repo in nginxinc/nginx-unprivileged busybox; do
  grep -qE "^$repo [A-Za-z0-9._-]+ sha256:[0-9a-f]{64}$" <<<"$rows" || fail "$repo is not listed with a tag and digest"
done
tests=$((tests + 1))

# A fixture: two annotated images, an empty component digest, the
# attestation-api copy, and a quoted repository.
good="$fixture/good.yaml"
cat >"$good" <<'EOF'
image:
  repository: ghcr.io/acme/operator
  tag: ""
  digest: ""
attestationApi:
  pinnedDigest: sha256:8d983edc5beb9d56f74adf93c2dac8af8bda58c6bfd681f6ff576254df0dff8a
metrics:
  image:
    repository: "registry.k8s.io/acme/metrics"
    # Resolve registry.k8s.io/acme/metrics:v1.2.3 to bump this digest.
    digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    tag: ""
  entrypoint: ["/metrics", "serve"]
  imageEnv:
    PATH: /usr/bin
    PORT: "8080"
    UNSET_BY_DEFAULT: null
prep:
  image:
    repository: busybox
    tag: ""
    # Resolve busybox:1.38.0 to bump this digest.
    digest: sha256:2222222222222222222222222222222222222222222222222222222222222222
EOF
expected='registry.k8s.io/acme/metrics v1.2.3 sha256:1111111111111111111111111111111111111111111111111111111111111111
busybox 1.38.0 sha256:2222222222222222222222222222222222222222222222222222222222222222'
[[ "$(bash "$script" list "$good")" == "$expected" ]] || fail "list: $(bash "$script" list "$good")"
tests=$((tests + 1))

# A digest without the line above it, a line without its digest, a line
# naming another repository, a malformed reference, a short digest.
bad="$fixture/bad.yaml"
sed '/# Resolve busybox/d' "$good" >"$bad"
expect_failure_naming 'names no tag' bash "$script" list "$bad"
sed 's/^    digest: sha256:2222.*$/    digest: ""/' "$good" >"$bad"
expect_failure_naming 'not followed by its digest' bash "$script" list "$bad"
sed 's/# Resolve busybox:1.38.0/# Resolve alpine:3.20/' "$good" >"$bad"
expect_failure_naming "names alpine but the block's repository is busybox" bash "$script" list "$bad"
sed 's/# Resolve busybox:1.38.0/# Resolve busybox/' "$good" >"$bad"
expect_failure_naming 'is not REPOSITORY:TAG' bash "$script" list "$bad"
sed 's/sha256:2222222222222222222222222222222222222222222222222222222222222222/sha256:2222/' "$good" >"$bad"
expect_failure_naming 'is not an OCI digest' bash "$script" list "$bad"
expect_failure_naming 'no such file' bash "$script" list "$fixture/absent.yaml"
tests=$((tests + 1))

# set rewrites the one digest under the named line and nothing else, keeps
# the quoting it found, and is idempotent.
copy="$fixture/copy.yaml"
cp "$good" "$copy"
new=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
bash "$script" set busybox:1.38.0 "$new" "$copy"
[[ "$(diff "$good" "$copy" | grep -c '^[<>]')" -eq 2 ]] || fail "set changed more than one line"
grep -q "^    digest: $new$" "$copy" || fail "set did not rewrite the busybox digest unquoted"
bash "$script" set registry.k8s.io/acme/metrics:v1.2.3 "$new" "$copy"
grep -q "^    digest: \"$new\"$" "$copy" || fail "set did not rewrite the metrics digest quoted"
bash "$script" set busybox:1.38.0 "$new" "$copy"
[[ "$(diff "$good" "$copy" | grep -c '^[<>]')" -eq 4 ]] || fail "set is not idempotent"
tests=$((tests + 1))

# A reference the file does not pin, or a malformed digest, changes nothing.
cp "$good" "$copy"
expect_failure_naming 'pins busybox:1.37.0 0 times' bash "$script" set busybox:1.37.0 "$new" "$copy"
expect_failure_naming 'is not REPOSITORY:TAG' bash "$script" set busybox "$new" "$copy"
for malformed in "${new#sha256:}" "sha256:${new:7:10}" "${new^^}"; do
  expect_failure_naming 'is not an OCI digest' bash "$script" set busybox:1.38.0 "$malformed" "$copy"
done
cmp -s "$good" "$copy" || fail "a refused set changed the file"
expect_failure bash "$script" set busybox:1.38.0
expect_failure bash "$script" frobnicate
tests=$((tests + 1))

# resolve asks a fake crane, digest requests only, for each pinned digest and
# each tag, and reports the tag's current digest beside the pinned one.
mkdir -p "$fixture/bin"
cat >"$fixture/bin/crane" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$CRANE_LOG"
if [[ "$1" == config && "$2" == --platform && "$3" == linux/amd64 && $# -eq 4 ]]; then
  case "$4" in
    registry.k8s.io/acme/metrics@sha256:1111*)
      cfg=${METRICS_CONFIG:-}
      [[ -n "$cfg" ]] || cfg='{"config":{"Entrypoint":["/metrics"],"Cmd":["serve","--port=8080"],"Env":["PATH=/usr/bin","PORT=8080"]}}'
      echo "$cfg" ;;
    *) echo "MANIFEST_UNKNOWN: $4" >&2; exit 1 ;;
  esac
  exit 0
fi
[[ "$1" == digest && $# -eq 2 ]] || { echo "unexpected crane call: $*" >&2; exit 1; }
case "$2" in
  registry.k8s.io/acme/metrics@sha256:1111*|busybox@sha256:2222*) echo "${2#*@}" ;;
  registry.k8s.io/acme/metrics:v1.2.3) echo sha256:1111111111111111111111111111111111111111111111111111111111111111 ;;
  busybox:1.38.0) echo sha256:3333333333333333333333333333333333333333333333333333333333333333 ;;
  *) echo "MANIFEST_UNKNOWN: $2" >&2; exit 1 ;;
esac
EOF
chmod +x "$fixture/bin/crane"
export PATH="$fixture/bin:$PATH" CRANE_LOG="$fixture/crane.log"
expected='registry.k8s.io/acme/metrics v1.2.3 sha256:1111111111111111111111111111111111111111111111111111111111111111 sha256:1111111111111111111111111111111111111111111111111111111111111111
busybox 1.38.0 sha256:2222222222222222222222222222222222222222222222222222222222222222 sha256:3333333333333333333333333333333333333333333333333333333333333333'
[[ "$(bash "$script" resolve "$good")" == "$expected" ]] || fail "resolve: $(bash "$script" resolve "$good")"
[[ $(grep -c . "$CRANE_LOG") -eq 4 ]] || fail "resolve made $(grep -c . "$CRANE_LOG") crane calls for two images, not 4"
# A pinned digest the registry no longer serves, or a tag it never had,
# fails, and the other image's row still prints.
sed 's/sha256:2222222222222222222222222222222222222222222222222222222222222222/sha256:4444444444444444444444444444444444444444444444444444444444444444/' "$good" >"$bad"
expect_failure_naming 'busybox@sha256:4444' bash "$script" resolve "$bad"
grep -q '^registry.k8s.io/acme/metrics v1.2.3 ' "$fixture/unexpected.stdout" || fail "a failed image hid the others' rows"
sed 's/# Resolve busybox:1.38.0/# Resolve busybox:1.37.0/' "$good" >"$bad"
expect_failure_naming 'busybox:1.37.0 does not resolve' bash "$script" resolve "$bad"
sed '/# Resolve busybox/d' "$good" >"$bad"
expect_failure_naming 'names no tag' bash "$script" resolve "$bad"
tests=$((tests + 1))

# check reads the config of every image whose block declares an entrypoint
# (one config read, linux/amd64) and requires the entrypoint to prefix
# ENTRYPOINT+CMD and imageEnv, nulls dropped, to equal Env; a block without
# an entrypoint is argv-pinned and skipped.
: >"$CRANE_LOG"
expected='registry.k8s.io/acme/metrics v1.2.3 ok
busybox 1.38.0 argv-pinned'
[[ "$(bash "$script" check "$good")" == "$expected" ]] || fail "check: $(bash "$script" check "$good")"
[[ $(grep -c '^config ' "$CRANE_LOG") -eq 1 ]] || fail "check read $(grep -c '^config ' "$CRANE_LOG") configs, not one"
sed 's|entrypoint: \["/metrics", "serve"\]|entrypoint: ["/metrics", "run"]|' "$good" >"$bad"
expect_failure_naming 'not the seeded entrypoint ["/metrics","run"]' bash "$script" check "$bad"
sed 's|PORT: "8080"|PORT: "9090"|' "$good" >"$bad"
expect_failure_naming 'not the seeded imageEnv' bash "$script" check "$bad"
sed 's|entrypoint: \["/metrics", "serve"\]|entrypoint: ["/metrics", "serve", "--port=8080", "--extra"]|' "$good" >"$bad"
expect_failure_naming 'not the seeded entrypoint' bash "$script" check "$bad"
METRICS_CONFIG='{"config":{"Entrypoint":["/metrics","serve"],"Env":["PATH=/usr/bin","PORT=8080","TOKEN=a=b"]}}' \
  expect_failure_naming '"TOKEN":"a=b"' bash "$script" check "$good"
tests=$((tests + 1))

# The production file is never written by this test.
cmp -s "$values" "$fixture/values.before" || fail "the production values.yaml changed"

echo "chart-image-pins: $tests tests passed"
