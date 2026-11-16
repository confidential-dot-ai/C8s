#!/usr/bin/env bash
# ghcr-digest.sh against a fake curl: one published tag, one missing, one
# registry that keeps answering 503.

set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$test_dir/../ghcr-digest.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

tests=0
pass() { tests=$((tests + 1)); }
fail() {
  echo "FAIL: $*" >&2
  exit 1
}
expect_failure() {
  if "$@" >"$work/unexpected.stdout" 2>"$work/unexpected.stderr"; then
    fail "command unexpectedly succeeded: $*"
  fi
}

digest=sha256:8d983edc5beb9d56f74adf93c2dac8af8bda58c6bfd681f6ff576254df0dff8a
mkdir -p "$work/bin"
cat >"$work/bin/curl" <<EOF
#!/usr/bin/env bash
# The last argument is the URL; -I asks for headers only.
url=\${@: -1}
case "\$url" in
  https://ghcr.io/token?scope=repository:acme/widget:pull) echo '{"token":"t0k"}' ;;
  https://ghcr.io/v2/acme/widget/manifests/sha-c52cd8e)
    printf 'HTTP/2 200\r\ndocker-content-digest: $digest\r\ncontent-type: application/vnd.oci.image.index.v1+json\r\n\r\n' ;;
  https://ghcr.io/v2/acme/widget/manifests/sha-0000000) printf 'HTTP/2 404\r\n\r\n' ;;
  https://ghcr.io/v2/acme/widget/manifests/flaky) printf 'HTTP/2 503\r\n\r\n' ;;
  *) exit 22 ;;
esac
EOF
chmod +x "$work/bin/curl"
cat >"$work/bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$work/bin/sleep"
export PATH="$work/bin:$PATH"

[[ $(bash "$script" acme/widget sha-c52cd8e) == "$digest" ]] ||
  fail "the published tag's digest was not reported"
pass

expect_failure bash "$script" acme/widget sha-0000000
grep -q 'is not published' "$work/unexpected.stderr" || fail "a missing tag was not named"
pass

expect_failure bash "$script" acme/widget flaky
grep -q 'on 4 attempts' "$work/unexpected.stderr" || fail "a flaky registry was not given up on"
pass

expect_failure bash "$script" acme/absent sha-c52cd8e
grep -q 'no pull token' "$work/unexpected.stderr" || fail "a token failure was not named"
pass

for bad in 'acme/widget;rm' 'Acme/Widget'; do
  expect_failure bash "$script" "$bad" sha-c52cd8e
done
expect_failure bash "$script" acme/widget 'sha c52cd8e'
pass

echo "ghcr-digest: $tests tests passed"
