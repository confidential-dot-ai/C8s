#!/usr/bin/env bash
# release-pin.sh against a fake gh: one repository whose latest release is an
# annotated tag, plus a lightweight tag, a non-release tag and a tag at a blob.

set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$test_dir/../release-pin.sh"
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

commit=1111111111111111111111111111111111111111
old_commit=0000000000000000000000000000000000000000
tag_object=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
blob=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

mkdir -p "$work/bin"
cat >"$work/bin/gh" <<EOF
#!/usr/bin/env bash
# Answers what the real gh --jq would print for each endpoint the script uses.
[ "\$1" = api ] || exit 2
shift
while [ "\$1" = -H ]; do shift 2; done
case "\$1" in
  repos/acme/widget/releases/latest) echo v1.2.0 ;;
  repos/acme/widget/git/ref/tags/v1.2.0) echo "tag $tag_object" ;;
  repos/acme/widget/git/tags/$tag_object) echo "commit $commit" ;;
  repos/acme/widget/git/ref/tags/v1.1.0) echo "commit $old_commit" ;;
  repos/acme/widget/git/ref/tags/v1.1.1) echo "blob $blob" ;;
  *) echo "gh: Not Found (HTTP 404)" >&2; exit 1 ;;
esac
EOF
chmod +x "$work/bin/gh"
export PATH="$work/bin:$PATH"

[[ $(bash "$script" acme/widget) == "v1.2.0 $commit" ]] ||
  fail "latest release did not resolve through the annotated tag"
pass

[[ $(bash "$script" acme/widget v1.1.0) == "v1.1.0 $old_commit" ]] ||
  fail "lightweight tag did not resolve"
pass

expect_failure bash "$script" acme/widget v1.1.1
grep -q 'does not end at a commit' "$work/unexpected.stderr" ||
  fail "a tag at a blob was not refused"
pass

expect_failure bash "$script" acme/widget v9.9.9
grep -q 'not found' "$work/unexpected.stderr" || fail "a missing tag was not refused"
pass

for bad in main v1 v1.2 1.2.0 v1.2.0-rc1; do
  expect_failure bash "$script" acme/widget "$bad"
done
pass

expect_failure bash "$script" acme/empty
grep -q 'has no release' "$work/unexpected.stderr" ||
  fail "a repository without releases was not refused"
pass

expect_failure bash "$script" 'acme/widget;rm' v1.2.0
pass

# --floor: only a strictly newer release prints; an equal or older one is a
# no-op, so a watcher keeps its pin.
[[ $(bash "$script" acme/widget --floor v1.1.0) == "v1.2.0 $commit" ]] ||
  fail "a newer release was not proposed over the floor"
[[ -z $(bash "$script" acme/widget --floor v1.2.0) ]] ||
  fail "the same release was proposed over itself"
[[ -z $(bash "$script" acme/widget --floor v2.0.0) ]] ||
  fail "an older release was proposed over a newer floor"
[[ -z $(bash "$script" acme/widget --floor v1.10.0) ]] ||
  fail "v1.2.0 compared newer than v1.10.0: components must compare numerically"
expect_failure bash "$script" acme/widget --floor main
pass

echo "release-pin: $tests tests passed"
