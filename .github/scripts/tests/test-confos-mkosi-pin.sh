#!/usr/bin/env bash
# confos-mkosi-pin.sh against a file:// tree standing in for raw.githubusercontent.

set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$test_dir/../confos-mkosi-pin.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export CONFOS_RAW_BASE="file://$work"

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

one=1111111111111111111111111111111111111111
none=2222222222222222222222222222222222222222
two=3333333333333333333333333333333333333333
mkosi=4736cd836108a97772142c461c49f1ddb4172348
base_yml() {
  mkdir -p "$work/$1/.github/workflows"
  cat >"$work/$1/.github/workflows/base.yml"
}
base_yml "$one" <<EOF
      - name: Setup mkosi
        uses: systemd/mkosi@$mkosi # v27
EOF
base_yml "$none" <<'EOF'
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
EOF
base_yml "$two" <<EOF
        uses: systemd/mkosi@$mkosi # v27
        uses: systemd/mkosi@$one # v28
EOF

[[ $(bash "$script" "$one") == "$mkosi v27" ]] ||
  fail "the single mkosi pin was not reported"
pass

expect_failure bash "$script" "$none"
grep -q 'found 0' "$work/unexpected.stderr" || fail "a base.yml without a pin was not refused"
pass

expect_failure bash "$script" "$two"
grep -q 'found 2' "$work/unexpected.stderr" || fail "two pins were not refused"
pass

expect_failure bash "$script" 4444444444444444444444444444444444444444
pass

for bad in main 1111111 "$one;rm"; do
  expect_failure bash "$script" "$bad"
done
pass

echo "confos-mkosi-pin: $tests tests passed"
