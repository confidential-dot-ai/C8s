#!/usr/bin/env bash
# release-seeds.sh against a fake c8s that records each render's arguments and
# writes a seed naming them, so the test needs no Helm and no chart render.

set -euo pipefail

test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$test_dir/../release-seeds.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

tests=0
pass() { tests=$((tests + 1)); }
fail() {
  echo "FAIL: $*" >&2
  exit 1
}

kube=$(sed -n 's/^KUBERNETES_VERSION="\(v[0-9.]*\)"$/\1/p' "$test_dir/../../../images/node-guest/worker/mkosi.sync")
[ -n "$kube" ] || fail "mkosi.sync pins no kubelet version"

mkdir -p "$work/bin"
cat >"$work/bin/c8s" <<'EOF'
#!/usr/bin/env bash
[ "$1 $2" = "node-image render" ] || exit 2
shift 2
args=$*
printf 'args %s\n' "$args" >> "$FAKE_C8S_LOG"
while [ $# -gt 0 ]; do
  if [ "$1" = --output-dir ]; then out=$2; fi
  shift
done
mkdir -p "$out"
echo "seed of $args" > "$out/allowlist-seed.json"
echo "set of $args" > "$out/component-set.json"
EOF
chmod +x "$work/bin/c8s"
export FAKE_C8S_LOG="$work/c8s.log"

operator=sha256:1111111111111111111111111111111111111111111111111111111111111111
mesh=sha256:2222222222222222222222222222222222222222222222222222222222222222
bash "$script" "$work/bin/c8s" "$work/out" "$operator" "$mesh" tdx sev-snp
for platform in tdx sev-snp; do
  [ -f "$work/out/allowlist-seed-$platform.json" ] || fail "the $platform seed is missing"
  [ -f "$work/out/component-set-$platform.json" ] || fail "the $platform component set is missing"
done
pass

for platform in tdx sev-snp; do
  args="--hardware-platform $platform --kube-version $kube --image-digest $operator --armtls-mesh-image-digest $mesh --output-dir "
  grep -Fq "args $args" "$work/c8s.log" ||
    fail "$platform did not render with the worker image's inputs: $(cat "$work/c8s.log")"
  grep -Fq "seed of $args" "$work/out/allowlist-seed-$platform.json" ||
    fail "allowlist-seed-$platform.json is not the render's seed"
  grep -Fq "set of $args" "$work/out/component-set-$platform.json" ||
    fail "component-set-$platform.json is not the render's set"
done
pass

if bash "$script" "$work/bin/c8s" "$work/out" "$operator" "$mesh" 2>"$work/stderr"; then
  fail "a call without a platform was not refused"
fi
grep -q '^usage:' "$work/stderr" || fail "a call without a platform printed no usage: $(cat "$work/stderr")"
pass

echo "release-seeds: $tests tests passed"
