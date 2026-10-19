#!/usr/bin/env bash
# Exercise the full production gate against copied inputs; fixture writes are
# scanned as text and never executed. The pinned confos checkout stays read-only.
set -euo pipefail
: "${CONFOS_REF:?CONFOS_REF must be set}"
test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "$test_dir/../../.." && pwd)
confos_dir=$(cd "$repo_dir/confos" && pwd -P)
fixture_dir=$(mktemp -d)
trap 'rm -rf -- "$fixture_dir"' EXIT
cp -a "$repo_dir/node-guest-image" "$repo_dir/.github" "$fixture_dir/"
# The gate also pins the runtime wrapper's compiled real-runc path against
# mkosi.sync, so the fixture needs that package at its repo-relative path.
mkdir -p "$fixture_dir/internal/cmds"
cp -a "$repo_dir/internal/cmds/c8srunc" "$fixture_dir/internal/cmds/"
mkdir -p "$fixture_dir/confos/mkosi/initrd/mkosi.extra"
ln -s "$confos_dir/kernel" "$fixture_dir/confos/kernel"
fixture_init="$fixture_dir/confos/mkosi/initrd/mkosi.extra/init"
cp "$confos_dir/mkosi/initrd/mkosi.extra/init" "$fixture_init"
probe="$fixture_dir/node-guest-image/c8s/mkosi.extra/usr/local/bin/invariant-write-test.sh"
tests=0

fail() { echo "FAIL: $*" >&2; exit 1; }
run_gate() {
  (
    cd "$fixture_dir"
    env "$@" bash .github/scripts/node-guest-image-invariants.sh
  ) >"$fixture_dir/output" 2>&1
}
accepts() {
  printf '%s\n' "$2" >"$probe"
  if ! run_gate; then
    cat "$fixture_dir/output"
    fail "$1 was rejected"
  fi
  tests=$((tests + 1))
}
rejects() {
  printf '%s\n' "$2" >"$probe"
  if run_gate; then fail "$1 was accepted"; fi
  grep -Fq '/usr/bin/c8s-invariant-probe is written at runtime' "$fixture_dir/output" || {
    cat "$fixture_dir/output"
    fail "$1 failed for an unrelated reason"
  }
  tests=$((tests + 1))
}

# The unchanged AppArmor boot probe itself contains an absolute executable
# followed by 2>&1. Its presence in the baseline must not require writable /usr.
accepts "production baseline" '# no additional runtime writes'
accepts "numeric descriptor duplication" '/usr/bin/aa-exec -- /bin/true 2>&1'
# shellcheck disable=SC2016 # Keep command substitution as scanned fixture text.
accepts "descriptor duplication before command-substitution close" \
  'label=$(/usr/bin/aa-exec -- /bin/true 2>&1)'
accepts "numeric input descriptor duplication" '/usr/bin/aa-exec -- /bin/true 3<&0'
rejects "file redirection" 'printf x > /usr/bin/c8s-invariant-probe'
rejects "file redirection before descriptor duplication" \
  'printf x > /usr/bin/c8s-invariant-probe 2>&1'
rejects "file redirection after descriptor duplication" \
  'printf x 2>&1 > /usr/bin/c8s-invariant-probe'
rejects "file append with descriptor duplication" \
  'printf x >> /usr/bin/c8s-invariant-probe 2>&1'
rejects "copy with descriptor duplication" \
  'cp /tmp/source /usr/bin/c8s-invariant-probe 2>&1'
rejects "mkdir with descriptor duplication" \
  'mkdir /usr/bin/c8s-invariant-probe 2>&1'

printf '%s\n' '# no additional runtime writes' >"$probe"
# Remove the support marker only from our copied init. Other confos inputs
# remain read-only references to the pinned checkout.
sed 's|/usr/lib/confai/state\.d|/usr/lib/confai/missing-state.d|g' \
  "$confos_dir/mkosi/initrd/mkosi.extra/init" >"$fixture_init"
for expectation in unset 1; do
  if [ "$expectation" = unset ]; then
    gate_env=(-u EXPECT_IMMUTABLE_ROOT)
  else
    gate_env=(EXPECT_IMMUTABLE_ROOT=1)
  fi
  if run_gate "${gate_env[@]}"; then
    fail "missing immutable-root support was accepted with EXPECT_IMMUTABLE_ROOT=$expectation"
  fi
  grep -Fq 'has no state.d in its initrd' "$fixture_dir/output" || {
    cat "$fixture_dir/output"
    fail "missing immutable-root support failed for an unrelated reason"
  }
  tests=$((tests + 1))
done
if ! run_gate EXPECT_IMMUTABLE_ROOT=0; then
  cat "$fixture_dir/output"
  fail "explicit legacy compatibility override was rejected"
fi
tests=$((tests + 1))

# gpu-cc-enforce runs only at boot, so no kernel config may enable PCI
# hotplug (#669). Fragment edits go to both fragments so the c8s-dev
# superset check still passes and the hotplug check is what fails.
cp "$confos_dir/mkosi/initrd/mkosi.extra/init" "$fixture_init"
kernel_dir="$fixture_dir/node-guest-image/kernel"
cp -a "$kernel_dir" "$fixture_dir/kernel.orig"
rejects_kernel_config() {
  local name=$1 expected=$2 edit=$3 config
  shift 3
  for config in "$@"; do
    sed "$edit" "$fixture_dir/kernel.orig/$config" >"$kernel_dir/$config"
  done
  if run_gate; then fail "$name was accepted"; fi
  grep -Fq "$expected" "$fixture_dir/output" || {
    cat "$fixture_dir/output"
    fail "$name failed for an unrelated reason"
  }
  for config in "$@"; do
    cp "$fixture_dir/kernel.orig/$config" "$kernel_dir/$config"
  done
  tests=$((tests + 1))
}
off='s/^# CONFIG_HOTPLUG_PCI is not set$/CONFIG_HOTPLUG_PCI=y/'
# shellcheck disable=SC2016 # sed's last-line address, not a shell expansion.
append='$a '
rejects_kernel_config "fragments enabling HOTPLUG_PCI" \
  "c8s.config must keep '# CONFIG_HOTPLUG_PCI is not set'" "$off" c8s.config c8s-dev.config
rejects_kernel_config "fragments enabling pciehp" \
  'c8s.config enables the PCI hotplug symbols' "${append}CONFIG_HOTPLUG_PCI_PCIE=y" c8s.config c8s-dev.config
rejects_kernel_config "dev fragment enabling HOTPLUG_PCI" \
  'c8s-dev.config enables the PCI hotplug symbols' "${append}CONFIG_HOTPLUG_PCI=y" c8s-dev.config
rejects_kernel_config "snapshot resolving HOTPLUG_PCI on" \
  "c8s.snapshot must keep '# CONFIG_HOTPLUG_PCI is not set'" "$off" config-x86_64-c8s.snapshot
rejects_kernel_config "snapshot resolving acpiphp on" \
  'c8s.snapshot enables the PCI hotplug symbols' "${append}CONFIG_HOTPLUG_PCI_ACPI=y" config-x86_64-c8s.snapshot
verity_off='s/^CONFIG_FS_VERITY=y$/# CONFIG_FS_VERITY is not set/'
rejects_kernel_config "fragments disabling FS_VERITY" \
  'c8s.config must set CONFIG_FS_VERITY=y' "$verity_off" c8s.config c8s-dev.config
rejects_kernel_config "snapshot resolving FS_VERITY off" \
  'c8s.snapshot must set CONFIG_FS_VERITY=y' "$verity_off" config-x86_64-c8s.snapshot
echo "$tests node-image invariant assertions passed"
