#!/usr/bin/env bash
# Exercise the production gate against copied inputs; the pinned confos
# checkout and images/node-guest stay read-only.
set -euo pipefail
test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "$test_dir/../../.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/.github" "$fixture/confos/mkosi/initrd/mkosi.extra" \
         "$fixture/images/node-guest/c8s"
cp -a "$repo_dir/images/cds-guest" "$fixture/images/"
cp -a "$repo_dir/.github/scripts" "$fixture/.github/"
cp "$(cd "$repo_dir/confos" && pwd -P)/mkosi/initrd/mkosi.extra/init" \
   "$fixture/confos/mkosi/initrd/mkosi.extra/init"
cp "$repo_dir/images/node-guest/c8s/mkosi.finalize" "$fixture/images/node-guest/c8s/"
pristine="$fixture/pristine"
mkdir "$pristine"
cp -a "$fixture/images" "$fixture/confos" "$pristine/"
tests=0

fail() { echo "FAIL: $*" >&2; exit 1; }
run_gate() {
  (cd "$fixture" && bash .github/scripts/cds-guest-image-invariants.sh) \
    >"$fixture/output" 2>&1
}
# Each mutation runs in the fixture, then the inputs are restored.
rejects() {
  local name=$1 expected=$2 mutation=$3
  (cd "$fixture" && "$mutation")
  if run_gate; then fail "$name was accepted"; fi
  grep -Fq "$expected" "$fixture/output" || {
    cat "$fixture/output"
    fail "$name failed for an unrelated reason"
  }
  rm -rf "$fixture/images" "$fixture/confos"
  cp -a "$pristine/images" "$pristine/confos" "$fixture/"
  tests=$((tests + 1))
}

add_interactive_profile() {
  sed -i 's|--profile cds|--profile cds --profile ssh|' images/cds-guest/build
}
forward_arguments() {
  printf '%s\n' '    "$@"' >> images/cds-guest/build
}
rename_profile_dir() {
  # shellcheck disable=SC2016 # Literal sed pattern, not an expansion.
  sed -i 's|--profile-dir "$IMAGE_DIR/cds"|--profile-dir "$IMAGE_DIR/trust-root"|' \
    images/cds-guest/build
}
add_second_service() {
  install -m 0644 /dev/null \
    images/cds-guest/cds/mkosi.extra/etc/systemd/system/rke2-agent.service
}
widen_attester_bind() {
  sed -i 's|127.0.0.1:8400|0.0.0.0:8400|g' images/cds-guest/cds/mkosi.finalize
}
persist_allowlist_store() {
  sed -i 's|--allowlist-db=/run/cds/|--allowlist-db=/var/lib/cds/|' \
    images/cds-guest/cds/mkosi.extra/etc/systemd/system/cds.service
}
rename_staged_launch_file() {
  sed -i 's|/sysroot/run/confai/operator-pubkey|/sysroot/run/confai/launch-file|g' \
    confos/mkosi/initrd/mkosi.extra/init
}
enable_cloud_init() {
  rm images/cds-guest/cds/mkosi.extra/etc/cloud/cloud-init.disabled
}
rewrite_snp_report_data() {
  sed -i 's|^KernelCommandLine=.*|KernelCommandLine=quiet|' \
    images/cds-guest/cds/mkosi.conf
}
pin_a_separate_attester() {
  sed -i 's|^ATTESTATION_RS_REF=.*|ATTESTATION_RS_REF=5e6f31cf0f4a90ff347f37f5274437545ef12a7a|' \
    images/cds-guest/build
}

if ! run_gate; then
  cat "$fixture/output"
  fail "the production images/cds-guest was rejected"
fi
tests=$((tests + 1))

rejects "an interactive profile in the composition" \
  "must enable the attest and cds profiles in that order" add_interactive_profile
rejects "arguments forwarded to confos build" \
  "must not forward extra arguments" forward_arguments
rejects "a profile dir under another name" \
  "must stage a profile dir named cds" rename_profile_dir
rejects "a second service in the image" \
  "may install cds.service only" add_second_service
rejects "a host-reachable attester" \
  "byte-identical to images/node-guest/c8s/mkosi.finalize" widen_attester_bind
rejects "an allowlist store outside the runtime directory" \
  "must keep the allowlist store in RuntimeDirectory=cds" persist_allowlist_store
rejects "a renamed staged launch file" \
  "confos initrd no longer stages the launch file" rename_staged_launch_file
rejects "cloud-init left enabled" \
  "cloud-init would run in the CDS VM" enable_cloud_init
rejects "a kernel that rewrites the SNP report data" \
  "must put snp_measurement_registers=off" rewrite_snp_report_data
rejects "an attester pinned apart from the node images" \
  "must flow from images/cds-guest/build" pin_a_separate_attester

echo "$tests cds-image invariant assertions passed"
