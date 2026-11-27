#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/install.sh"
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
site=$tmp/site
state=$tmp/state
mkdir -p "$site/qemu" "$site/ta" "$state" "$tmp/bin"
printf '%s\n' disk > "$site/ta/disk.raw"
printf '%s\n' iso > "$state/ta.iso"
printf '%s\n' fw > "$site/firmware.fd"
cat > "$tmp/bin/qemu-system-x86_64" <<'QEMU'
#!/bin/sh
printf '%s\n' "$@"
QEMU
chmod +x "$tmp/bin/qemu-system-x86_64"
export PATH="$tmp/bin:$PATH"
printf '%s\n' '["-m","4G","-smp","2"]' > "$site/qemu/ta.json"
(start_vm ta) > "$tmp/args"
grep -Fx -- "if=none,id=root,file=$site/ta/disk.raw,format=raw,readonly=on" "$tmp/args"
grep -Fx -- "if=none,id=launch,file=$state/ta.iso,format=raw,readonly=on" "$tmp/args"
grep -Fx -- "$site/firmware.fd" "$tmp/args"
grep -F 'confidential-guest-support=tdx' "$tmp/args"
grep -F '"/run/tdx-qgs/qgs.socket"' "$tmp/args"
printf '%s\n' '["-m","2G\n-monitor"]' > "$site/qemu/ta.json"
set +e
(set -e; start_vm ta) > "$tmp/rejected"
rc=$?
set -e
[ "$rc" -ne 0 ] && [ ! -s "$tmp/rejected" ] || fail "accepted an invalid QEMU argument"
rm "$site/ta/disk.raw"
if (start_vm ta) >/dev/null 2>"$tmp/missing"; then fail "accepted a missing raw disk"; fi
grep -F "Missing local input: $site/ta/disk.raw" "$tmp/missing"
cat > "$site/k3s" <<'K3S'
#!/bin/sh
cat "$TEST_JOIN_TOKEN"
K3S
cat > "$tmp/bin/genisoimage" <<'ISO'
#!/bin/sh
while [ "$1" != -o ]; do shift; done
cat "$TEST_BOOTSTRAP_PATH" > "$2"
ISO
chmod +x "$site/k3s" "$tmp/bin/genisoimage"
export TEST_JOIN_TOKEN="$tmp/token" TEST_BOOTSTRAP_PATH="$state/bootstrap-token"
echo 'abcdef.0000000000000000' > "$TEST_JOIN_TOKEN"
worker_launch_iso
echo 'abcdef.1111111111111111' > "$TEST_JOIN_TOKEN"
worker_launch_iso
cmp "$TEST_JOIN_TOKEN" "$state/worker.iso"
test ! -e "$TEST_BOOTSTRAP_PATH"
