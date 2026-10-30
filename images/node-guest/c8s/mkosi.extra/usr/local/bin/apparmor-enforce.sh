#!/bin/sh
# Verify the running kernel and userspace before either RKE2 role starts.
# This probes AppArmor itself; tests/apparmor-runtime-test.sh separately
# verifies containerd's RuntimeDefault profile and Kubernetes admission.
set -eu
export LC_ALL=C

fail() {
    echo "apparmor-enforce: $1 — refusing to start the node" >&2
    exit 1
}

grep -qE '(^|,)apparmor(,|$)' /sys/kernel/security/lsm \
    || fail "AppArmor is absent from the active LSM list"
[ "$(cat /sys/module/apparmor/parameters/enabled)" = Y ] \
    || fail "AppArmor is disabled"
# This is the exact parser path containerd's host-support check uses.
[ -x /sbin/apparmor_parser ] || fail "apparmor_parser is missing"
[ -x /usr/bin/aa-exec ] || fail "aa-exec is missing"
[ "$(systemctl is-enabled apparmor.service 2>/dev/null || true)" = disabled ] \
    || fail "apparmor.service must be disabled"
[ "$(systemctl is-active apparmor.service 2>/dev/null || true)" = inactive ] \
    || fail "apparmor.service must be inactive"

# A dedicated, unattached profile: it never attaches to host tools by path.
# Use the same parser configuration as containerd, but never cached policy.
profile() {
    cat <<'EOF'
profile c8s-apparmor-boot-probe flags=(attach_disconnected) {
  file,
  deny /proc/version r,
}
EOF
}
cleanup() {
    profile | /sbin/apparmor_parser --remove --skip-cache \
        || fail "cannot remove the boot probe profile"
}
profile | /sbin/apparmor_parser --replace --skip-cache \
    || fail "cannot load the boot probe profile"
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
grep -qxF 'c8s-apparmor-boot-probe (enforce)' /sys/kernel/security/apparmor/profiles \
    || fail "boot probe profile is not in enforce mode"

# Prove execution/label selection works before treating any denial as success.
label=$(/usr/bin/aa-exec -p c8s-apparmor-boot-probe -- /bin/cat /proc/self/attr/current) \
    || fail "cannot enter the boot probe profile"
[ "$label" = 'c8s-apparmor-boot-probe (enforce)' ] \
    || fail "boot probe process has unexpected label: $label"
/bin/cat /proc/version >/dev/null || fail "unconfined control read failed"
if denied=$(/usr/bin/aa-exec -p c8s-apparmor-boot-probe -- /bin/cat /proc/version 2>&1); then
    fail "AppArmor did not deny the probe read"
else
    [ "$?" = 1 ] || fail "probe command failed unexpectedly: $denied"
fi
case "$denied" in
    *'Permission denied'*) ;;
    *) fail "probe read failed for an unrelated reason: $denied" ;;
esac
cleanup
trap - EXIT HUP INT TERM
echo "apparmor-enforce: active AppArmor, parser load and enforced denial verified"
