#!/usr/bin/env bash
# Check the AppArmor contract in either a fragment or a resolved .config.
# Kconfig is data: never source it. Require one canonical assignment per
# security setting so an earlier matching line cannot hide a later override.
set -euo pipefail

if [[ $# -ne 1 || ! -f "$1" || ! -r "$1" ]]; then
    echo "usage: check-apparmor-config.sh READABLE_KERNEL_CONFIG" >&2
    exit 1
fi

awk '
BEGIN {
    expected["CONFIG_SECURITY_APPARMOR"] = "CONFIG_SECURITY_APPARMOR=y"
    expected["CONFIG_DEFAULT_SECURITY_APPARMOR"] = "CONFIG_DEFAULT_SECURITY_APPARMOR=y"
    expected["CONFIG_SECURITYFS"] = "CONFIG_SECURITYFS=y"
    expected["CONFIG_SECURITY_SELINUX"] = "# CONFIG_SECURITY_SELINUX is not set"
    expected["CONFIG_SECURITY_SMACK"] = "# CONFIG_SECURITY_SMACK is not set"
    expected["CONFIG_SECURITY_TOMOYO"] = "# CONFIG_SECURITY_TOMOYO is not set"
    expected["CONFIG_LSM"] = "CONFIG_LSM=\"landlock,lockdown,yama,loadpin,safesetid,apparmor,ipe,bpf\""
}
/^CONFIG_[A-Z0-9_]+=/ || /^# CONFIG_[A-Z0-9_]+ is not set$/ {
    symbol = $0
    sub(/^# /, "", symbol)
    sub(/=.*$/, "", symbol)
    sub(/ is not set$/, "", symbol)
    if (symbol in expected) {
        count[symbol]++
        actual[symbol] = $0
    }
}
END {
    for (symbol in expected) {
        if (count[symbol] != 1 || actual[symbol] != expected[symbol]) {
            printf "%s: require exactly one %s (found %d assignments)\n", FILENAME, expected[symbol], count[symbol] > "/dev/stderr"
            failed = 1
        }
    }
    exit failed
}
' "$1"
