#!/usr/bin/env bash
# Root-free regression tests run the exact build/invariant checker.
set -euo pipefail
TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$TESTS_DIR/lib.sh"
CHECKER="$TESTS_DIR/../check-apparmor-config.sh"
SNAPSHOT="$TESTS_DIR/../kernel/config-x86_64-c8s.snapshot"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

accepts() { bash "$CHECKER" "$1" >"$WORK/stdout" 2>"$WORK/stderr"; }
rejects() { ! accepts "$1"; }

CASE=committed-configs
for config in "$SNAPSHOT" "$TESTS_DIR/../kernel/c8s.config" "$TESTS_DIR/../kernel/c8s-dev.config"; do
    ok "accepts ${config##*/}" accepts "$config"
done

CASE=missing-config
ok "missing config rejected" rejects "$WORK/missing"
ok "missing argument rejected" not bash "$CHECKER"

CASE=lsm-disabled
sed 's/CONFIG_LSM=.*/CONFIG_LSM="landlock,lockdown,yama,loadpin,safesetid,ipe,bpf"/' "$SNAPSHOT" >"$WORK/config"
ok "AppArmor built but absent from LSM list rejected" rejects "$WORK/config"
ok "diagnostic identifies CONFIG_LSM" stderr_has CONFIG_LSM

for symbol in CONFIG_SECURITY_APPARMOR CONFIG_DEFAULT_SECURITY_APPARMOR CONFIG_SECURITYFS \
              CONFIG_SECURITY_SELINUX CONFIG_SECURITY_SMACK CONFIG_SECURITY_TOMOYO CONFIG_LSM; do
    CASE="missing-$symbol"
    sed "/^$symbol=/d; /^# $symbol is not set$/d" "$SNAPSHOT" >"$WORK/config"
    ok "missing assignment rejected" rejects "$WORK/config"
    ok "diagnostic identifies missing symbol" stderr_has "$symbol"

    CASE="override-$symbol"
    cp "$SNAPSHOT" "$WORK/config"
    printf '%s=n\n' "$symbol" >>"$WORK/config"
    ok "conflicting duplicate rejected" rejects "$WORK/config"

    CASE="duplicate-$symbol"
    cp "$SNAPSHOT" "$WORK/config"
    grep -E "^$symbol=|^# $symbol is not set$" "$SNAPSHOT" >>"$WORK/config"
    ok "identical duplicate rejected" rejects "$WORK/config"

    CASE="changed-$symbol"
    sed "/^$symbol=/d; /^# $symbol is not set$/d" "$SNAPSHOT" >"$WORK/config"
    case "$symbol" in
        CONFIG_SECURITY_SELINUX|CONFIG_SECURITY_SMACK|CONFIG_SECURITY_TOMOYO) printf '%s=y\n' "$symbol" ;;
        *) printf '# %s is not set\n' "$symbol" ;;
    esac >>"$WORK/config"
    ok "disabled AppArmor or enabled competitor rejected" rejects "$WORK/config"
done

summarize "AppArmor kernel config"
