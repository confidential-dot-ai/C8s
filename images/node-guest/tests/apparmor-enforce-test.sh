#!/bin/bash
# Fault-injection tests of the unchanged production AppArmor boot gate.
# Driver mode needs Docker and CONFOS_RELEASE; --inside uses a private chroot
# with fixtures at the real absolute paths, without mounting host filesystems.
set -u

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

cleanup_container() {
    local status=$?
    trap - EXIT
    if [[ -n "$container" ]]; then
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    exit "$status"
}

if [[ "${1:-}" != --inside ]]; then
    command -v docker >/dev/null 2>&1 || { echo "docker required"; exit 2; }
    : "${CONFOS_RELEASE:?set CONFOS_RELEASE to the pinned confos Ubuntu release}"
    container=""
    trap 'cleanup_container' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    container=$(docker create --network none --cap-drop ALL --cap-add SYS_CHROOT --cap-add MKNOD \
        "ubuntu:$CONFOS_RELEASE" sleep infinity) || exit 2
    docker cp "$TESTS_DIR/.." "$container":/ngi >/dev/null || exit 2
    docker start "$container" >/dev/null || exit 2
    docker exec "$container" bash /ngi/tests/apparmor-enforce-test.sh --inside
    exit $?
fi

[[ -f /.dockerenv && $(id -u) == 0 ]] || {
    echo "--inside requires the disposable root-owned Docker container"; exit 2;
}
. "$TESTS_DIR/lib.sh"
SCRIPT=$TESTS_DIR/../c8s/mkosi.extra/usr/local/bin/apparmor-enforce.sh
[[ -f "$SCRIPT" ]] || { echo "script not found: $SCRIPT"; exit 2; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export PROBE_CASE=good
mkdir -p "$WORK/bin" "$WORK/sbin" "$WORK/usr/bin" "$WORK/usr/local/bin" "$WORK/dev" \
    "$WORK/sys/kernel/security/apparmor" \
    "$WORK/sys/module/apparmor/parameters" "$WORK/proc/self/attr" || exit 2
mknod -m 666 "$WORK/dev/null" c 1 3 || exit 2

# Use the image's real /bin/sh and commands, not a substitute interpreter.
# Copy dependencies rather than bind mounting anything from the host.
for binary in /bin/sh /bin/cat /bin/grep /bin/touch /bin/rm; do
    cp -L --parents "$binary" "$WORK" || exit 2
done
libraries=$(ldd /bin/sh /bin/cat /bin/grep /bin/touch /bin/rm) || exit 2
while IFS= read -r library; do
    cp -L --parents "$library" "$WORK" || exit 2
done < <(printf '%s\n' "$libraries" | awk '
    $2 == "=>" && $3 ~ /^\// { print $3 }
    $1 ~ /^\// && $2 ~ /^\(/ { print $1 }
' | sort -u)
cp "$SCRIPT" "$WORK/usr/local/bin/apparmor-enforce.sh" || exit 2

cat >"$WORK/sbin/apparmor_parser" <<'EOF'
#!/bin/sh
cat > /policy
grep -qxF '  deny /proc/version r,' /policy || exit 2
printf '%s\n' "$*" >> /parser-calls
case "$1" in
    --replace)
        [ "$PROBE_CASE" != load-fails ] || exit 1
        mode=enforce
        [ "$PROBE_CASE" != complain ] || mode=complain
        printf 'c8s-apparmor-boot-probe (%s)\n' "$mode" > /sys/kernel/security/apparmor/profiles
        touch /loaded
        ;;
    --remove)
        [ "$PROBE_CASE" != cleanup-fails ] || exit 1
        rm -f /loaded
        ;;
    *) exit 1 ;;
esac
EOF
cat >"$WORK/usr/bin/aa-exec" <<'EOF'
#!/bin/sh
[ "$1" = -p ] && [ "$2" = c8s-apparmor-boot-probe ] && [ "$3" = -- ] || exit 2
shift 3
[ "$1" = /bin/cat ] || exit 2
case "$2" in
    /proc/self/attr/current)
        case "$PROBE_CASE" in
            bad-label) echo unconfined ;;
            empty-label) : ;;
            enter-fails) exit 1 ;;
            *) echo 'c8s-apparmor-boot-probe (enforce)' ;;
        esac
        ;;
    /proc/version)
        case "$PROBE_CASE" in
            denial-ignored) exit 0 ;;
            wrong-error) echo 'cat: unexpected failure' >&2; exit 1 ;;
            wrong-status) echo 'cat: Permission denied' >&2; exit 127 ;;
            *) echo 'cat: Permission denied' >&2; exit 1 ;;
        esac
        ;;
    *) exit 2 ;;
esac
EOF
cat >"$WORK/bin/systemctl" <<'EOF'
#!/bin/sh
[ "$2" = apparmor.service ] || exit 2
case "$1:$PROBE_CASE" in
    is-enabled:service-enabled) echo enabled ;;
    is-enabled:service-unknown) echo not-found; exit 4 ;;
    is-enabled:*) echo disabled; exit 1 ;;
    is-active:service-active) echo active ;;
    is-active:service-state-unknown) echo unknown; exit 4 ;;
    is-active:*) echo inactive; exit 3 ;;
    *) exit 2 ;;
esac
EOF

reset_probe() {
    PROBE_CASE=good
    chmod +x "$WORK/sbin/apparmor_parser" "$WORK/usr/bin/aa-exec" "$WORK/bin/systemctl"
    printf '%s\n' 'lockdown,yama,apparmor,bpf' > "$WORK/sys/kernel/security/lsm"
    printf 'Y\n' > "$WORK/sys/module/apparmor/parameters/enabled"
    printf 'Linux test kernel\n' > "$WORK/proc/version"
    : > "$WORK/sys/kernel/security/apparmor/profiles"
    : > "$WORK/parser-calls"
    rm -f "$WORK/loaded"
}

run_enforce() {
    cmp "$SCRIPT" "$WORK/usr/local/bin/apparmor-enforce.sh" || return
    PATH=/bin:/usr/bin:/sbin chroot "$WORK" /bin/sh /usr/local/bin/apparmor-enforce.sh \
        >"$WORK/stdout" 2>"$WORK/stderr"
}

CASE="working enforcement"
reset_probe
ok "production script is byte-identical" cmp "$SCRIPT" "$WORK/usr/local/bin/apparmor-enforce.sh"
ok "production shell is byte-identical" cmp /bin/sh "$WORK/bin/sh"
ok "passes" run_enforce
ok "policy keeps the production absolute path" grep -qxF '  deny /proc/version r,' "$WORK/policy"
ok "policy contains no fixture root" not grep -qF "$WORK" "$WORK/policy"
ok "loads uncached profile" grep -qx -- '--replace --skip-cache' "$WORK/parser-calls"
ok "removes uncached profile" grep -qx -- '--remove --skip-cache' "$WORK/parser-calls"
ok "probe profile removed" test ! -e "$WORK/loaded"

for missing in absent substring; do
    CASE="$missing AppArmor LSM"
    reset_probe
    if [[ $missing == absent ]]; then
        rm "$WORK/sys/kernel/security/lsm"
    else
        printf 'lockdown,notapparmor,yama\n' > "$WORK/sys/kernel/security/lsm"
    fi
    ok "fails closed" not run_enforce
    ok "names LSM cause" stderr_has 'active LSM list'
done

CASE="disabled AppArmor module"
reset_probe
printf 'N\n' > "$WORK/sys/module/apparmor/parameters/enabled"
ok "fails closed" not run_enforce
ok "names disabled module" stderr_has 'AppArmor is disabled'

for binary in sbin/apparmor_parser usr/bin/aa-exec; do
    CASE="missing ${binary##*/}"
    reset_probe
    chmod -x "$WORK/$binary"
    ok "fails closed" not run_enforce
    ok "names missing binary" stderr_has "${binary##*/} is missing"
done

for state in service-enabled service-active service-unknown service-state-unknown; do
    CASE="$state"
    reset_probe
    PROBE_CASE=$state
    ok "fails closed" not run_enforce
    ok "names stock service" stderr_has 'apparmor.service must be'
    ok "does not load a profile" test ! -s "$WORK/parser-calls"
done

CASE="parser load failure"
reset_probe
PROBE_CASE=load-fails
ok "fails closed" not run_enforce
ok "names load failure" stderr_has 'cannot load'

for scenario in complain bad-label empty-label enter-fails denial-ignored wrong-error wrong-status; do
    CASE="$scenario"
    reset_probe
    PROBE_CASE=$scenario
    ok "fails closed" not run_enforce
    ok "failure removes profile" test ! -e "$WORK/loaded"
    ok "cleanup invoked" grep -qx -- '--remove --skip-cache' "$WORK/parser-calls"
done

CASE="unconfined control read failure"
reset_probe
rm "$WORK/proc/version"
ok "fails closed" not run_enforce
ok "names control read" stderr_has 'unconfined control read failed'
ok "failure removes profile" test ! -e "$WORK/loaded"

CASE="cleanup failure"
reset_probe
PROBE_CASE=cleanup-fails
ok "fails closed" not run_enforce
ok "names cleanup failure" stderr_has 'cannot remove'
ok "does not report success" not grep -q 'verified' "$WORK/stdout"

summarize "apparmor-enforce"
