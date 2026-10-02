#!/usr/bin/env bash
# Exercise the pinned initrd with real mounts, without booting a CVM. Hardware
# discovery and switch_root are shims; the production init/finalizer stay intact.
set -euo pipefail
export LC_ALL=C

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    if [ -f /command.log ]; then cat /command.log >&2; fi
    exit 1
}

run_checked() {
    if ! timeout --signal=KILL 30s "$@" >/command.log 2>&1; then
        fail "command failed: $*"
    fi
}

snapshot_image() {
    # NUL-delimited records cover names, types, modes, owners, symlinks and
    # file contents, but ignore timestamps changed by reading the fixture.
    find /image -mindepth 1 -print0 | sort -z |
        while IFS= read -r -d '' path; do
            stat --printf='%n\0%f\0%u\0%g\0' -- "$path"
            if [ -L "$path" ]; then
                readlink -z -- "$path"
            elif [ -f "$path" ]; then
                sha256sum --zero -- "$path"
            fi
        done
}

run_test_case() {
    local test_case=$1 path directory status
    [ -f /c8s-immutable-test-root ] || fail "test case requires the isolated root"
    case "$test_case" in
        declared-state|missing-state-directory) ;;
        *) fail "unknown test case: $test_case" ;;
    esac
    cp -a /image-template /image
    # Package-created base dirs and sync-created C8s paths. The invariant
    # gate separately checks mkosi.sync creates CNI/NRI directories; do not
    # derive these from state.d, which would hide missing build-time dirs.
    for directory in var home root tmp run etc \
        etc/rancher/rke2/config.yaml.d etc/cni/net.d opt/cni/bin \
        etc/nri/conf.d opt/nri/plugins usr/lib/c8s; do
        mkdir -p "/image/$directory"
    done
    chmod 0700 /image/root
    chmod 1777 /image/tmp
    cp /nri-floor-template /image/usr/lib/c8s/image-policy.yaml
    printf 'baked plugin fixture\n' > /image/opt/nri/plugins/10-nri-image-policy
    # Finalize after composing every profile, including /etc/confai's symlink.
    run_checked env BUILDROOT=/image /bin/bash /finalize-under-test
    [ "$(readlink /image/etc/confai)" = ../run/confai ] || fail "/etc/confai target"
    : > /proc/sysrq-trigger

    if [ "$test_case" = missing-state-directory ]; then
        # This is an unmounted fixture directory inside the private chroot.
        mv /image/etc/cni /removed-cni
    fi
    snapshot_image > /image-before

    if [ "$test_case" = declared-state ]; then
        run_checked /bin/bash /init-under-test
        printf '/sysroot\n/sbin/init\n' > /expected
        cmp /expected /switch-root-args || fail "switch_root arguments"
        : > /expected
        cmp /expected /proc/sysrq-trigger || fail "successful init changed sysrq trigger"
        printf 'runtime state\n' > /expected
        # Launch preparation derives the runtime floor from the immutable template.
        cp /sysroot/usr/lib/c8s/image-policy.yaml /sysroot/etc/nri/conf.d/image-policy.yaml
        # Exercise atomic replacement of the staged floor and node state.
        for path in \
            etc/rancher/rke2/config.yaml.d/95-gpu-resources.yaml \
            etc/rancher/node/password etc/cni/net.d/10-canal.conflist \
            opt/cni/bin/calico etc/nri/conf.d/image-policy.yaml \
            var/lib/rancher/rke2/server/token run/immutable-root-test; do
            path="/sysroot/$path"
            mkdir -p "${path%/*}"
            printf 'runtime state\n' > "$path.new"
            mv -T -- "$path.new" "$path"
            cmp /expected "$path" || fail "runtime write: $path"
        done
        for path in usr/local/bin/immutable-root-test \
            opt/nri/plugins/10-nri-image-policy usr/lib/c8s/image-policy.yaml \
            etc/hostname etc/undeclared; do
            if { printf 'must not modify the image\n' > "/sysroot/$path"; } 2>/write-error; then
                fail "undeclared path is writable: $path"
            fi
            # Bash reports errno through this C-locale diagnostic. Reject an
            # unrelated failure (missing path, permission denied, etc.).
            grep -Fq 'Read-only file system' /write-error || fail "expected EROFS: $path"
        done
        for directory in root tmp; do
            [ "$(stat -c %a "/sysroot/$directory")" = "$(stat -c %a "/image/$directory")" ] \
                || fail "directory mode changed: $directory"
        done
    else
        status=0
        timeout --signal=KILL 30s /bin/bash /init-under-test >/command.log 2>&1 || status=$?
        [ "$status" -eq 1 ] || fail "missing state directory: expected exit 1, got $status"
        grep -Fq 'FATAL: state.d: etc/cni listed in 60-c8s.conf' /command.log \
            || fail "missing state directory diagnostic"
        [ ! -e /switch-root-args ] || fail "missing state directory reached switch_root"
        printf 'b\n' > /expected
        cmp /expected /proc/sysrq-trigger || fail "missing state directory did not request reboot"
    fi
    snapshot_image > /image-after
    cmp /image-before /image-after || fail "lower image changed"
    printf 'PASS: %s\n' "$test_case"
}

if [ "${1:-}" = --inside-test-root ]; then
    run_test_case "${2:?missing test case}"
    exit 0
fi
test_script=$(realpath "${BASH_SOURCE[0]}")
ngi_dir=$(cd "$(dirname "$test_script")/.." && pwd)
CONFOS_DIR=$(realpath "${CONFOS_DIR:-$ngi_dir/../confos}")
export CONFOS_DIR

if [ "$EUID" -ne 0 ] || [ "$(uname -s)" != Linux ]; then
    echo "immutable-root-test.sh requires root on Linux with mount namespace/overlay support" >&2
    exit 1
fi
if [ "${1:-}" != --private-mount-namespace ]; then
    # Each case gets a fresh namespace, so failed boot mounts never leak into
    # another case. Cleanup runs outside chroot with the real /proc mount table.
    for test_case in declared-state missing-state-directory; do
        unshare --mount --propagation private /bin/bash "$test_script" \
            --private-mount-namespace "$test_case"
    done
    exit 0
fi

fixture_root=$(mktemp -d)
cleanup() {
    local status=$?
    trap - EXIT
    # Never recursively remove a fixture while it contains host bind mounts.
    if mountpoint -q "$fixture_root"; then
        if ! umount -R "$fixture_root"; then
            echo "Failed to unmount test root: $fixture_root" >&2
            exit 1
        fi
    fi
    rmdir "$fixture_root"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mount -t tmpfs tmpfs "$fixture_root"
mkdir -p "$fixture_root"/{usr,dev,proc,sys,run,tmp,image-template}
mount --bind /usr "$fixture_root/usr"
mount -o remount,bind,ro "$fixture_root/usr"
# /usr stays read-only; this private tmpfs supplies only hardware boundary shims.
mount -t tmpfs tmpfs "$fixture_root/usr/sbin"
for directory in bin sbin lib; do
    ln -s "usr/$directory" "$fixture_root/$directory"
done
if [ -d /usr/lib64 ]; then
    ln -s usr/lib64 "$fixture_root/lib64"
fi
touch "$fixture_root/c8s-immutable-test-root" "$fixture_root/dev/null" "$fixture_root/dev/vda2"
mount --bind /dev/null "$fixture_root/dev/null"
printf 'roothash=%064d\n' 0 > "$fixture_root/proc/cmdline"
# A fail-closed boot can only write this ordinary fixture file, never host sysrq.
touch "$fixture_root/proc/sysrq-trigger"

base="$CONFOS_DIR/mkosi/base"
for extra in "$base/mkosi.extra" \
    "$base/mkosi.profiles/gpu/mkosi.extra" \
    "$base/mkosi.profiles/attest-gpu/mkosi.extra" \
    "$ngi_dir/c8s/mkosi.extra"; do
    cp -a "$extra/." "$fixture_root/image-template/"
done
cp "$ngi_dir/c8s/image-policy.yaml.in" "$fixture_root/nri-floor-template"
cp "$base/mkosi.finalize" "$fixture_root/finalize-under-test"
cp "$CONFOS_DIR/mkosi/initrd/mkosi.extra/init" "$fixture_root/init-under-test"
cp "$test_script" "$fixture_root/tests.sh"

cat > "$fixture_root/usr/sbin/veritysetup" <<'SHIM'
#!/bin/bash
exit 0
SHIM
cat > "$fixture_root/usr/sbin/blkid" <<'SHIM'
#!/bin/bash
# No operator-key or scratch disk: exercise the real tmpfs state fallback.
exit 1
SHIM
cat > "$fixture_root/usr/sbin/mount" <<'SHIM'
#!/bin/bash
set -euo pipefail
case "$*" in
    "-t proc proc /proc"|"-t sysfs sysfs /sys"|"-t devtmpfs devtmpfs /dev")
        exit 0 ;;
    "-o ro /dev/mapper/root /sysroot")
        /usr/bin/mount --bind /image /sysroot
        exec /usr/bin/mount -o remount,bind,ro /sysroot ;;
    *)
        exec /usr/bin/mount "$@" ;;
esac
SHIM
cat > "$fixture_root/usr/sbin/switch_root" <<'SHIM'
#!/bin/bash
printf '%s\n' "$@" > /switch-root-args
SHIM
chmod +x "$fixture_root"/usr/sbin/*
chroot "$fixture_root" /bin/bash /tests.sh --inside-test-root "${2:?missing test case}"
