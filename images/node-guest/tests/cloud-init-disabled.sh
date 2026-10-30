#!/bin/bash
# Runs the cloud-init the node image actually ships — cloud-init-base from the
# Ubuntu release the pinned confos base builds on — against the baked
# /etc/cloud/cloud-init.disabled marker.
#
# Needs network and a private mount namespace: ds-identify and the units read
# the marker at an absolute path, so it is mounted over /etc/cloud rather than
# written to the runner. The "FAIL:" prefix matches tests/lib.sh.
set -uo pipefail

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
NGI_DIR=$(dirname "$TESTS_DIR")
CONFOS_CONF=${CONFOS_CONF:-confos/mkosi/base/mkosi.conf}
MARKER=/etc/cloud/cloud-init.disabled

# A host that owns the cmdline gets every channel at once: ds= pins a
# datasource, cc:/end_cc and cloud-config-url= inject cloud-config outright.
HOSTILE='BOOT_IMAGE=/vmlinuz ds=nocloud cloud-init=enabled cloud-config-url=file:///dev/vdb'

# The one thing the gate takes from confos is the release its base builds on.
# CONFOS_RELEASE carries it directly; otherwise it is read from a checkout.
REL=${CONFOS_RELEASE:-}
if [[ -z $REL ]]; then
    [[ -f "$CONFOS_CONF" ]] || { echo "confos base mkosi.conf not found: $CONFOS_CONF (set CONFOS_RELEASE or CONFOS_CONF)"; exit 2; }
    REL=$(sed -n 's/^Release=[[:space:]]*//p' "$CONFOS_CONF" | head -1)
    [[ -n $REL ]] || { echo "no Release= in $CONFOS_CONF"; exit 2; }
fi

if [[ ${IN_NS:-} != 1 ]]; then
    mkdir -p /etc/cloud 2>/dev/null
    for ns in -m -rm; do
        unshare $ns true 2>/dev/null && exec env IN_NS=1 unshare $ns -- "$0" "$@"
    done
    echo "need a private mount namespace: run as root, or enable unprivileged user namespaces"
    exit 2
fi

PASS=0; FAIL=0
ok() { # ok DESC cmd...
    local desc="$1"; shift
    if "$@"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "  FAIL: $desc"; fi
}

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

# --- the marker is in the tree mkosi bakes into the verity root -------------
ok "the c8s profile bakes $MARKER" \
    test -f "$NGI_DIR/c8s/mkosi.extra${MARKER}"

# --- fetch the exact cloud-init the image installs --------------------------
DEB=""
for pocket in "$REL-updates" "$REL"; do
    idx="http://archive.ubuntu.com/ubuntu/dists/$pocket/main/binary-amd64/Packages.gz"
    curl -fsSL --retry 3 "$idx" -o "$WORK/Packages.gz" 2>/dev/null || continue
    f=$(zcat "$WORK/Packages.gz" | awk '/^Package: cloud-init-base$/,/^$/' |
        sed -n 's/^Filename: //p' | head -1)
    [[ -n $f ]] && { DEB=$f; break; }
done
[[ -n $DEB ]] || { echo "no cloud-init-base in the $REL archive"; exit 2; }
curl -fsSL --retry 3 "http://archive.ubuntu.com/ubuntu/$DEB" -o "$WORK/ci.deb" || exit 2
dpkg-deb -x "$WORK/ci.deb" "$WORK/ci" || exit 2
echo "cloud-init-base from $REL: $(basename "$DEB")"

SYSD=$WORK/ci/usr/lib/systemd/system
DSID=$WORK/ci/usr/lib/cloud-init/ds-identify
ok "the package ships ds-identify" test -x "$DSID"

# --- nothing cloud-init can execute survives the marker ---------------------
# The marker is systemd's gate, not cloud-init's: a unit condition cannot be
# outranked from the cmdline, unlike anything in /etc/cloud/cloud.cfg.d.
shopt -s nullglob
units=("$SYSD"/*)
ok "the package ships units" test "${#units[@]}" -gt 0
for u in "${units[@]}"; do
    n=$(basename "$u")
    if grep -qE '^(ExecStart=|\[Socket\])' "$u"; then
        ok "$n is gated on the marker" \
            grep -qxF "ConditionPathExists=!$MARKER" "$u"
    else
        ok "$n runs nothing, so needs no gate" test "${n##*.}" = target
    fi
done

# --- ds-identify: the marker outranks every cmdline channel -----------------
di() { # di -> rc; leaves the run dir at $WORK/run
    rm -rf "$WORK/run" "$WORK/root/run"
    mkdir -p "$WORK/root/proc" "$WORK/root/sys/class/dmi/id" "$WORK/run"
    printf '%s\n' "$HOSTILE" > "$WORK/root/proc/cmdline"
    printf '100.0 100.0\n' > "$WORK/root/proc/uptime"
    printf 'ds=nocloud;s=http://169.254.169.254/\n' \
        > "$WORK/root/sys/class/dmi/id/product_serial"
    PATH_ROOT="$WORK/root" PATH_RUN="$WORK/run" PATH_RUN_CI="$WORK/run/cloud-init" \
    PATH_RUN_CI_CFG="$WORK/run/cloud-init/cloud.cfg" \
    PATH_RUN_DI_RESULT="$WORK/run/cloud-init/.ds-identify.result" \
        sh "$DSID" >/dev/null 2>&1
}

# Unmarked first: ds-identify must really honour the hostile cmdline, or the
# marked arm below proves nothing.
mount -t tmpfs tmpfs /etc/cloud
di; rc=$?
ok "unmarked: the cmdline datasource is honoured (rc=0, got $rc)" test "$rc" = 0
ok "unmarked: /run/cloud-init/cloud.cfg names the host's datasource" \
    grep -q 'nocloud' "$WORK/run/cloud-init/cloud.cfg"

: > "$MARKER"
di; rc=$?
ok "marked: ds-identify reports disabled (rc=2, got $rc)" test "$rc" = 2
ok "marked: no /run/cloud-init/cloud.cfg to outrank /etc/cloud/cloud.cfg.d" \
    test ! -e "$WORK/run/cloud-init/cloud.cfg"

echo "==== cloud-init disabled ===="
echo "PASS: $PASS  FAIL: $FAIL"
(( FAIL == 0 ))
