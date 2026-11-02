#!/usr/bin/env bash
set -euo pipefail
# Private mount namespace; detach only the loop devices this invocation created.
if [[ "${RECOVERY_MOUNT_NAMESPACE:-}" != 1 ]]; then
    exec unshare --mount --propagation private env RECOVERY_MOUNT_NAMESPACE=1 bash "$0" "$@"
fi
old=$1 new=$2 fixture=$3 work=$4
loops=()
mounts=()
cleanup() {
    local m l
    for m in "${mounts[@]}"; do umount "$m" || true; done
    for l in "${loops[@]}"; do losetup -d "$l" || true; done
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
for side in old new; do
    disk=$old
    [[ "$side" != new ]] || disk=$new
    loop=$(losetup -Pfr --show "$disk")
    loops+=("$loop")
    m="$work/mount-$side"
    mkdir -p "$m"
    found=false
    for part in "$loop"p*; do
        [[ "$(blkid -o value -s TYPE "$part" || true)" = erofs ]] || continue
        mount -o ro "$part" "$m"
        if [[ -f "$m/usr/local/bin/c8s" ]]; then found=true; mounts+=("$m"); break; fi
        umount "$m"
    done
    [[ "$found" == true ]]
done

# Compare actual immutable production bytes before publishing the fixture.
old_root="$work/mount-old" new_root="$work/mount-new"
digest() { sha256sum "$1" | cut -d' ' -f1; }
fail() { echo "$1" >&2; exit 1; }
hashes="$work/production-hashes.tsv"
: > "$hashes"
for item in usr/local/bin/c8s usr/local/bin/c8s-runc opt/nri/plugins/10-nri-image-policy \
    usr/lib/c8s \
    etc/systemd/system/podcvm-status.service etc/systemd/system/podcvm-kubelet.service \
    etc/systemd/system/podcvm-containerd.service etc/systemd/system/rke2-role.service \
    etc/attestation-api/config.toml usr/lib/confai/state.d/60-c8s.conf; do
    source="$old_root/$item"
    [[ -e "$source" || -L "$source" ]] || fail "baseline production path is missing: $item"
    if [[ -d "$source" && ! -L "$source" ]]; then
        members=$(cd "$old_root" && find "$item" -mindepth 1 | LC_ALL=C sort)
        [[ "$members" == "$(cd "$new_root" && find "$item" -mindepth 1 | LC_ALL=C sort)" ]] || fail 'production runtime file list changed'
    else
        members=$item
    fi
    while IFS= read -r relative; do
        path="$old_root/$relative" target="$new_root/$relative"
        if [[ -L "$path" ]]; then
            [[ -L "$target" && "$(readlink "$path")" == "$(readlink "$target")" ]] || fail "production symlink changed: $relative"
        elif [[ -f "$path" ]]; then
            [[ ! -L "$target" && -f "$target" && "$(stat -c %f "$path")" == "$(stat -c %f "$target")" ]] || fail "production bytes changed: $relative"
            sum=$(digest "$path")
            [[ "$sum" == "$(digest "$target")" ]] || fail "production bytes changed: $relative"
            printf '%s\t%s\n' "$relative" "$sum" >> "$hashes"
        fi
    done <<< "$members"
done
for forbidden in etc/systemd/system/serial-getty@ttyS0.service.d etc/ssh/sshd_config \
    var/lib/rancher/rke2/agent/etc/containerd/config-v3.toml.d/60-dev-runc.toml; do
    [[ ! -e "$new_root/$forbidden" ]] || fail 'debug profile detected'
done
controller=usr/local/libexec/pod-recovery-fixture
[[ ! -e "$old_root/$controller" && "$(digest "$new_root/$controller")" == "$(digest "$work/pod-recovery/mkosi.extra/$controller")" ]] || fail 'test controller provenance differs'
jq -S -R -n --arg controller "$(digest "$new_root/$controller")" \
    '{baseline: "05211a8b106415a0aefd5f47bc40b266b0c1dacd", controllerSHA256: $controller,
      files: ([inputs | split("\t") | {key: .[0], value: .[1]}] | from_entries)}' "$hashes" > "$work/runtime-components.json"
