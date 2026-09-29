#!/bin/bash
# Shared Linux-only fixtures for the production launch script and real systemd
# harnesses. These stub device I/O and the c8s command boundary; Go tests own
# signatures, image/key verification, strict parsing and credential staging.

C8S_ROLE_FIXTURE=/tmp/c8s-role-fixture
export C8S_ROLE_FIXTURE

install_launch_stubs() {
    local bindir=$1
    mkdir -p "$bindir" "$C8S_ROLE_FIXTURE/media"
    cat > "$bindir/udevadm" <<'STUB'
#!/bin/bash
set -euo pipefail
[[ "$*" == 'settle --timeout=10' ]]
[[ ! -e "$C8S_ROLE_FIXTURE/udev-fails" ]]
STUB
    cat > "$bindir/blkid" <<'STUB'
#!/bin/bash
set -euo pipefail
[[ "$*" == '-L opkeydata' ]]
printf '%s\n' "$*" > "$C8S_ROLE_FIXTURE/blkid-args"
[[ -f "$C8S_ROLE_FIXTURE/disk-present" ]]
printf '%s\n' '/dev/test launch disk'
STUB
    cat > "$bindir/mount" <<'STUB'
#!/bin/bash
set -euo pipefail
[[ $# == 6 && $1 == -t && $2 == iso9660 && $3 == -o && $4 == ro,nodev,nosuid,noexec && $5 == '/dev/test launch disk' ]]
[[ ! -e "$C8S_ROLE_FIXTURE/mount-fails" ]]
printf '%s\n' "$@" > "$C8S_ROLE_FIXTURE/mount-args"
cp -a "$C8S_ROLE_FIXTURE/media/." "$6/"
STUB
    cat > "$bindir/umount" <<'STUB'
#!/bin/bash
set -euo pipefail
[[ $# == 1 && $1 == /run/confos/launch-disk.* ]]
rm -f "$1/launch.yaml" "$1/launch.yaml.sig"
: > "$C8S_ROLE_FIXTURE/unmounted"
STUB
    cat > "$bindir/timeout" <<'STUB'
#!/bin/bash
set -euo pipefail
[[ $1 == 10 ]]
shift
[[ $1 == mount ]]
: > "$C8S_ROLE_FIXTURE/mount-bounded"
[[ ! -e "$C8S_ROLE_FIXTURE/mount-times-out" ]] || exit 124
exec "$@"
STUB
    cat > "$bindir/c8s" <<'STUB'
#!/bin/bash
set -euo pipefail
case "$1 $2" in
'launch-config stage')
    [[ $# == 5 && $3 == --platform=tdx || $# == 5 && $3 == --platform=snp ]]
    [[ $4 == --config=/run/confos/launch-disk.*/launch.yaml ]]
    [[ $5 == --signature=/run/confos/launch-disk.*/launch.yaml.sig ]]
    printf '%s\n' "$@" > "$C8S_ROLE_FIXTURE/stage-args"
    config=${4#--config=}
    signature=${5#--signature=}
    [[ -f "$config" && -f "$signature" ]]
    [[ $(cat "$signature") == valid-test-signature ]]
    rm -f /run/confos/role-server /run/confos/role-agent
    case "$(cat "$config")" in
        server)
            # Real staging writes the agent enrollment policy only when the
            # signed document authorizes agents; the fixture mirrors that so
            # the release unit's condition is exercised both ways.
            mkdir -p /run/confos/launch
            if [[ ! -e "$C8S_ROLE_FIXTURE/no-agents" ]]; then
                printf '%s\n' '{"test":"authorized-agents"}' > /run/confos/launch/agents.json
            fi
            : > /run/confos/role-server
            ;;
        agent) : > /run/confos/role-agent ;;
        *) exit 31 ;;
    esac
    ;;
'node-services prepare')
    [[ $# == 2 ]]
    [[ -f /run/confos/role-server || -f /run/confos/role-agent ]]
    [[ ! -e "$C8S_ROLE_FIXTURE/prepare-fails" ]]
    : > "$C8S_ROLE_FIXTURE/prepared"
    ;;
*) exit 32 ;;
esac
STUB
    chmod +x "$bindir"/{udevadm,blkid,mount,umount,timeout,c8s}
}

reset_launch_fixture() {
    rm -rf "$C8S_ROLE_FIXTURE" /run/confos
    mkdir -p "$C8S_ROLE_FIXTURE/media" /run/confos
}

launch_media() {
    printf '%s\n' "$1" > "$C8S_ROLE_FIXTURE/media/launch.yaml"
    printf '%s\n' valid-test-signature > "$C8S_ROLE_FIXTURE/media/launch.yaml.sig"
    : > "$C8S_ROLE_FIXTURE/disk-present"
}

no_launch_markers() { [[ ! -e /run/confos/role-server && ! -e /run/confos/role-agent ]]; }
