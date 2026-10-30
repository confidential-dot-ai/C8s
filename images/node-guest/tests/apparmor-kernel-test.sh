#!/usr/bin/env bash
# Real parser/kernel test under systemd in a disposable privileged container.
# The kernel is the Docker host's, userspace is the confos Ubuntu release.
# This supplements the actual node-image TDX E2E; it does not boot that image.
set -euo pipefail
: "${CONFOS_RELEASE:?set CONFOS_RELEASE to the pinned confos Ubuntu release}"
tests_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
image="c8s-apparmor-test-$$"
container=""
namespace=""
namespace_created=0
image_created=0
cleanup() {
    local result=$?
    if [ "$namespace_created" = 1 ]; then
        docker exec "$container" rmdir "/sys/kernel/security/apparmor/policy/namespaces/$namespace" || result=1
    fi
    if [ -n "$container" ]; then docker rm -f "$container" >/dev/null || result=1; fi
    if [ "$image_created" = 1 ]; then docker image rm "$image" >/dev/null || result=1; fi
    return "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
docker build -q -t "$image" --build-arg "RELEASE=$CONFOS_RELEASE" - <<'EOF'
ARG RELEASE
FROM ubuntu:${RELEASE}
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    systemd systemd-sysv apparmor && systemctl disable apparmor.service
CMD ["/sbin/init"]
EOF
image_created=1
container=$(docker run -d --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock "$image")
namespace="c8s-boot-test-${container:0:12}"
for _ in $(seq 1 30); do
    state=$(docker exec "$container" systemctl is-system-running 2>/dev/null || true)
    case "$state" in running|degraded) break ;; esac
    sleep 1
done
case "$state" in running|degraded) ;; *) echo "systemd not ready: $state" >&2; exit 1 ;; esac
docker cp "$tests_dir/../c8s/mkosi.extra/usr/local/bin/apparmor-enforce.sh" "$container:/probe.sh"
# Mount securityfs privately. The probe uses a unique AppArmor namespace so
# its transient policy cannot replace a policy on the Docker host.
docker exec "$container" sh -ec '
    mountpoint -q /sys/kernel/security || mount -t securityfs securityfs /sys/kernel/security
    test -d /sys/kernel/security/apparmor
'
docker exec "$container" mkdir "/sys/kernel/security/apparmor/policy/namespaces/$namespace"
namespace_created=1
# aa-exec can enter a policy namespace with no profile change. Kernel securityfs
# then presents that namespace while the actual production script runs unchanged.
docker exec "$container" aa-exec -n "$namespace" -- /bin/sh /probe.sh
echo "PASS: production boot probe with real AppArmor kernel/parser and systemd"
