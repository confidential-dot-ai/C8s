#!/usr/bin/env bash
# Runs only inside run.sh's disposable, privately namespaced container.
set -euo pipefail

[[ "${C8S_POD_RUNTIME_ISOLATED:-}" == 1 ]] || {
    echo "use test/integration/pod-runtime/run.sh" >&2
    exit 2
}
[[ "$(id -u)" == 0 && -f /validation/inputs.json ]] || exit 2
mkdir -p /validation/artifacts
: > /validation/isolated

runtime_pid=
finish() {
    local status=$?
    trap - EXIT
    if [[ -n "$runtime_pid" ]]; then
        kill "$runtime_pid" 2>/dev/null || true
        wait "$runtime_pid" 2>/dev/null || true
    fi
    if [[ -f /validation/containerd.log ]]; then
        tail -c 262144 /validation/containerd.log > /validation/artifacts/containerd.log
    fi
    exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Delegate only this container's private cgroup root to its nested runtime.
mkdir -p /sys/fs/cgroup/pod-runtime-init
# Snapshot before moving: cgroup.procs changes as entries leave, so streaming it
# while moving both timeout and this shell can skip a remaining root process.
mapfile -t nested_pids < /sys/fs/cgroup/cgroup.procs
for nested_pid in "${nested_pids[@]}"; do
    printf '%s\n' "$nested_pid" > /sys/fs/cgroup/pod-runtime-init/cgroup.procs
done
read -r -a controllers < /sys/fs/cgroup/cgroup.controllers
for controller in "${controllers[@]}"; do
    printf '+%s\n' "$controller" > /sys/fs/cgroup/cgroup.subtree_control
done

mkdir -p /run/c8s-pod /validation/empty-plugins /validation/empty-config
mkdir -p /var/lib/rancher/rke2/bin
install -m 0755 /validation/runtime/runc /var/lib/rancher/rke2/bin/runc
export PATH="/validation/runtime:$PATH"

{
    containerd --version
    runc --version
} > /validation/artifacts/runtime-versions.txt
runc --help > /validation/artifacts/runc-help.txt

cat > /validation/containerd.toml <<'TOML'
version = 3
root = '/var/lib/pod-start-test'
state = '/run/pod-start-test'
[grpc]
address = '/run/pod-start-test/containerd.sock'
[plugins.'io.containerd.cri.v1.images']
snapshotter = 'native'
[plugins.'io.containerd.cri.v1.images'.pinned_images]
sandbox = 'example.invalid/pod-start:fixture'
[plugins.'io.containerd.cri.v1.runtime']
disable_apparmor = true
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]
runtime_type = 'io.containerd.runc.v2'
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]
BinaryName = '/validation/c8s-runc'
SystemdCgroup = false
[plugins.'io.containerd.nri.v1.nri']
disable = false
socket_path = '/run/pod-start-test/nri.sock'
plugin_path = '/validation/empty-plugins'
plugin_config_path = '/validation/empty-config'
plugin_registration_timeout = '5s'
plugin_request_timeout = '500ms'
[plugins.'io.containerd.nri.v1.nri'.default_validator]
enable = false
TOML

containerd --config /validation/containerd.toml > /validation/containerd.log 2>&1 &
runtime_pid=$!
ready=0
for _ in $(seq 1 100); do
    if ctr --address /run/pod-start-test/containerd.sock version > /dev/null 2>&1; then
        ready=1
        break
    fi
    kill -0 "$runtime_pid" || exit 1
    sleep 0.1
done
[[ "$ready" == 1 ]] || { echo "containerd did not become ready" >&2; exit 1; }
ctr --address /run/pod-start-test/containerd.sock --namespace k8s.io \
    images import --local --platform "linux/$C8S_POD_RUNTIME_ARCH" \
    --snapshotter native /validation/fixtures.tar

cd /validation/source/internal/cmds/nri-image-policy
/validation/nri-runtime.test -test.v -test.timeout=120s \
    -test.run '^TestPodRuntimeAdmissionIntegration$'
