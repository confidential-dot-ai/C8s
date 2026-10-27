#!/usr/bin/env bash
# Exercise the production runtime admission boundary in a disposable container.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
cd "$REPO_ROOT"
for tool in docker go python3; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

# Bound local daemon calls as well as downloads; this runner never uses a
# host runtime socket or bind-mounts host paths into its privileged container.
bounded() {
    python3 - "$@" <<'PY'
import subprocess
import sys

try:
    result = subprocess.run(sys.argv[2:], timeout=int(sys.argv[1]), check=False)
except subprocess.TimeoutExpired:
    raise SystemExit("command exceeded its bounded deadline: " + sys.argv[2])
raise SystemExit(result.returncode)
PY
}

work=$(mktemp -d "${TMPDIR:-/tmp}/c8s-pod-runtime.XXXXXXXX")
stage="$work/stage"
mkdir -p "$stage/runtime" "$stage/artifacts"
artifacts="${C8S_POD_RUNTIME_ARTIFACTS:-$work/artifacts}"
mkdir -p "$artifacts"
artifacts=$(cd "$artifacts" && pwd)
runtime_container=
test_container=
cleanup() {
    local status=$?
    trap - EXIT
    if [[ -n "$test_container" ]]; then
        bounded 30 docker logs "$test_container" > "$work/container.log" 2>&1 || true
        tail -c 262144 "$work/container.log" > "$artifacts/test.log"
        bounded 30 docker cp "$test_container:/validation/artifacts/." "$artifacts/" \
            >/dev/null 2>&1 || true
        bounded 30 docker inspect --format \
            '{"id":{{json .Id}},"image":{{json .Config.Image}},"privileged":{{json .HostConfig.Privileged}},"network":{{json .HostConfig.NetworkMode}},"cgroupns":{{json .HostConfig.CgroupnsMode}},"pidMode":{{json .HostConfig.PidMode}},"binds":{{json .HostConfig.Binds}},"exitCode":{{.State.ExitCode}}}' \
            "$test_container" > "$artifacts/container.json" 2>/dev/null || true
        if ! bounded 30 docker rm -f -v "$test_container" >/dev/null; then
            echo "failed to remove owned runtime-test container $test_container" >&2
            status=1
        fi
    fi
    if [[ -n "$runtime_container" ]]; then
        if ! bounded 30 docker rm -f -v "$runtime_container" >/dev/null; then
            echo "failed to remove owned runtime-source container $runtime_container" >&2
            status=1
        fi
    fi
    if [[ "$status" == 0 ]]; then
        printf '{"removed":true}\n' > "$artifacts/cleanup.json"
    fi
    echo "Pod runtime artifacts: $artifacts"
    # Keep the default artifacts; binaries and staged source are disposable.
    rm -rf "$stage"
    rm -f "$work/container.log"
    if [[ "$artifacts" != "$work/artifacts" ]]; then
        rmdir "$work" 2>/dev/null || true
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Never mix a failed invocation with receipts from an earlier successful run.
python3 - "$artifacts" <<'PY'
import sys
from pathlib import Path

if any(Path(sys.argv[1]).iterdir()):
    raise SystemExit("runtime artifacts directory must be empty; use a new directory")
PY

arch=$(bounded 30 docker version --format '{{.Server.Arch}}')
python3 "$SCRIPT_DIR/fixtures.py" prepare "$REPO_ROOT" "$stage" "$arch"
input() {
    python3 - "$stage/inputs.json" "$1" <<'PY'
import json
import sys

print(json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]])
PY
}
runtime_image=$(input runtimeImage)
runner_image=$(input runnerImage)
cp "$stage/inputs.json" "$artifacts/inputs.json"

echo "Building Linux/$arch runtime test binaries"
bounded 300 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 \
    go build -o "$stage/c8s-runc" ./cmd/c8s-runc
bounded 300 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 \
    go build -o "$stage/marker-workload" ./test/integration/pod-runtime/workload
bounded 300 env GOOS=linux GOARCH="$arch" CGO_ENABLED=0 \
    go test -tags pod_runtime_integration -c -o "$stage/nri-runtime.test" \
    ./internal/cmds/nri-image-policy
python3 "$SCRIPT_DIR/fixtures.py" image "$stage" "$arch"
cp "$SCRIPT_DIR/inside.sh" "$stage/inside.sh"

for image in "$runtime_image" "$runner_image"; do
    if ! bounded 30 docker image inspect "$image" >/dev/null 2>&1; then
        bounded 300 docker pull --platform "linux/$arch" "$image"
    fi
    actual=$(bounded 30 docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")
    [[ "$actual" == "linux/$arch" ]] || {
        echo "image platform mismatch: expected linux/$arch, got $actual" >&2
        exit 1
    }
done

runtime_container=$(bounded 30 docker create --platform "linux/$arch" \
    --label confidential.ai/pod-runtime-source=1 \
    --entrypoint /bin/true "$runtime_image")
for binary in containerd containerd-shim-runc-v2 runc ctr; do
    bounded 30 docker cp "$runtime_container:/bin/$binary" "$stage/runtime/$binary"
    chmod 0755 "$stage/runtime/$binary"
done
bounded 30 docker rm -v "$runtime_container" >/dev/null
runtime_container=

# Existing policy-rendering test helpers read these public source fixtures.
for file in node-guest-image/c8s/image-policy.yaml.in \
    internal/helmchart/c8s/templates/router-helpers.tpl \
    internal/testdata/node-identities.json; do
    mkdir -p "$stage/source/$(dirname "$file")"
    cp "$file" "$stage/source/$file"
done
mkdir -p "$stage/source/internal/cmds/nri-image-policy"
python3 - "$stage" "$artifacts/runtime-binaries.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

stage = Path(sys.argv[1])
files = sorted((stage / "runtime").iterdir()) + [stage / "c8s-runc", stage / "nri-runtime.test"]
records = {}
for path in files:
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    records[str(path.relative_to(stage))] = {"sha256": digest, "size": path.stat().st_size}
Path(sys.argv[2]).write_text(json.dumps(records, indent=2) + "\n")
PY

test_container=$(bounded 30 docker create --platform "linux/$arch" \
    --label confidential.ai/pod-runtime-test=1 \
    --privileged --network none --cgroupns private --cpus 2 --memory 2g \
    --pids-limit 512 --log-opt max-size=1m --log-opt max-file=1 \
    --env C8S_POD_RUNTIME_ISOLATED=1 --env "C8S_POD_RUNTIME_ARCH=$arch" \
    --entrypoint /bin/bash "$runner_image" \
    -c 'exec timeout --signal=TERM --kill-after=10s 180s bash /validation/inside.sh')
bounded 60 docker cp "$stage/." "$test_container:/validation"
bounded 220 docker start -a "$test_container"

python3 - "$test_container" <<'PY'
import subprocess
import sys

state = subprocess.check_output(
    ["docker", "inspect", "--format", "{{.State.ExitCode}}", sys.argv[1]], timeout=30
).decode().strip()
if state != "0":
    raise SystemExit("runtime-test container exited with " + state)
PY

# A successful test command that matched no tests must still fail this lane.
# Copy into this invocation's private staging tree, never trust old artifacts.
bounded 30 docker cp "$test_container:/validation/artifacts/result.json" "$stage/result.json"
python3 "$SCRIPT_DIR/fixtures.py" receipt "$stage/inputs.json" "$stage/result.json"
