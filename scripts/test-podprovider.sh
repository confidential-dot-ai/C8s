#!/usr/bin/env bash
# Run the real scheduler/provider integration in an owned disposable kind cluster.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
for tool in go docker kind python3; do
    command -v "$tool" >/dev/null || { echo "required tool missing: $tool" >&2; exit 1; }
done
if command -v timeout >/dev/null; then
    deadline=timeout
elif command -v gtimeout >/dev/null; then
    deadline=gtimeout
else
    echo 'GNU timeout is required (timeout or gtimeout)' >&2
    exit 1
fi

# Reuse the cluster harness pin; unrelated C8S_IT_* settings cannot select this run.
C8S_IT_NODE_IMAGE="${C8S_PODPROVIDER_NODE_IMAGE:-}"
C8S_IT_CLUSTER=""
source ./test/integration/cluster/lib.sh
node_image="$NODE_IMAGE"
if [[ ! "$node_image" =~ @sha256:[[:xdigit:]]{64}$ ]]; then
    echo 'the kind node image must be pinned by sha256 digest' >&2
    exit 1
fi

scratch="$(mktemp -d "${TMPDIR:-/tmp}/c8s-podprovider.XXXXXXXX")"
# kind must never read or update the developer's default kubeconfig.
export KUBECONFIG="$scratch/kubeconfig"
cluster="c8s-podprovider-$(date +%s)-$$"
node=""
owned=false
artifacts="${C8S_PODPROVIDER_ARTIFACTS:-$repo_root/target/podprovider-integration/$cluster}"
mkdir -p "$artifacts"
artifacts="$(cd "$artifacts" && pwd)"
if [[ -n "$(ls -A "$artifacts")" ]]; then
    echo 'scheduler evidence directory must be empty; use a new path for each run' >&2
    rmdir "$scratch"
    exit 1
fi

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [ "$owned" = true ]; then
        if [ -n "$node" ]; then
            "$deadline" 15 docker exec "$node" kubectl --kubeconfig=/etc/kubernetes/admin.conf \
                get nodes -o wide > "$artifacts/nodes.txt" 2>&1 || true
            "$deadline" 15 docker exec "$node" kubectl --kubeconfig=/etc/kubernetes/admin.conf \
                -n tenant get pods -o wide > "$artifacts/pods.txt" 2>&1 || true
            "$deadline" 15 docker exec "$node" kubectl --kubeconfig=/etc/kubernetes/admin.conf \
                -n tenant get events --sort-by=.lastTimestamp 2>&1 | tail -100 > "$artifacts/events.txt" || true
            for receipt in result.json lifecycle-result.json; do
                "$deadline" 15 docker cp "$node:/podprovider-test/artifacts/$receipt" "$artifacts/$receipt" 2>/dev/null || true
            done
        fi
        if ! "$deadline" 60 kind delete cluster --name "$cluster"; then
            echo "failed to clean up owned kind cluster $cluster" >&2
            status=1
        fi
    fi
    rm -rf "$scratch"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker_arch="$("$deadline" 15 docker version --format '{{.Server.Arch}}')"
case "$docker_arch" in
    amd64|arm64) ;;
    *) echo "unsupported Docker architecture: $docker_arch" >&2; exit 1 ;;
esac
"$deadline" 600 env GOOS=linux GOARCH="$docker_arch" CGO_ENABLED=0 go test -c \
    -tags podprovider_integration -o "$scratch/provider.test" ./internal/podprovider

existing="$("$deadline" 15 kind get clusters)"
if printf '%s\n' "$existing" | grep -Fxq "$cluster"; then
    echo "refusing to reuse existing kind cluster $cluster" >&2
    exit 1
fi
owned=true
"$deadline" 240 kind create cluster --name "$cluster" --image "$node_image" --wait 120s
node="$("$deadline" 15 kind get nodes --name "$cluster")"
if [[ "$node" != "$cluster-control-plane" ]]; then
    echo 'expected exactly the owned kind control-plane container' >&2
    exit 1
fi
"$deadline" 15 docker exec "$node" mkdir -p /podprovider-test/artifacts
"$deadline" 15 docker cp "$scratch/provider.test" "$node:/podprovider-test/provider.test"
printf 'kind image: %s\ncluster: %s\nCloud and guest attestation: explicit test fakes\n' "$node_image" "$cluster" > "$artifacts/scope.txt"
# The same selected test now also spends a real 30-second verification window
# and checks warm claims, manager restart and delayed orphan termination.
"$deadline" 600 docker exec \
    -e C8S_PODPROVIDER_KUBECONFIG=/etc/kubernetes/admin.conf \
    -e C8S_PODPROVIDER_ARTIFACTS=/podprovider-test/artifacts \
    "$node" timeout 585 /podprovider-test/provider.test \
    -test.v -test.count=1 -test.timeout=570s -test.run '^Test(PodProviderControlPlane|KindInfrastructureSelectorPreservesExistingScheduling)$' \
    2>&1 | tee "$artifacts/run.log"
for receipt in result.json lifecycle-result.json; do
    "$deadline" 15 docker cp "$node:/podprovider-test/artifacts/$receipt" "$artifacts/$receipt"
done
python3 - "$artifacts/result.json" "$artifacts/lifecycle-result.json" <<'PY'
import json
import sys

for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as stream:
        receipt = json.load(stream)
    if receipt.get("result") != "PASS" or receipt.get("ownedFakeVMsRemaining") != 0:
        raise SystemExit("scheduler integration did not produce a passing, cleaned-up receipt")
    if receipt.get("scheduler") != "real kind control plane" or not receipt.get("cloud", "").startswith("explicit fake"):
        raise SystemExit("scheduler receipt has an unexpected execution scope")

with open(sys.argv[2], encoding="utf-8") as stream:
    lifecycle = json.load(stream)
required = (
    "verificationDeadlineSurvivesManagerRestart", "lateStatusCannotReviveFailedPod",
    "terminalCleanupWaitsForTermination", "genericIdleBootHasNoPodAuthority",
    "twoScheduledPodsClaimDistinctSlots", "assignmentIntentPrecedesPOST",
    "lostAssignmentReplySurvivesManagerRestart", "staleClaimWriteRejectedByAPI",
    "forcedPodDeletionRetainsAllocationBudget", "newPodUIDGetsNewAllocationGeneration",
    "poolDisabledAndDrained",
)
if any(lifecycle.get(name) is not True for name in required):
    raise SystemExit("required scheduler lifecycle assertion is absent or did not pass")
PY
