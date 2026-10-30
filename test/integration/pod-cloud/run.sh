#!/usr/bin/env bash
# Explicit real Cloud acceptance. Credentials, ownership and logs stay private.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"
if [[ "${C8S_PODCLOUD_LOCKED:-}" != 1 ]]; then
    exec python3 "$repo_root/test/integration/pod-cloud/lock.py" "$repo_root/test/integration/pod-cloud/run.sh" "$@"
fi
python3 "$repo_root/test/integration/pod-cloud/lock.py" --verify "$repo_root/test/integration/pod-cloud/run.sh" "$@"
mode="${1:-}"
[[ "${C8S_PODCLOUD_LIVE:-}" == 1 ]] || { echo 'Set C8S_PODCLOUD_LIVE=1 to enable this live lane.' >&2; exit 1; }
for tool in docker kind jq; do
    command -v "$tool" >/dev/null || { echo "required tool missing: $tool" >&2; exit 1; }
done
if command -v timeout >/dev/null; then
    deadline=timeout
elif command -v gtimeout >/dev/null; then
    deadline=gtimeout
else
    echo 'GNU timeout is required.' >&2
    exit 1
fi

case "$mode" in
    run)
        [[ $# == 3 && "$2" == /* && "$3" == /* ]] || { echo 'usage: run.sh run /absolute/input.json /absolute/new-private-state' >&2; exit 1; }
        input="$2"; state="$3"
        [[ ! -e "$state" ]] || { echo 'run requires new state; use cleanup for an existing run' >&2; exit 1; }
        mkdir -m 700 "$state"
        state="$(cd "$state" && pwd)"
        ;;
    cleanup)
        [[ $# == 2 && "$2" == /* && -d "$2" && ! -L "$2" ]] || { echo 'usage: run.sh cleanup /absolute/existing-private-state' >&2; exit 1; }
        state="$(cd "$2" && pwd)"
        ;;
    *) echo 'expected run or cleanup' >&2; exit 1 ;;
esac
[[ "$state" != *','* && "$state" != *$'\n'* ]] || { echo 'state path cannot contain commas or newlines' >&2; exit 1; }

# Validate a real container identity before exec or deletion. The initial capture
# also supports interruption during kind creation: it requires the fresh intent's
# exact digest, creation time, kind labels and private bind, never a name alone.
owned_node() {
    cluster="$(jq -er '.cluster | select(test("^c8s-podcloud-[0-9]+-[0-9]+$"))' "$state/kind.json")"
    node_image="$(jq -er '.nodeImage | select(test("@sha256:[a-f0-9]{64}$"))' "$state/kind.json")"
    node="$cluster-control-plane"
    if ! "$deadline" 15 docker inspect --type container "$node" > "$state/node-inspect.json" 2>/dev/null; then
        members="$("$deadline" 15 docker ps -aq --no-trunc --filter "label=io.x-k8s.kind.cluster=$cluster")" || return 1
        [[ -z "$members" ]] || { echo 'unexpected replacement cluster member; refusing adoption' >&2; return 1; }
        return 3
    fi
    if ! jq -e --arg state "$state" --slurpfile owner "$state/kind.json" '
        length == 1 and (.[0] as $n | $owner[0] as $o |
        $n.Config.Image == $o.nodeImage and
        $n.Config.Labels["io.x-k8s.kind.cluster"] == $o.cluster and
        $n.Config.Labels["io.x-k8s.kind.role"] == "control-plane" and
        any($n.Mounts[]; .Type == "bind" and .Source == $state and .Destination == "/podcloud" and .RW == true) and
        (($n.Created | split(".")[0] + "Z" | fromdateiso8601) >= $o.createdAfter) and
        (($o.nodeID == null and $o.imageID == null) or ($n.Id == $o.nodeID and $n.Image == $o.imageID)))
        ' "$state/node-inspect.json" >/dev/null; then
        echo 'owned container identity, image or private mount differs; refusing exec/delete' >&2
        return 1
    fi
    node_id="$(jq -er '.[0].Id' "$state/node-inspect.json")"
    members="$("$deadline" 15 docker ps -aq --no-trunc --filter "label=io.x-k8s.kind.cluster=$cluster")"
    [[ "$members" == "$node_id" ]] || { echo 'unexpected additional cluster member; refusing cleanup' >&2; return 1; }
    jq --slurpfile node "$state/node-inspect.json" '.nodeID=$node[0][0].Id | .imageID=$node[0][0].Image' "$state/kind.json" > "$state/kind.json.next"
    mv "$state/kind.json.next" "$state/kind.json"
}

delete_local_cluster() {
    local status
    if owned_node; then
        "$deadline" 60 kind delete cluster --name "$cluster" --kubeconfig "$state/kubeconfig"
    else
        status=$?
        [[ "$status" == 3 ]] || return "$status"
    fi
}

if [[ "$mode" == cleanup && ! -e "$state/ledger.json" ]]; then
    [[ ! -e "$state/cloud-authority-issued.json" ]] || { echo 'Cloud authority was issued but its ledger is missing; refusing local-only cleanup' >&2; exit 1; }
    # Ledger persistence precedes every possible Cloud POST. This branch cannot
    # execute the Go live lane and only removes verified owned local resources.
    if [[ -e "$state/kind.json" ]]; then
        if [[ -e "$state/execution-started" ]]; then
            # The host shell may have died while Docker kept its Go process
            # alive in preflight. Obtain that process's independent lock before
            # interpreting ledger absence as proof of no Cloud authority.
            if owned_node; then
                "$deadline" 30 docker exec -e C8S_PODCLOUD_LIVE=1 -e C8S_PODCLOUD_STATE=/podcloud \
                    "$node_id" /podcloud/provider.test -test.count=1 -test.timeout=20s \
                    -test.run '^TestPodProviderCloudLocalCleanup$'
                jq -e '.localCleanup == true' "$state/closed-before-ledger.json" >/dev/null || { echo 'missing stopped-process cleanup fence' >&2; exit 1; }
            else
                node_status=$?
                [[ "$node_status" == 3 ]] || exit 1
            fi
        fi
        [[ ! -e "$state/ledger.json" ]] || { echo 'Cloud authority appeared; rerun normal cleanup' >&2; exit 1; }
        delete_local_cluster
    fi
    echo 'No Cloud authority was issued; owned partial local setup cleaned.'
    exit 0
fi

if [[ "$mode" == run ]]; then
    scenario="$(jq -er 'if .scenario == null or .scenario == "" then "connected" else .scenario end |
        select(. == "connected" or . == "verification-timeout" or . == "warm-assignment" or . == "cds-outage")' "$input")" || {
        echo 'scenario must be connected, verification-timeout, warm-assignment or cds-outage' >&2; exit 1;
    }
    command -v go >/dev/null || { echo 'go is required to build the live harness' >&2; exit 1; }
    for entry in tokenFile manifestFile cliFile probeFile; do
        source_file="$(jq -er --arg key "$entry" '.[$key] | select(type == "string" and startswith("/"))' "$input")"
        [[ -f "$source_file" && ! -L "$source_file" ]] || { echo 'regular local input files required' >&2; exit 1; }
        cp "$source_file" "$state/$entry"
        chmod 600 "$state/$entry"
    done
    chmod 700 "$state/cliFile" "$state/probeFile"
    jq --arg scenario "$scenario" '.scenario=$scenario | .tokenFile="/podcloud/tokenFile" | .manifestFile="/podcloud/manifestFile" | .cliFile="/podcloud/cliFile" | .probeFile="/podcloud/probeFile"' "$input" > "$state/config.json"
    C8S_IT_NODE_IMAGE="${C8S_PODCLOUD_NODE_IMAGE:-}"
    C8S_IT_CLUSTER=""
    source ./test/integration/cluster/lib.sh
    node_image="$NODE_IMAGE"
    [[ "$node_image" =~ @sha256:[[:xdigit:]]{64}$ ]] || { echo 'kind image must be digest pinned' >&2; exit 1; }
    docker_arch="$("$deadline" 15 docker version --format '{{.Server.Arch}}')"
    [[ "$docker_arch" == amd64 || "$docker_arch" == arm64 ]] || { echo 'unsupported Docker architecture' >&2; exit 1; }
    "$deadline" 600 env GOOS=linux GOARCH="$docker_arch" CGO_ENABLED=0 go test -c \
        -tags podprovider_integration,podprovider_cloud -o "$state/provider.test" ./internal/podprovider
    provider_binary_sha256="$(python3 - "$state" <<'PYBUILD'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

state = Path(sys.argv[1])
def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True,
                          text=True, timeout=15).stdout.strip()

# The provider is built from this checkout; config.source identifies guest/CLI.
source = git("rev-parse", "--verify", "HEAD")
dirty = bool(git("status", "--porcelain=v1", "--untracked-files=normal"))
digest = hashlib.sha256()
with (state / "provider.test").open("rb") as runner:
    for chunk in iter(lambda: runner.read(1024 * 1024), b""):
        digest.update(chunk)
with (state / "provider-build.json").open("x") as receipt:
    json.dump({"source": source, "dirty": dirty,
               "providerBinarySHA256": digest.hexdigest()}, receipt)
print(digest.hexdigest())
PYBUILD
)"
    cluster="c8s-podcloud-$(date +%s)-$$"
    existing="$("$deadline" 15 kind get clusters)"
    if printf '%s\n' "$existing" | grep -Fxq "$cluster"; then
        echo 'refusing an existing cluster identity' >&2
        exit 1
    fi
    jq -n --arg cluster "$cluster" --arg image "$node_image" --argjson created "$(date +%s)" \
        '{cluster:$cluster,nodeImage:$image,createdAfter:$created}' > "$state/kind.json"
    jq -n --arg state "$state" '{kind:"Cluster",apiVersion:"kind.x-k8s.io/v1alpha4",nodes:[{role:"control-plane",extraMounts:[{hostPath:$state,containerPath:"/podcloud"}]}]}' > "$state/kind-config.json"
    # The user's normal kubeconfig and current context are never changed.
    "$deadline" 240 kind create cluster --name "$cluster" --image "$node_image" \
        --config "$state/kind-config.json" --kubeconfig "$state/kubeconfig" --wait 120s
    owned_node
else
    [[ -f "$state/kind.json" && -f "$state/provider.test" ]] || { echo 'cleanup requires the original private runner and local ownership intent' >&2; exit 1; }
fi

execute() {
    local action="$1" seconds="$2" status
    if owned_node; then
        "$deadline" "$seconds" docker exec \
            -e C8S_PODCLOUD_LIVE=1 -e C8S_PODCLOUD_MODE="$action" \
            -e C8S_PODCLOUD_CONFIG=/podcloud/config.json -e C8S_PODCLOUD_STATE=/podcloud \
            -e C8S_PODPROVIDER_KUBECONFIG=/etc/kubernetes/admin.conf \
            "$node_id" timeout "$((seconds-10))" /podcloud/provider.test \
            -test.v -test.count=1 -test.timeout="$((seconds-20))s" -test.run '^TestPodProviderCloud$'
    else
        status=$?
        [[ "$action" == cleanup && "$status" == 3 ]] || return 1
        "$deadline" "$seconds" docker run --rm --read-only --tmpfs /tmp \
            --mount "type=bind,source=$state,target=/podcloud" \
            -e C8S_PODCLOUD_LIVE=1 -e C8S_PODCLOUD_MODE=cleanup \
            -e C8S_PODCLOUD_CONFIG=/podcloud/config.json -e C8S_PODCLOUD_STATE=/podcloud \
            --entrypoint /podcloud/provider.test "$node_image" \
            -test.v -test.count=1 -test.timeout="$((seconds-20))s" -test.run '^TestPodProviderCloud$'
    fi
}

verify_state_mount() {
    local expected observed
    # Docker's mount metadata can name the requested host path even when a
    # remote daemon or VM sees a different, empty directory at that path.
    expected="$(python3 - "$state" "$provider_binary_sha256" <<'PY'
import hashlib
import os
import secrets
import sys

directory = sys.argv[1]
nonce = secrets.token_hex(32) + "\n"
fd = os.open(os.path.join(directory, ".mount-nonce"),
             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "w") as marker:
    marker.write(nonce)
digest = hashlib.sha256()
with open(os.path.join(directory, "provider.test"), "rb") as runner:
    for chunk in iter(lambda: runner.read(1024 * 1024), b""):
        digest.update(chunk)
if digest.hexdigest() != sys.argv[2]:
    raise SystemExit("built provider binary changed before execution")
print(nonce, end="")
print(digest.hexdigest() + "  /podcloud/provider.test")
PY
)"
    if ! observed="$("$deadline" 30 docker exec "$node_id" /bin/sh -ec '
        test -f /podcloud/.mount-nonce && test ! -L /podcloud/.mount-nonce
        test -f /podcloud/provider.test && test ! -L /podcloud/provider.test
        test -x /podcloud/provider.test
        cat /podcloud/.mount-nonce
        sha256sum /podcloud/provider.test
    ' 2>/dev/null)" || [[ "$observed" != "$expected" ]]; then
        echo 'Docker cannot see the exact host state and runner; use a new state directory under a Docker-shared host path, then clean up this local-only attempt.' >&2
        return 1
    fi
}

if [[ "$mode" == run ]]; then
    # Keep execution-started absent on mount failure so partial cleanup needs
    # no in-container runner and cannot be confused with a live Cloud attempt.
    verify_state_mount
    python3 - "$state" <<'PY'
import os
import sys
directory = sys.argv[1]
fd = os.open(os.path.join(directory, "execution-started"),
             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "wb") as marker:
    marker.write(b"Cloud execution may start\n")
    marker.flush()
    os.fsync(marker.fileno())
parent = os.open(directory, os.O_RDONLY)
try:
    os.fsync(parent)
finally:
    os.close(parent)
PY
fi
set +e
if [[ "$mode" == run ]]; then
    execute run 9300 2>&1 | tee "$state/run.log"
else
    execute cleanup 680 2>&1 | tee "$state/cleanup.log"
fi
status=${PIPESTATUS[0]}
set -e
if [[ "$status" != 0 ]] || ! jq -e '.complete == true' "$state/ledger.json" >/dev/null; then
    echo 'Run/cleanup incomplete. Retain private state and rerun cleanup; do not delete its cluster or ledger.' >&2
    exit 1
fi
if [[ "$mode" == run ]]; then
    observed_binary_sha256="$(python3 - "$state/provider.test" <<'PY'
import hashlib
import sys

digest = hashlib.sha256()
with open(sys.argv[1], "rb") as runner:
    for chunk in iter(lambda: runner.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
)"
    jq -e --arg scenario "$scenario" --arg binary "$provider_binary_sha256" \
      --arg observed "$observed_binary_sha256" --slurpfile build "$state/provider-build.json" \
      --slurpfile cfg "$state/config.json" --slurpfile ledger "$state/ledger.json" '
      .scenario == $scenario and .scenario == $cfg[0].scenario and
      .providerBinarySHA256 == $binary and $binary == $observed and $build[0].providerBinarySHA256 == $binary and
      .passed == true and .run == $ledger[0].run and .source == $cfg[0].source and
      .image == $cfg[0].image and .cdsImage == $cfg[0].cdsImage and
      .cliSHA256 == $cfg[0].cliSHA256 and .manifestDigest == $cfg[0].manifestDigest and .meshImage == $cfg[0].meshImage and
      (.assertions | keys == (if $scenario == "verification-timeout" then
        ["attestedReadiness","cleanup","exactDigests","lateVerifiedResultRejected","normalScheduler","persistedVerificationDeadline","providerDeletion","readinessWithdrawn","restartRecovery","timeoutTermination"]
      elif $scenario == "cds-outage" then
        ["attestedReadiness","authenticatedPolicyUpdate","cdsIngressRestored","certificateIdentity","cleanup","exactDigests","guestObservedOutage","normalScheduler","providerDeletion","revocationEnforced","servedPolicyRetained"]
      elif $scenario == "warm-assignment" then
        ["assignmentBeforePOST","attestedReadiness","certificateIdentity","cleanup","conflictingAssignmentRejected","exactDigests","genericIdle","normalScheduler","poolDrain","providerDeletion","restartRecovery","uidFencedClaim"]
      else
        ["attestedReadiness","cleanup","exactDigests","meshDNSInternet","negativeProbes","normalScheduler","providerDeletion","readinessCycle","restartRecovery","timedRenewal"]
      end)) and
      all(.assertions[]; . == true)
      ' "$state/result.json" >/dev/null || { echo 'Missing matching complete acceptance receipt; cleanup success alone is not acceptance.' >&2; exit 1; }
fi
delete_local_cluster
echo 'Confirmed owned Cloud cleanup; private evidence retained locally.'
