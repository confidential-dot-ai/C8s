#!/usr/bin/env bash
# Explicit real Cloud acceptance. Credentials, ownership and logs stay private.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"
mode="${1:-}"
[[ "${C8S_PODCLOUD_LIVE:-}" == 1 ]] || { echo 'Set C8S_PODCLOUD_LIVE=1 to enable this live lane.' >&2; exit 1; }
compatible_source() {
    # Only one SchemaVersion constant, naming the v2 contract, in a source
    # file of ordinary size. The compiled Go entry point checks its actual value.
    local source="$repo_root/internal/cmds/launchconfig/config.go" versions
    [[ -f "$source" && "$(wc -c < "$source")" -le $((1 << 20)) ]] || return 1
    versions="$(grep -E '^[[:space:]]*SchemaVersion[[:space:]]*=[[:space:]]*"[^"]+"[[:space:]]*$' "$source" | sed -E 's/.*"([^"]+)".*/\1/')"
    [[ "$versions" == "c8s-launch/v2" ]]
}
if [[ "$mode" == run ]]; then
    # Reject unsupported source before acquiring a lock, creating state, reading
    # credentials or invoking build/provisioning tools. Cleanup uses its runner.
    compatible_source || {
        echo 'This Cloud acceptance lane requires c8s-launch/v2 and a dedicated measured CDS. Retained runs must use their original cleanup binary.' >&2
        exit 1
    }
fi
# The runner tool holds the host lock and writes the private markers; it is
# built from this checkout before any state exists.
runner_tool="$repo_root/build/pod-cloud-tool"
if [[ "${C8S_PODCLOUD_LOCKED:-}" != 1 ]]; then
    command -v go >/dev/null || { echo 'go is required to build the runner tool' >&2; exit 1; }
    mkdir -p "$(dirname "$runner_tool")"
    go build -o "$runner_tool" ./test/integration/pod-cloud/tool
    exec "$runner_tool" lock "$repo_root/test/integration/pod-cloud/run.sh" "$@"
fi
"$runner_tool" lock --verify "$repo_root/test/integration/pod-cloud/run.sh" "$@"
for tool in docker jq; do
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

# The acceptance binary runs in a disposable container of the pinned Linux
# image with the private state bind-mounted; nothing it needs is installed on
# the host. runner.json records the image and the container label of a run, so
# cleanup finds a container the host shell lost and refuses to run beside it.
no_live_container() {
    local label members
    label="$(jq -er '.label | select(test("^c8s-podcloud-[0-9]+-[0-9]+$"))' "$state/runner.json")"
    members="$("$deadline" 15 docker ps -aq --no-trunc --filter "label=c8s.podcloud.run=$label")" || return 1
    [[ -z "$members" ]] || { echo 'a container of this run is still present; let it finish or stop it before cleanup' >&2; return 1; }
}

# execute runs the acceptance binary once. Every invocation is a fresh,
# read-only container that Docker removes when the process exits; the host
# deadline wraps the container's own, so a lost host shell leaves at most one
# container, found by its run label.
execute() {
    local action="$1" seconds="$2" pattern="${3:-^TestPodCloud$}"
    "$deadline" "$seconds" docker run --rm --read-only --tmpfs /tmp \
        --label "c8s.podcloud.run=$label" \
        --mount "type=bind,source=$state,target=/podcloud" \
        -e C8S_PODCLOUD_LIVE=1 -e C8S_PODCLOUD_MODE="$action" \
        -e C8S_PODCLOUD_CONFIG=/podcloud/config.json -e C8S_PODCLOUD_STATE=/podcloud \
        --entrypoint timeout "$node_image" "$((seconds-10))" /podcloud/acceptance.test \
        -test.v -test.count=1 -test.timeout="$((seconds-20))s" -test.run "$pattern"
}

if [[ "$mode" == cleanup && ! -e "$state/ledger.json" ]]; then
    [[ ! -e "$state/cloud-authority-issued.json" ]] || { echo 'Cloud authority was issued but its ledger is missing; refusing local-only cleanup' >&2; exit 1; }
    # Ledger persistence precedes every possible Cloud POST. This branch cannot
    # execute the Go live lane; it only proves no Cloud authority exists.
    if [[ -e "$state/execution-started" ]]; then
        # The host shell may have died while Docker kept its Go process alive
        # in preflight. Obtain that process's independent lock before
        # interpreting ledger absence as proof of no Cloud authority.
        [[ -f "$state/runner.json" && -f "$state/acceptance.test" ]] || { echo 'cleanup requires the original private runner' >&2; exit 1; }
        no_live_container
        label="$(jq -er '.label' "$state/runner.json")"
        node_image="$(jq -er '.image | select(test("@sha256:[a-f0-9]{64}$"))' "$state/runner.json")"
        execute cleanup 60 '^TestPodCloudLocalCleanup$'
        jq -e '.localCleanup == true' "$state/closed-before-ledger.json" >/dev/null || { echo 'missing stopped-process cleanup fence' >&2; exit 1; }
        [[ ! -e "$state/ledger.json" ]] || { echo 'Cloud authority appeared; rerun normal cleanup' >&2; exit 1; }
    fi
    echo 'No Cloud authority was issued; nothing to clean up in Cloud.'
    exit 0
fi

if [[ "$mode" == run ]]; then
    scenario="$(jq -er 'if .scenario == null or .scenario == "" then "connected" else .scenario end |
        select(. == "connected" or . == "warm-assignment" or . == "cds-outage" or . == "cds-renewal-outage")' "$input")" || {
        echo 'scenario must be connected, warm-assignment, cds-outage or cds-renewal-outage' >&2; exit 1;
    }
    command -v go >/dev/null || { echo 'go is required to build the live harness' >&2; exit 1; }
    for entry in tokenFile manifestFile cdsManifestFile cliFile probeFile; do
        source_file="$(jq -er --arg key "$entry" '.[$key] | select(type == "string" and startswith("/"))' "$input")"
        [[ -f "$source_file" && ! -L "$source_file" ]] || { echo 'regular local input files required' >&2; exit 1; }
        cp "$source_file" "$state/$entry"
        chmod 600 "$state/$entry"
    done
    chmod 700 "$state/cliFile" "$state/probeFile"
    jq --arg scenario "$scenario" '.scenario=$scenario | .tokenFile="/podcloud/tokenFile" | .manifestFile="/podcloud/manifestFile" | .cdsManifestFile="/podcloud/cdsManifestFile" | .cliFile="/podcloud/cliFile" | .probeFile="/podcloud/probeFile"' "$input" > "$state/config.json"
    # The container image is the cluster harness's digest-pinned node image:
    # a Linux userland with GNU timeout and sh, and nothing of kind is used.
    C8S_IT_NODE_IMAGE="${C8S_PODCLOUD_NODE_IMAGE:-}"
    C8S_IT_CLUSTER=""
    source ./test/integration/cluster/lib.sh
    node_image="$NODE_IMAGE"
    [[ "$node_image" =~ @sha256:[[:xdigit:]]{64}$ ]] || { echo 'container image must be digest pinned' >&2; exit 1; }
    docker_arch="$("$deadline" 15 docker version --format '{{.Server.Arch}}')"
    [[ "$docker_arch" == amd64 || "$docker_arch" == arm64 ]] || { echo 'unsupported Docker architecture' >&2; exit 1; }
    "$deadline" 600 env GOOS=linux GOARCH="$docker_arch" CGO_ENABLED=0 go test -c \
        -tags pod_cloud_integration -o "$state/acceptance.test" ./test/integration/pod-cloud/acceptance
    # The harness is built from this checkout; config.source identifies guest/CLI.
    acceptance_binary_sha256="$("$runner_tool" build-receipt "$state")"
    label="c8s-podcloud-$(date +%s)-$$"
    jq -n --arg label "$label" --arg image "$node_image" --argjson created "$(date +%s)" \
        '{label:$label,image:$image,createdAfter:$created}' > "$state/runner.json"
else
    [[ -f "$state/runner.json" && -f "$state/acceptance.test" ]] || { echo 'cleanup requires the original private runner' >&2; exit 1; }
    no_live_container
    label="$(jq -er '.label' "$state/runner.json")"
    node_image="$(jq -er '.image | select(test("@sha256:[a-f0-9]{64}$"))' "$state/runner.json")"
fi

verify_state_mount() {
    local expected observed
    # Docker's mount metadata can name the requested host path even when a
    # remote daemon or VM sees a different, empty directory at that path.
    expected="$("$runner_tool" mount-proof "$state" "$acceptance_binary_sha256")"
    if ! observed="$("$deadline" 30 docker run --rm --read-only \
        --mount "type=bind,source=$state,target=/podcloud" \
        --entrypoint /bin/sh "$node_image" -ec '
        test -f /podcloud/.mount-nonce && test ! -L /podcloud/.mount-nonce
        test -f /podcloud/acceptance.test && test ! -L /podcloud/acceptance.test
        test -x /podcloud/acceptance.test
        cat /podcloud/.mount-nonce
        sha256sum /podcloud/acceptance.test
    ' 2>/dev/null)" || [[ "$observed" != "$expected" ]]; then
        echo 'Docker cannot see the exact host state and runner; use a new state directory under a Docker-shared host path, then clean up this local-only attempt.' >&2
        return 1
    fi
}

if [[ "$mode" == run ]]; then
    # Keep execution-started absent on mount failure so partial cleanup needs
    # no in-container runner and cannot be confused with a live Cloud attempt.
    verify_state_mount
    "$runner_tool" started "$state"
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
    echo 'Run/cleanup incomplete. Retain private state and rerun cleanup; do not delete its ledger.' >&2
    exit 1
fi
if [[ "$mode" == run ]]; then
    observed_binary_sha256="$("$runner_tool" sha256 "$state/acceptance.test")"
    jq -e --arg scenario "$scenario" --arg binary "$acceptance_binary_sha256" \
      --arg observed "$observed_binary_sha256" --slurpfile build "$state/acceptance-build.json" \
      --slurpfile cfg "$state/config.json" --slurpfile ledger "$state/ledger.json" '
      .scenario == $scenario and .scenario == $cfg[0].scenario and
      .acceptanceBinarySHA256 == $binary and $binary == $observed and $build[0].acceptanceBinarySHA256 == $binary and
      .version == 2 and .podLaunchFormat == "c8s-launch/v2" and .cdsLaunchFormat == "c8s-cds/v1" and
      .cdsConfigSHA256 == $ledger[0].owned.cds.launchFileSHA256 and (.cdsConfigSHA256 | test("^[a-f0-9]{64}$")) and
      .passed == true and .run == $ledger[0].run and .source == $cfg[0].source and
      .image == $cfg[0].image and .cdsImage == $cfg[0].cdsImage and
      .cliSHA256 == $cfg[0].cliSHA256 and .manifestDigest == $cfg[0].manifestDigest and .diskDigest == $cfg[0].diskDigest and
      .cdsManifestDigest == $cfg[0].cdsManifestDigest and .cdsDiskDigest == $cfg[0].cdsDiskDigest and .meshImage == $cfg[0].meshImage and
      (.assertions | keys == (if $scenario == "cds-outage" then
        ["attestedReadiness","authenticatedPolicyUpdate","cdsAccessControl","cdsIngressRestored","certificateIdentity","cleanup","exactDigests","guestObservedOutage","ownedDeletion","revocationEnforced","servedPolicyRetained"]
      elif $scenario == "cds-renewal-outage" then
        ["attestedReadiness","authenticatedPolicyUpdate","cdsAccessControl","cdsIngressRestored","certificateIdentity","cleanup","exactDigests","guestObservedOutage","ownedDeletion","renewalAfterOutage","revocationEnforced","servedPolicyRetained","taskContinuity"]
      elif $scenario == "warm-assignment" then
        ["assignmentBeforePOST","attestedReadiness","cdsAccessControl","certificateIdentity","cleanup","conflictingAssignmentRejected","exactDigests","genericIdle","ownedDeletion"]
      else
        ["attestedReadiness","cdsAccessControl","cleanup","exactDigests","meshDNSInternet","negativeProbes","ownedDeletion","readinessCycle","timedRenewal"]
      end)) and
      all(.assertions[]; . == true)
      ' "$state/result.json" >/dev/null || { echo 'Missing matching complete acceptance receipt; cleanup success alone is not acceptance.' >&2; exit 1; }
fi
echo 'Confirmed owned Cloud cleanup; private evidence retained locally.'
