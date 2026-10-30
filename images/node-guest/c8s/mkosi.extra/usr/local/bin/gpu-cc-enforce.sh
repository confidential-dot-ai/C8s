#!/bin/sh
# gpu-cc-enforce: refuse to bring up a node CVM unless every passed-through
# NVIDIA GPU is in confidential-compute (CC) mode and its attestation
# verifies.
#
# Runs before nvidia-cc-ready flips the CC Ready state, which is NVIDIA's
# intended sequence: a GPU becomes usable for CUDA only after a verifier
# accepted its SPDM evidence. confos's nvidia-cc-ready never fails and sets
# Ready unconditionally, so the unit running this script is RequiredBy it
# (and by rke2), and the unit's FailureAction powers the VM off.
#
# Attestation goes through the node's own baked attestation-api: POST
# /attest with a fresh nonce and nvidia_gpu=true, then POST /verify on the
# result with the GPU bundle required. attestation-api delegates signature
# and measurement checks to NRAS and applies its device policy (secure boot
# on, debug off, measurements matched, nonce bound). The verdict comes from
# inside the same measured CVM, so it is a self-check: it gates Ready state
# and node start but does not reach relying parties (README: known gaps).
#
# PCI presence (vendor 0x10de) mirrors gpu-node-label.sh so a GPU-less boot
# of the same image is a clean no-op.
#
# Runs once per boot. That is enough only because the guest kernel has PCI
# hotplug compiled out, so the host cannot add a GPU later; kernel/c8s.config
# pins it and .github/scripts/node-guest-image-invariants.sh enforces it. A
# /sys/bus/pci/rescan by guest root or any privileged platform pod is not
# covered (#669).
set -eu

API=${GPU_CC_API:-http://127.0.0.1:8400}
DRIVER_TIMEOUT=${GPU_CC_DRIVER_TIMEOUT:-180}
API_TIMEOUT=${GPU_CC_API_TIMEOUT:-60}

fail() {
    echo "gpu-cc-enforce: $1 — refusing to start the node (GPU memory would be unprotected)." >&2
    exit 1
}

present=0
for vendor in /sys/bus/pci/devices/*/vendor; do
    [ -e "$vendor" ] || continue
    if [ "$(cat "$vendor")" = "0x10de" ]; then
        present=1
        break
    fi
done
if [ "$present" = 0 ]; then
    echo "gpu-cc-enforce: no NVIDIA GPU present; nothing to enforce"
    exit 0
fi

# Deadlines are checked before sleeping, so a zero timeout means one attempt.
deadline() { echo $(( $(date +%s) + $1 )); }
expired() { [ "$(date +%s)" -ge "$1" ]; }

# The out-of-tree module load and the GPU function-level reset can still be
# settling when persistenced reports started; nvidia-cc-ready used to absorb
# that wait, but this unit now runs before it. A driver that never comes up
# cannot vouch for anything, so that is fatal too.
driver_deadline=$(deadline "$DRIVER_TIMEOUT")
until status=$(nvidia-smi conf-compute -f 2>&1); do
    expired "$driver_deadline" && fail "nvidia-smi conf-compute -f failed: $status"
    sleep 2
done

# Driver 595 prints "CC status: ON"; older drivers "CC feature: ON". One line
# per GPU with -i, one aggregate line without, so an aggregate check can miss
# a single CC-off GPU among several. Query each index instead, and name the
# offending index and uuid on failure.
cc_gpu_list=$(nvidia-smi --query-gpu=index,uuid --format=csv,noheader 2>&1) \
    || fail "nvidia-smi --query-gpu failed: $cc_gpu_list"
[ -n "$cc_gpu_list" ] || fail "nvidia-smi enumerates no GPU despite CC mode on"
while read -r cc_gpu_line; do
    cc_gpu_index=${cc_gpu_line%%,*}
    cc_gpu_uuid=${cc_gpu_line#*, }
    cc_status=$(nvidia-smi conf-compute -f -i "$cc_gpu_index" 2>&1) \
        || fail "nvidia-smi conf-compute -f -i $cc_gpu_index failed: $cc_status"
    cc_line=$(printf '%s\n' "$cc_status" | grep -iE 'cc (feature|status)[[:space:]]*:' || true)
    [ -n "$cc_line" ] || fail "cannot parse CC status for GPU $cc_gpu_index ($cc_gpu_uuid): $cc_status"
    if printf '%s\n' "$cc_line" | grep -qviE ':[[:space:]]*(on|enabled)[[:space:]]*$'; then
        fail "GPU $cc_gpu_index ($cc_gpu_uuid) not in CC mode ($cc_line). Enable GPU CC mode on the host (nvidia_gpu_tools.py --set-cc-mode=on)"
    fi
done <<EOF
$cc_gpu_list
EOF
echo "gpu-cc-enforce: all NVIDIA GPUs in CC mode"

# Every GPU the driver enumerates must appear in the verified claims:
# attestation-api tolerates a per-device collection failure (it only rejects
# an empty bundle), so a count mismatch means a GPU slipped past NRAS.
gpu_uuids=$(nvidia-smi --query-gpu=uuid --format=csv,noheader 2>&1) \
    || fail "nvidia-smi --query-gpu failed: $gpu_uuids"
gpu_count=$(printf '%s\n' "$gpu_uuids" | grep -c . || true)
[ "$gpu_count" -gt 0 ] || fail "nvidia-smi enumerates no GPU despite CC mode on"

# post PATH JSON — POST to attestation-api; print the body on 200, else fail
# with the status and body.
post() {
    body=$(mktemp)
    # The request JSON must NOT travel in argv: an 8-GPU /verify bundle exceeds
    # ARG_MAX and curl dies with "Argument list too long", which fails the gate
    # and powers the node off. Measured on b200-dev-1: 1 GPU fits, 8 does not.
    # Feed it on stdin instead, which has no size limit.
    req=$(mktemp)
    printf '%s' "$2" > "$req"
    code=$(curl -sS -o "$body" -w '%{http_code}' -X POST \
        -H 'content-type: application/json' --data-binary @"$req" "$API$1" 2>&1) \
        || { rm -f "$body" "$req"; fail "POST $1: $code"; }
    rm -f "$req"
    if [ "$code" != 200 ]; then
        resp=$(cat "$body"); rm -f "$body"
        fail "POST $1 returned $code: $resp"
    fi
    cat "$body"; rm -f "$body"
}

api_deadline=$(deadline "$API_TIMEOUT")
until curl -sf "$API/health" >/dev/null 2>&1; do
    expired "$api_deadline" && fail "attestation-api not up at $API within ${API_TIMEOUT}s"
    sleep 2
done

platform_json=$(curl -sf "$API/platform") || fail "GET /platform failed"
platform=$(printf '%s' "$platform_json" | jq -r '.platform // empty')
[ -n "$platform" ] || fail "attestation-api detected no TEE platform"

nonce=$(head -c 32 /dev/urandom | base64 -w0)
attest=$(post /attest "$(jq -cn --arg p "$platform" --arg n "$nonce" \
    '{platform: $p, report_data: $n, nvidia_gpu: true}')")
printf '%s' "$attest" | jq -e '.nvidia_gpu != null' >/dev/null \
    || fail "/attest returned no GPU evidence"

verify_req=$(printf '%s' "$attest" | jq -c --arg n "$nonce" \
    '{platform, evidence, nvidia_gpu, params: {expected_report_data: $n, nvidia_gpu_user_nonce: $n, nvidia_gpu_required: true}}')
verdict=$(post /verify "$verify_req")

# attestation-api already errors (non-200) on a failed NRAS check or device
# policy; the field checks below guard against a verdict that merely omits
# the GPU section, and the count against a partially collected bundle.
verified=$(printf '%s' "$verdict" | jq -r --argjson want "$gpu_count" '
    .result as $r
    | ($r.claims.nvidia_gpu // {}) as $g
    | [$g.devices[]? | select(.arch != "LS10")] | length as $gpus
    | if $r.signature_valid == true
        and $r.report_data_match == true
        and $g.overall_ok == true
        and $g.nonce_binding_ok == true
        and $gpus >= $want
      then "ok \($gpus)"
      else "bad signature_valid=\($r.signature_valid) report_data_match=\($r.report_data_match) overall_ok=\($g.overall_ok) nonce_binding_ok=\($g.nonce_binding_ok) gpus=\($gpus) want=\($want)"
      end') || fail "cannot parse /verify response: $verdict"
case "$verified" in
ok\ *) echo "gpu-cc-enforce: ${verified#ok } NVIDIA GPU(s) attested (platform $platform)" ;;
*) fail "GPU attestation rejected: ${verified#bad }" ;;
esac
