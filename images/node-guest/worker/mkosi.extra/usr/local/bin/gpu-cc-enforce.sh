#!/bin/sh
# gpu-cc-enforce: refuse to bring up a node CVM unless every passed-through
# NVIDIA GPU is in confidential-compute (CC) mode and its attestation
# verifies.
#
# Runs before nvidia-cc-ready flips the CC Ready state, which is NVIDIA's
# intended sequence: a GPU becomes usable for CUDA only after a verifier
# accepted its SPDM evidence. confos's nvidia-cc-ready never fails and sets
# Ready unconditionally, so the unit running this script is RequiredBy it
# (and by containerd), and the unit's FailureAction powers the VM off.
#
# Attestation goes through the node's own baked attestation-api: POST
# /attest with a fresh nonce and nvidia_gpu=true, then POST /verify on the
# result with the GPU bundle required. attestation-api delegates signature
# and measurement checks to NRAS and applies its device policy (secure boot
# on, debug off, measurements matched, nonce bound). The verdict comes from
# inside the same measured CVM, so it is a self-check: it gates Ready state
# and node start. The boot cache retains the raw evidence and its nonce.
#
# PCI presence (vendor 0x10de) decides whether this gate applies, so a GPU-less boot
# of the same image is a clean no-op.
#
# Runs once per boot. That is enough only because the guest kernel has PCI
# hotplug compiled out, so the host cannot add a GPU later; kernel/c8s.config
# pins it and images/node-guest/tests/worker-invariants.sh enforces it. A
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

cache_dir=/run/c8s
cache=$cache_dir/gpu-attestation.json
mkdir -p "$cache_dir"
umask 077
rm -f "$cache"
work=$(mktemp -d "$cache_dir/.gpu-attestation.XXXXXX")
trap 'rm -rf "$work"' EXIT
boot_id=$(cat /proc/sys/kernel/random/boot_id)
[ -n "$boot_id" ] || fail "cannot read the boot ID"

[ -d /sys/bus/pci/devices ] || fail "PCI inventory unavailable"
present=0
pci_gpus=0
for vendor in /sys/bus/pci/devices/*/vendor; do
    [ -e "$vendor" ] || continue
    vendor_id=$(cat "$vendor")
    [ "$vendor_id" = "0x10de" ] || continue
    present=1
    pci_class=$(cat "${vendor%/*}/class")
    case "$pci_class" in
        0x03*|0x1200*) pci_gpus=$((pci_gpus + 1)) ;;
    esac
done
if [ "$present" = 0 ]; then
    jq -cn --arg boot "$boot_id" '{status: "no_gpu", boot_id: $boot}' > "$work/cache"
    mv "$work/cache" "$cache"
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

gpu_count=$(printf '%s\n' "$cc_gpu_list" | wc -l)
[ "$gpu_count" -ge "$pci_gpus" ] || fail "driver enumerated $gpu_count GPUs for $pci_gpus NVIDIA PCI GPU functions"

post() {
    code=$(curl -sS -o "$work/$1.json" -w '%{http_code}' -X POST \
        -H 'content-type: application/json' --data-binary @"$work/request" "$API/$1") \
        || fail "POST /$1 failed"
    if [ "$code" != 200 ]; then
        fail "POST /$1 returned $code: $(cat "$work/$1.json")"
    fi
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
[ "${#nonce}" -eq 44 ] || fail "cannot generate an attestation nonce"
jq -cn --arg p "$platform" --arg n "$nonce" \
    '{platform: $p, report_data: $n, nvidia_gpu: true}' > "$work/request"
post attest

jq -e --arg p "$platform" --argjson want "$gpu_count" '
    def populated: type == "string" and length > 0;
    def distinct_values: all(.[]; populated) and length == (unique | length);
    .platform == $p and .evidence != null and
    ([.nvidia_gpu.devices[]? | select(.arch != "LS10")] |
        length == $want and
        (map(.uuid) | distinct_values) and
        (all(.[]; .cert_chain_b64 | populated)) and
        (map(.evidence_b64) | distinct_values))
' "$work/attest.json" >/dev/null || fail "/attest lacks distinct GPU evidence for every enumerated GPU"

jq -c --arg n "$nonce" \
    '{platform, evidence, nvidia_gpu, params: {expected_report_data: $n, nvidia_gpu_user_nonce: $n, nvidia_gpu_required: true}}' \
    "$work/attest.json" > "$work/request"
post verify

# attestation-api already errors (non-200) on a failed NRAS check or device
# policy; the field checks below guard against a verdict that merely omits
# the GPU section, and the count against a partially collected bundle.
verified=$(jq -r --argjson want "$gpu_count" '
    .result as $r
    | ($r.claims.nvidia_gpu // {}) as $g
    | [$g.devices[]? | select(.arch != "LS10") | .ueid] as $ids
    | ($ids | length) as $gpus
    | if $r.signature_valid == true
        and $r.report_data_match == true
        and $g.overall_ok == true
        and $g.nonce_binding_ok == true
        and $gpus == $want
        and all($ids[]; type == "string" and length > 0)
        and ($ids | unique | length) == $want
      then "ok \($gpus)"
      else "bad signature_valid=\($r.signature_valid) report_data_match=\($r.report_data_match) overall_ok=\($g.overall_ok) nonce_binding_ok=\($g.nonce_binding_ok) gpus=\($gpus) want=\($want)"
      end' "$work/verify.json") || fail "cannot parse /verify response"
case "$verified" in
ok\ *) echo "gpu-cc-enforce: ${verified#ok } NVIDIA GPU(s) attested (platform $platform)" ;;
*) fail "GPU attestation rejected: ${verified#bad }" ;;
esac

jq -c --arg boot "$boot_id" --arg nonce "$nonce" '
    {status: "attested", boot_id: $boot, nonce: $nonce, platform, evidence, nvidia_gpu}
    + (if has("collateral") then {collateral} else {} end)
' "$work/attest.json" > "$work/cache"
mv "$work/cache" "$cache"
