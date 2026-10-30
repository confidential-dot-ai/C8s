#!/bin/bash
# Unit test for gpu-cc-enforce.sh: a GPU-less boot is a no-op, every CC-on
# wording passes, and any GPU with CC off (checked per device, so one CC-off
# GPU among several still fails the gate), an unparseable status, a dead
# driver, or a failed/partial attestation fails the gate. Root-free: fakes
# the PCI sysfs tree under a temp root and shadows nvidia-smi and curl with
# stubs on PATH (jq is the real one).
set -u

TESTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$TESTS_DIR/lib.sh"
SCRIPT=${GPU_CC_SCRIPT:-"$TESTS_DIR/../c8s/mkosi.extra/usr/local/bin/gpu-cc-enforce.sh"}
[[ -x "$SCRIPT" ]] || { echo "script not found: $SCRIPT"; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/api"

# Run the production script verbatim with the sysfs root rebased into $WORK,
# the stubs first on PATH, and zero wait budgets so a failing dependency
# fails on its first probe.
run_enforce() {
    sed -e "s|/sys/bus/pci/devices|$WORK/sys/bus/pci/devices|g" "$SCRIPT" \
        | PATH="$WORK/bin:$PATH" GPU_CC_DRIVER_TIMEOUT=0 GPU_CC_API_TIMEOUT=0 sh 2>"$WORK/stderr"
}
set_vendor() { # set_vendor HEXID
    rm -rf "$WORK/sys/bus/pci/devices"
    mkdir -p "$WORK/sys/bus/pci/devices/0000:0b:00.0"
    printf '%s' "$1" > "$WORK/sys/bus/pci/devices/0000:0b:00.0/vendor"
}
# stub_smi RC OUTPUT... — `nvidia-smi conf-compute -f` (no -i, the driver-
# ready probe) prints every OUTPUT line and exits RC; `conf-compute -f -i N`
# prints OUTPUT[N] (or OUTPUT[0] if N has no OUTPUT of its own, so a
# SMI_GPUS override beyond the given OUTPUTs still reports CC on); both
# `--query-gpu=index,uuid` and `--query-gpu=uuid` list $SMI_GPUS (default:
# number of OUTPUTs) GPUs.
stub_smi() {
    local rc=$1; shift
    local n=$#
    {
        echo '#!/bin/sh'
        echo 'case "$1" in'
        echo '--query-gpu=index,uuid) i=0; while [ $i -lt '"${SMI_GPUS:-$n}"' ]; do echo "$i, GPU-$i"; i=$((i+1)); done; exit 0 ;;'
        echo '--query-gpu=uuid) i=0; while [ $i -lt '"${SMI_GPUS:-$n}"' ]; do echo "GPU-$i"; i=$((i+1)); done; exit 0 ;;'
        echo 'esac'
        echo 'if [ "$1 $2" = "conf-compute -f" ] && [ "$3" = "-i" ]; then'
        echo '  case "$4" in'
        local i=0 out
        for out in "$@"; do
            printf '  %s) echo "%s" ;;\n' "$i" "$out"
            i=$((i+1))
        done
        printf '  *) echo "%s" ;;\n' "$1"
        echo '  esac'
        echo "  exit $rc"
        echo 'fi'
        printf 'echo "%s"\n' "$@"
        echo "exit $rc"
    } > "$WORK/bin/nvidia-smi"
    chmod +x "$WORK/bin/nvidia-smi"
}

# The curl stub serves $WORK/api/<endpoint>.{code,body}; a missing file is a
# connection failure. POST bodies are recorded in $WORK/api/<endpoint>.req.
cat > "$WORK/bin/curl" <<'EOF'
#!/bin/sh
out=""; url=""; data=""
while [ $# -gt 0 ]; do
    case "$1" in
    -o) out=$2; shift ;;
    --data-binary) data=$2; shift ;;
    http*) url=$1 ;;
    esac
    shift
done
ep=${url##*/}
# Real curl reads the body from a file when the argument starts with @
# (gpu-cc-enforce does this so an 8-GPU /verify bundle cannot exceed
# ARG_MAX). Resolve it here, or the recorded request would be the
# filename instead of the body and every request assertion would pass
# vacuously.
case "$data" in
    @?*) data=$(cat "${data#@}") ;;
esac
[ -n "$data" ] && printf '%s' "$data" > "$API_DIR/$ep.req"
[ -e "$API_DIR/$ep.code" ] || { echo "curl: (7) Failed to connect" >&2; exit 7; }
code=$(cat "$API_DIR/$ep.code")
if [ -n "$out" ]; then
    cp "$API_DIR/$ep.body" "$out"; printf '%s' "$code"; exit 0
fi
[ "$code" = 200 ] || exit 22   # -f
cat "$API_DIR/$ep.body"
EOF
chmod +x "$WORK/bin/curl"
export API_DIR=$WORK/api
api() { # api ENDPOINT CODE BODY
    printf '%s' "$2" > "$WORK/api/$1.code"
    printf '%s' "$3" > "$WORK/api/$1.body"
}
api_down() { rm -f "$WORK/api/$1".*; }

# verdict GPUS [OVERRIDE_JQ] — a passing /verify body for GPUS Hopper
# devices plus one NVSwitch, optionally mutated by a jq expression.
verdict() {
    jq -cn --argjson n "$1" '{result: {
        signature_valid: true, platform: "tdx", report_data_match: true,
        claims: {nvidia_gpu: {overall_ok: true, nonce_binding_ok: true,
            devices: ([range($n) | {arch: "HOPPER", secboot: true}] + [{arch: "LS10"}])}}}}' \
        | jq -c "${2:-.}"
}
attest_body='{"platform":"tdx","evidence":{"quote":"AAAA"},"nvidia_gpu":{"devices":[{"arch":"HOPPER"}]}}'
all_up() {
    rm -f "$WORK/api"/*
    api health 200 ok
    api platform 200 '{"platform":"tdx"}'
    api attest 200 "$attest_body"
    api verify 200 "$(verdict "${SMI_GPUS:-1}")"
}

CASE="no nvidia device"
set_vendor 0x8086
stub_smi 1 "No devices were found"
api_down health
ok "no-op without a GPU even when nvidia-smi fails" run_enforce

CASE="cc on (driver 595 wording)"
set_vendor 0x10de
stub_smi 0 "CC status: ON"
all_up
ok "passes" run_enforce
ok "attest request binds a nonce and asks for GPU evidence" \
    jq -e '.nvidia_gpu == true and .platform == "tdx" and (.report_data | length) >= 40' "$WORK/api/attest.req" >/dev/null
ok "verify request forwards the same nonce and requires the GPU bundle" \
    bash -c 'n=$(jq -r .report_data "$1/attest.req"); jq -e --arg n "$n" ".params.expected_report_data == \$n and .params.nvidia_gpu_user_nonce == \$n and .params.nvidia_gpu_required == true and .nvidia_gpu != null" "$1/verify.req" >/dev/null' _ "$WORK/api"

CASE="cc on (older 'CC feature' wording)"
stub_smi 0 "CC feature: ON"
ok "passes" run_enforce

CASE="cc off"
stub_smi 0 "CC status: OFF"
ok "fails" not run_enforce
ok "names the cause" stderr_has "not in CC mode"

CASE="one of two gpus off"
stub_smi 0 "CC status: ON" "CC status: OFF"
ok "fails when any GPU is off" not run_enforce
ok "names the offending GPU's index and uuid" stderr_has "GPU 1 (GPU-1)"

CASE="unparseable status"
stub_smi 0 "Confidential Compute is not supported on this device"
ok "fails when no CC status line is printed" not run_enforce
ok "names the cause" stderr_has "cannot parse"

CASE="driver not up"
stub_smi 9 "NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver"
ok "fails when nvidia-smi errors" not run_enforce
ok "names the cause" stderr_has "conf-compute -f failed"

CASE="gpu query fails after cc check"
stub_smi 0 "CC status: ON"
all_up
sed -i 's|^--query-gpu=uuid) .*|--query-gpu=uuid) echo "Unable to determine the device handle"; exit 15 ;;|' "$WORK/bin/nvidia-smi"
ok "fails when nvidia-smi cannot enumerate" not run_enforce
ok "names the cause" stderr_has "query-gpu failed"

CASE="platform endpoint down"
stub_smi 0 "CC status: ON"
all_up; api_down platform
ok "fails when GET /platform errors" not run_enforce
ok "names the cause" stderr_has "GET /platform failed"

CASE="attestation-api down"
all_up; api_down health
ok "fails when attestation-api never answers" not run_enforce
ok "names the cause" stderr_has "attestation-api not up"

CASE="attest fails"
all_up; api attest 500 '{"error":"NVAT SDK init failed"}'
ok "fails when /attest errors" not run_enforce
ok "names the cause" stderr_has "POST /attest returned 500"

CASE="attest without gpu evidence"
all_up; api attest 200 '{"platform":"tdx","evidence":{"quote":"AAAA"}}'
ok "fails when the bundle is missing" not run_enforce
ok "names the cause" stderr_has "no GPU evidence"

CASE="verify rejects"
all_up; api verify 400 '{"error":"NVIDIA GPU attestation: NRAS overall result is false"}'
ok "fails when /verify errors" not run_enforce
ok "names the cause" stderr_has "NRAS overall result is false"

CASE="verify passes but omits the gpu section"
all_up; api verify 200 "$(verdict 1 'del(.result.claims.nvidia_gpu)')"
ok "fails" not run_enforce
ok "names the cause" stderr_has "overall_ok=null"

CASE="verify passes but report_data differs"
all_up; api verify 200 "$(verdict 1 '.result.report_data_match = false')"
ok "fails" not run_enforce
ok "names the cause" stderr_has "report_data_match=false"

CASE="one of two gpus missing from the verified bundle"
SMI_GPUS=2 stub_smi 0 "CC status: ON"
api verify 200 "$(verdict 1)"
ok "fails when fewer GPUs attested than enumerated" not run_enforce
ok "names the cause" stderr_has "gpus=1 want=2"
api verify 200 "$(verdict 2)"
ok "passes once both attest (the NVSwitch does not count)" run_enforce

summarize "gpu-cc-enforce"
