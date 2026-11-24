#!/usr/bin/env bash
# Verify one worker boot record against an independent attestation-api v0.6.0.
set -euo pipefail
if [[ $# != 3 ]]; then
  echo "usage: $0 RECORD.json TRUSTED-PINS.json TRUSTED-WORKER.yaml" >&2
  exit 2
fi
record=$1
pins=$2
document=$3
platform=$(jq -er '.platform | select(. == "tdx" or . == "snp")' "$pins")
case $platform in
  tdx)
    document_pin=$({ head -c 48 /dev/zero; openssl dgst -sha384 -binary "$document"; } |
      openssl dgst -sha384 -binary | openssl base64 -A)
    ;;
  snp) document_pin=$(openssl dgst -sha256 -binary "$document" | openssl base64 -A) ;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

jq -en --slurpfile r "$record" --slurpfile p "$pins" --arg doc "$document_pin" '
  def digest: type == "string" and test("^[A-Za-z0-9+/]{64}$");
  def gpu: .arch == "HOPPER" or .arch == "BLACKWELL";
  $p[0] as $p | $r[0] as $r |
  select($r.status == "attested" and $r.platform == $p.platform and
    ($r.nonce | type == "string" and test("^[A-Za-z0-9+/]{43}=$")) and
    ($p.gpu_count | type == "number" and . >= 1 and floor == .) and
    ([$r.nvidia_gpu.devices[] | select(gpu)] | length == $p.gpu_count)) |
  (if $p.platform == "tdx" then
     select([$p.mrtd,$p.rtmr1,$p.rtmr2] | all(.[]; digest)) |
     {expected_mrtd:$p.mrtd, expected_rtmr1:$p.rtmr1,
      expected_rtmr2:$p.rtmr2, expected_rtmr3:$doc}
   else
     select($p.launch_digest | digest) |
     {expected_launch_digest:$p.launch_digest, expected_init_data_hash:$doc}
   end) as $image |
  $r | {platform,evidence,nvidia_gpu,params:($image + {
    expected_report_data:.nonce, nvidia_gpu_user_nonce:.nonce, nvidia_gpu_required:true
  })}' > "$work/request"

curl --noproxy '*' --fail-with-body --silent --show-error --max-time 120 \
  -H 'Content-Type: application/json' --data-binary @"$work/request" \
  http://127.0.0.1:8400/verify > "$work/result"
jq -e --slurpfile p "$pins" '
  $p[0] as $p | .result as $r | $r.claims.nvidia_gpu as $g |
  select($r.platform == $p.platform and $r.signature_valid == true and
    $r.report_data_match == true and $r.collateral_verified == true and
    (if $p.platform == "tdx" then
       $r.mrtd_match == true and $r.rtmr1_match == true and $r.rtmr2_match == true and
       $r.rtmr3_match == true and $r.tcb_status.tcb_status == "UpToDate" and
       $r.tcb_status.collateral_expired == false
     else $r.launch_digest_match == true and $r.init_data_match == true end) and
    $g.overall_ok == true and $g.nonce_binding_ok == true) |
  [$g.devices[] | select(.arch == "HOPPER" or .arch == "BLACKWELL") | .ueid] |
  select(length == $p.gpu_count and all(.[]; type == "string" and length > 0) and
    (unique | length) == $p.gpu_count)' "$work/result"
