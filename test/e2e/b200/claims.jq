def good_chain:
    .["x-nvidia-cert-status"] == "valid"
    and .["x-nvidia-cert-ocsp-status"] == "good"
    and .["x-nvidia-cert-ocsp-response-valid"] == true;

def verified_rim($kind):
    .["x-nvidia-gpu-" + $kind + "-rim-signature-verified"] == true
    and .["x-nvidia-gpu-" + $kind + "-rim-version-match"] == true
    and (.["x-nvidia-gpu-" + $kind + "-rim-cert-chain"] | good_chain);

def verify_device:
    if (.["x-nvidia-device-type"] == "gpu" and .eat_nonce == $nonce
        and .secboot == true and .dbgstat == "disabled" and .measres == "success"
        and .["x-nvidia-gpu-attestation-report-nonce-match"] == true
        and .["x-nvidia-gpu-attestation-report-signature-verified"] == true
        and .["x-nvidia-gpu-attestation-report-cert-chain-fwid-match"] == true
        and (.["x-nvidia-gpu-attestation-report-cert-chain"] | good_chain)
        and verified_rim("driver") and verified_rim("vbios"))
    then .ueid else error("GPU evidence or collateral rejected for UEID \(.ueid)") end;

if length == 1 then .[0] else error("expected one SDK verdict") end |
if (($expected | length) != 1 or ($expected[0] | type) != "array" or ($expected[0] | length) != 8
    or ($expected[0] | unique | length) != 8 or any($expected[0][]; type != "string" or length == 0))
then error("expected eight distinct enrolled GPU UEIDs")
elif .result_code != 0 or (.claims | type) != "array" then error("local SDK rejected GPU evidence")
elif (.claims | map(verify_device) | sort) != ($expected[0] | sort) then error("verified GPU UEIDs differ from assignment")
else "Verified fresh GPU evidence for eight assigned devices." end
