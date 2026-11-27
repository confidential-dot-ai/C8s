def chain: {"x-nvidia-cert-status":"valid", "x-nvidia-cert-ocsp-status":"good", "x-nvidia-cert-ocsp-response-valid":true};
    def rim($kind): {("x-nvidia-gpu-"+$kind+"-rim-cert-chain"):chain,
        ("x-nvidia-gpu-"+$kind+"-rim-signature-verified"):true, ("x-nvidia-gpu-"+$kind+"-rim-version-match"):true};
    {result_code:0,claims:[$input[0][] | {ueid:.,eat_nonce:$nonce,dbgstat:"disabled",secboot:true,measres:"success",
        "x-nvidia-device-type":"gpu", "x-nvidia-gpu-attestation-report-nonce-match":true,
        "x-nvidia-gpu-attestation-report-signature-verified":true, "x-nvidia-gpu-attestation-report-cert-chain-fwid-match":true,
        "x-nvidia-gpu-attestation-report-cert-chain":chain} + rim("driver") + rim("vbios")]}
