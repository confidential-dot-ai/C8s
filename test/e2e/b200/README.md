# Measure the B200 offline verification window

The verifier maintainer and site operator run this qualification before selecting a guest verifier release. It produces a fresh hardware verdict and measures how much time the site has to replace the NVIDIA collateral. The attestation-rs v0.6.0 verifier pinned by C8s uses NRAS. A successful standalone SDK test still needs integration in the measured worker's CPU/GPU boot gate.

## Prepare the qualification

Use the eight assigned B200s in CC mode in a verifier environment that the operator trusts independently of the launch host. Bring the verified nvattest binary, Bash, jq, OpenSSL 3, Python 3.11 or newer and chrony. Install the site's NTS CA independently on this system and the trusted workstation. Build nvattest from the [pinned SDK source](https://github.com/NVIDIA/attestation-sdk/tree/0c1be386a8fbb8f2766a6a556d10df86f5fed9d3).

1. Enroll the eight assigned NVIDIA UEIDs in a JSON array of strings named `ueids` in a qualification approval file (`approval.json`). These are hardware attestation identities. Retain the owner’s signed association of each UEID to its enrolled PCI address, UUID, model, driver and VBIOS version. Put the UEIDs in that order and include the SHA-256 of the corresponding headerless `nvidia-smi --query-gpu=pci.bus_id,uuid,name,driver_version,vbios_version --format=csv,noheader | LC_ALL=C sort` output as `inventorySha256`. The script compares the exact inventory and independently verifies the eight hardware UEIDs.
2. Obtain the exact GPU report, driver RIM and VBIOS RIM certificate chains for this assignment. Collect each distinct issuing CA in `intermediates.pem`. For each certificate requiring OCSP, add its name and lowercase DER SHA-256 to the `certificateFingerprints` JSON object. Keep that inventory and the NVIDIA vendor roots on the trusted workstation.
3. Include the approved nvattest executable SHA-256 as `nvattestSha256`, the policy file’s SHA-256 as `policySha256`, maximum status age as integer `maxStatusAgeSeconds`, and the expected RIM response body hashes as a nonempty array `rimSha256`. Have the owner sign the complete approval with its out-of-band enrollment record, retain the signature and independently authenticated digest before the run. Stage site RIM and OCSP responders serving the signed vendor bytes. Provision a private endpoint for this run accessible only by its verifier, start empty logs, and log each response body SHA-256. Keep each original response body and close the endpoints immediately after the SDK exits.
4. Record UTC Unix seconds from authenticated site-synchronized clocks before requesting fresh vendor RIM and certificate status on the connected workstation and after those exact bytes have been transported, checked and imported at the disconnected site. Include the complete operator turnaround. The vendor signs `thisUpdate` independently of both timestamps. Stage, on the workstation, one directory per enrolled name containing `cert.pem`, `issuer.pem` and `ocsp.der`. Keep the target's intermediate certificates together in `intermediates.pem`.
5. Block internet egress before verification. Record the site endpoints, DNS activity and egress-deny logs for the verifier and the OCSP responder. The operator must confirm that neither process tried a public destination.

## Run on hardware

Substitute the approved site name, NTS CA and isolated site responder URLs below. Run from the repository root. Each invocation checks local clock agreement with a fresh NTS measurement. The hardware command creates a private directory and refuses to overwrite an earlier run.

```bash
export B200_NTS_SERVER=time.site.example B200_NTS_CA=/etc/site/nts-ca.pem
test/e2e/b200/verify-gpus.sh approval.json "$APPROVAL_SHA256" \
    https://rim.site.example https://ocsp.site.example approved-cached-status.rego b200-run
```

Retain the assignment, policy digest, hardware inventory, per-device CC status, challenge and SDK result. Check the policy digest against the signed approval and the reported driver and VBIOS against the approved build inputs. Keep hardware identifiers and response logs in the site's evidence store.

## Check the refresh window

Transfer the complete capture and the isolated responders’ logs to the trusted workstation over authenticated channels. Export their body digests for this run, one lowercase SHA-256 per line, into `served-ocsp.sha256` and `served-rim.sha256`. Use the independent approval digest, the same NTS variables and the observed timestamps.

```bash
test/e2e/b200/refresh-window.py b200-run "$APPROVAL_SHA256" responses/ nvidia-roots.pem \
    intermediates.pem served-ocsp.sha256 served-rim.sha256 \
    "$REFRESH_STARTED_UNIX" "$IMPORT_FINISHED_UNIX" > b200-window.json
```

A zero exit code and the JSON report establish the measured NVIDIA window. The report binds the challenge, verdict, approval, eight UEIDs, RIM hashes and per-certificate response hashes. It names the limiting certificate or chain file, the earliest UTC expiry, conservative remaining seconds and measured turnaround. It checks each signed OCSP response against its enrolled certificate and issuer. The pinned SDK computes a missing `nextUpdate` from `thisUpdate` plus 3,600 seconds. [SDK expiry calculation](https://github.com/NVIDIA/attestation-sdk/blob/0c1be386a8fbb8f2766a6a556d10df86f5fed9d3/nv-attestation-sdk-cpp/src/nv_ocsp.cpp#L305-L309) · [SDK fallback interval](https://github.com/NVIDIA/attestation-sdk/blob/0c1be386a8fbb8f2766a6a556d10df86f5fed9d3/nv-attestation-sdk-cpp/include/nv_attestation/nv_ocsp.h#L81). The owner age and certificate expiry may shorten this deadline. The conservative remaining validity must exceed one more complete measured trip. A smaller bound in the measured guest must also govern release. For a negative run, remove one enrolled certificate’s OCSP response from a fresh isolated responder, repeat the hardware command in a new directory and retain its exit status, stderr and the failed request. Restore it, then block UDP/123 or TCP/4460 to the NTS server for another fresh run and require the clock preflight to report `could not measure site time` before collection.

For C8s acceptance the measured boot gate must also verify fresh CPU-bound evidence, compare the complete authenticated device assignment and prevent containerd from starting when one assigned device lacks evidence. The released worker does not yet map this SDK experiment to locally selected Intel/GPU collateral. Acceptance requires a measured verifier that rechecks the active generation at site time and preserves the ordinary CPU/GPU challenge binding. Run cold-restart and workload checks on that integrated release. CI runs `make test-e2e-b200-fixtures` using synthetic claims shaped from the pinned SDK and signed test OCSP responses.

Use the authenticated capture to [prepare a mixed collateral candidate](../../../docs/offline-mixed-candidate.md).
