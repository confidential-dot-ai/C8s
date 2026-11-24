# Verify a worker's GPU boot evidence

The measured worker router serves `GET /.well-known/c8s/gpu-attestations`.
Each entry in `workers` names a discovered worker. An `attested` entry contains
its Linux `boot_id`, base64 `nonce`, CPU `platform` and `evidence`, the NVIDIA
SPDM bundle in `nvidia_gpu`, and any attached `collateral`. A CPU-only boot
returns `no_gpu` and its boot ID. An unreadable worker returns `unavailable`.
Discovery uses the same IPv4-based node names as worker registration.
Compare the list with your own worker inventory because Kubernetes controls discovery.
The `Last-Modified` header dates the last completed refresh. A failed worker read
clears its evidence, and an observation older than 90 seconds becomes `unavailable`.
Incomplete discovery, a list exceeding 1,024 Nodes or 16 MiB, or an inventory
exceeding the 32 MiB snapshot budget returns HTTP 503.

The worker collects this evidence before enabling GPU CC Ready. Each boot
chooses its own nonce. Repeated downloads can verify the same historical
boot even after that worker has stopped. Names and boot IDs are inventory
metadata. The CPU and GPU reports bind the nonce. Establishing that a
particular request ran on a particular GPU requires separate evidence.

## Fetch through a verified router

Use Bash, jq, OpenSSL and curl 7.88+ with an OpenSSL backend. Set `ROUTER`
to the HTTPS origin and `ROUTE_DIGEST` to the expected route digest. Supply
your deployment's router image policy, mesh CA and trusted HTTPS CA bundle.
On an ACME deployment you can use the system CA bundle for `HTTPS_CA`.
The function checks the leaf curl actually saw against the attested leaf on
every download. A renewal between the two connections requires a new fetch.
See [router verification](verify.md).

```bash
set -euo pipefail
fetch() {
  local tmp leaf expected
  tmp=$(mktemp -d)
  (
    trap 'rm -rf "$tmp"' EXIT
    c8s verify "$ROUTER" --kind lb --mode attest-lb -o json \
      --mesh-ca mesh-ca.pem --image-policy-file router-pins.json \
      --route-digest "$ROUTE_DIGEST" > "$tmp/verdict"
    expected=$(jq -er 'select(.verified == true and .measurement_pinned == true)
      | .serving_leaf_sha256 | select(length == 43)' "$tmp/verdict")
    curl --noproxy '*' -fsS --cacert "$HTTPS_CA" --max-time 30 \
      -o "$tmp/body" -w '%{certs}' "$ROUTER/.well-known/c8s/gpu-attestations" > "$tmp/certs"
    leaf=$(openssl x509 -in "$tmp/certs" -outform DER | openssl dgst -sha256 -binary |
      openssl base64 -A | tr '/+' '_-' | tr -d '=')
    [[ "$leaf" == "$expected" ]] || exit 1
    jq -eS '.workers |= sort_by(.name)' "$tmp/body"
  )
}
fetch > before.json
jq -r '.workers[] | [.name,.status,.boot_id] | @tsv' before.json
```

## Verify the downloaded reports

Run a separate attestation-api on your own verifier host, using NVIDIA's
production NRAS and AMD or Intel collateral endpoints. The example targets
the v0.6.0 HTTP contract. The worker CI builds its GPU collector from the
node-image source pin and pre-stages the binary with libnvat. The verifier
only needs the GPU verification feature. On a machine with Docker, start
the matching verifier from a trusted checkout of this release.

```bash
digest=$(jq -er '.builds["node-image"].attestation_api_digest' .github/build-pins.json)
docker run --rm -d --name gpu-boot-verifier -p 127.0.0.1:8400:8400 \
  "ghcr.io/confidential-dot-ai/attestation-api@$digest"
```

The pin commands also require `xxd`. Set `GPU` to the expected worker name and `GPU_COUNT` to its expected number
of GPUs, excluding switches. Source the expected image measurements from a
trusted build manifest and the worker document from the admitted launch
configuration. Use the exact document bytes, including the final newline.
The following commands take lowercase hex digests from your trusted inputs.
Set `PLATFORM` to the expected `tdx` or `snp`.

```bash
b64digest() { [[ "$1" =~ ^[0-9a-f]{96}$ ]] || return 1; printf '%s' "$1" | xxd -r -p | openssl base64 -A; }

case "$PLATFORM" in
  tdx)
    jq -n --argjson n "$GPU_COUNT" --arg m "$(b64digest "$MRTD")" \
      --arg r1 "$(b64digest "$RTMR1")" --arg r2 "$(b64digest "$RTMR2")" \
      '{platform:"tdx",gpu_count:$n,mrtd:$m,rtmr1:$r1,rtmr2:$r2}' > gpu-pins.json ;;
  snp)
    jq -n --argjson n "$GPU_COUNT" --arg m "$(b64digest "$LAUNCH_DIGEST")" \
      '{platform:"snp",gpu_count:$n,launch_digest:$m}' > gpu-pins.json ;;
  *) exit 2 ;;
esac
```

```bash
worker() {
  jq -e --arg n "$1" '[.workers[] | select(.name == $n)] |
    select(length == 1) | first' "$2"
}
worker "$GPU" before.json > worker.json
samples/verify-gpu-boot.sh worker.json gpu-pins.json worker.yaml
```

Success prints distinct NVIDIA device UEIDs. The script requires both
nonce checks, a verified CPU signature and collateral, and a passing NVIDIA
verdict for the expected GPU count. The verifier contacts NRAS to appraise
the SPDM reports and check signed device claims. v0.6.0 obtains its own
collateral. On TDX the script checks an up-to-date Intel TCB and the worker
document's RTMR[3] boot seed. On SNP it checks the launch digest and the
document's SHA-256 in HOST_DATA. Distinct UEIDs identify the reported devices. An exact device
inventory can additionally pin those UEIDs. See the [launch binding](launch-configuration.md#launch-binding).

## Release check on a disposable cluster

Use a known inventory with one CPU-only worker (`CPU`) and one worker with
at least two GPUs (`GPU`). Use the same helper functions and pins as above.
Wait for both entries to settle, then save `before.json` again. Check that
only these two workers appear, and verify the selected worker as above. Set
`TEST_CONTEXT` and `RELEASE` to this disposable cluster and its Helm release.

```bash
jq -e --arg cpu "$CPU" --arg gpu "$GPU" '
  (.workers | map(.name) | sort) == ([$cpu,$gpu] | sort) and
  any(.workers[]; .name == $cpu and .status == "no_gpu") and
  any(.workers[]; .name == $gpu and .status == "attested")' before.json
(( GPU_COUNT >= 2 ))
: "${TEST_CONTEXT:?set the disposable cluster context}" "${RELEASE:?set the test Helm release}"
kubectl --context "$TEST_CONTEXT" -n c8s-router rollout restart deployment/"$RELEASE-router"
kubectl --context "$TEST_CONTEXT" -n c8s-router rollout status deployment/"$RELEASE-router"
# Allow the restarted collector to finish its first inventory.
fetch > restarted.json
cmp before.json restarted.json
```

Reboot just the GPU worker using your test VM manager. For a local libvirt
test, `virsh -c qemu:///system reboot "$GPU_TEST_DOMAIN"` requests a guest
reboot. After the worker rejoins at its original address and a discovery
poll completes, check the new boot and verify the fresh record independently.

```bash
fetch > after.json
jq -e --slurpfile old before.json --arg gpu "$GPU" '
  (.workers | map(.name)) == ($old[0].workers | map(.name)) and
  ([.workers[] | select(.name != $gpu)] == [$old[0].workers[] | select(.name != $gpu)]) and
  ((.workers[] | select(.name == $gpu)) as $new |
   ($old[0].workers[] | select(.name == $gpu)) as $was |
   $new.status == "attested" and $new.boot_id != $was.boot_id and
   $new.nonce != $was.nonce and $new.evidence != $was.evidence and
   $new.nvidia_gpu != $was.nvidia_gpu)' after.json
worker "$GPU" after.json > fresh.json
verify() { samples/verify-gpu-boot.sh "$1" gpu-pins.json worker.yaml; }
verify fresh.json
jq --slurpfile old worker.json '.nonce = $old[0].nonce' fresh.json > wrong-nonce.json
jq --slurpfile old worker.json '.evidence = $old[0].evidence' fresh.json > wrong-cpu.json
jq --slurpfile old worker.json '.nvidia_gpu = $old[0].nvidia_gpu' fresh.json > wrong-gpu.json
for altered in wrong-{nonce,cpu,gpu}.json; do
  if verify "$altered"; then echo "accepted $altered" >&2; exit 1; fi
done
verify fresh.json
```
