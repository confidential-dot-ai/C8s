# Exercise the disconnected nginx workload

Use the pilot with one GPU worker, its TA outside the worker, the reviewed `demo-nginx` grant in the canonical allowlist, and a signed router manifest serving the sample. The test deploys [the digest-pinned sample](../../../samples/nginx-confidential-pod.yaml) to the prepared `demo` namespace, waits for a normal renewal, stops the worker VM and boots a fresh QEMU process. The released v0.113.1 CLI lacks site-selected Intel verification. Use an approved build containing the [site collateral CLI change](https://github.com/confidential-dot-ai/confidential-kubernetes/pull/1943). Check that `c8s verify --help`, `c8s ta verify --help` and `c8s ta ca --help` each list `--tdx-collateral-profile`. Keep the operator workstation, site gateway, observer clocks and their evidence storage independently trusted.

## Arm the site gateway before installation

Route all host, TA, worker and CLI traffic through an independent, dedicated Linux gateway. Use separate routable addresses for the host and the bridged TA and worker guests. The gateway must see all four sources before NAT, including workstation and guest DNS to the site resolver. Use a non-forwarding site DNS service, ordinary UDP/TCP 53, and private registries and endpoints with no upstream proxies. Include every ingress interface, approved destination IP and permitted query name (including registry aliases) in the reviewed `network.json`. A site with another uplink, an encrypted DNS relay or local filtering before observation needs equivalent coverage at those boundaries.

```json
{"interfaces":["pilot0"],"destinations":["10.1.0.10","10.1.0.11"],
 "dnsNames":["registry.site.example","time.site.example"], "pilotId":"tdx-b200-01","pilotEndUtc":"2026-12-15T18:00:00Z",
 "refreshObserverKey":"/etc/site/observer.pub","verifierImage":"sha256:<approved 64 lowercase hex characters>",
 "sources":{"host":["10.2.0.2"],"ta":["10.2.0.3"],"worker":["10.2.0.4"],"cli":["10.2.0.5"]}}
```

On the gateway install nftables, tcpdump, iproute2, systemd and Python 3.11 or newer. Run the recorder before starting the empty-cache install. It creates its own nftables table, permits the listed destinations on the pilot ingress interfaces, counts and drops all other gateway-local and forwarded IP traffic, and records DNS. Keep one continuous recording from before installation through the first pull, a triggered guest background refresh, worker restart and the repeat run in the pilot’s final 24 hours. Approve the scheduled `pilotEndUtc` in the configuration before arming the recorder. It retains that configuration with the capture, and the audit compares it with the independently approved copy.

```bash
sudo test/e2e/offline/record-network.sh network.json gateway-recording
```

The pilot starts when the empty-cache installation begins. Immediately before starting the installer, record the actual UTC on the trusted gateway with `date -u +%FT%TZ | sudo tee gateway-recording/pilot-start-utc`. Use synchronized, authenticated site time on all observers. The audit compares their recorded UTC intervals directly. Correct clock disagreement and repeat any affected run. Each source must issue a site DNS query during the recording for its observation to count. Keep the results private.

## Verify renewal and restart

On the workstation set `TA_URL`, `WORKLOAD_URL` (a privately reachable armTLS endpoint for the sample), `NGINX_URL` (the HTTPS route with a valid router SAN), `SITE_PROFILE`, `TA_PIN`, `WORKER_PIN` and `ALLOWLIST` from independently approved inputs. The worker image policy must include the launch approver key. Set `ACCEPTED_POLICIES` to the comma-separated reviewed `sha256:<hex>` policy-history digests through admission. Set `ROUTE_DIGEST` to the approved route-manifest digest in lowercase hex and `NGINX_BODY_SHA256` to the SHA-256 of the expected response bytes from the pinned image. Keep these files read-only throughout the run.

Set `WORKER_HOST` to the verified SSH alias of the assigned pilot host. The account needs non-interactive sudo for stopping `c8s-offline-worker.service` and running the installed worker launch script. Set `RENEWAL_TIMEOUT_SECONDS` above the deployment's normal renewal interval. Run from the release source tree using the operator kubeconfig.

```bash
test/e2e/offline/lifecycle.sh nginx-run
```

Each phase retains the verified workload certificate SHA-256 and sandbox ID, router receipt, serving certificate, verification result and response bytes. The trusted harness generates a fresh 32-byte challenge and records the serving leaf on the same TLS connection that carries the HTTP request. The CLI’s file-mode verdict reports `fresh: false` because the harness chose the nonce. It verifies the transcript binding that nonce, leaf and route digest. Renewal must change the certificate of the same sandbox. The restart records two host service invocation IDs, a changed reported guest boot ID, and verifies the new certificate and route. The TA stays up. The trusted site supervisor witnesses the worker stop and start with the same signed worker launch document and pinned image. The launcher issues a fresh kubelet bootstrap token. The host service IDs and Kubernetes boot ID are operational observations from the launch host and control plane. Repeat the command using a new `nginx-final-day` directory in the final 24 hours of the pilot. Stop the same recorder with Ctrl-C only after the final request of that second run. Transfer the recording over the trusted operator channel.

During installation or the first run the trusted observer must authenticate the release-specific verifier log and see the **background** path finish a refresh for this pilot. Copy its exact uncolored service stdout line (timestamp, INFO, `selected_tdx:`, JSON) to `gateway-recording/refresh-event.log`. Record a pre-trigger journal cursor, run `systemctl kill -s HUP --kill-whom=main attestation-api.service` in the measured guest and export the new matching message via `journalctl -u attestation-api.service --after-cursor "$CURSOR" -o cat`. The audit requires a successful `sighup` event with `intel_collateral` scope and matches its generation, digest and authenticated `siteTime` verbatim to the witness. The signed witness attests to the observed Intel background check. The NVIDIA scope remains pending a qualified implementation and its own authenticated observation. Record the site-observed UTC, authenticated generation and snapshot digest from that refresh. Use a reviewed guest containing the [selected Intel SIGHUP recheck](https://github.com/confidential-dot-ai/attestation-rs/pull/177). A release lacking this completion event cannot pass the audit. The observer signs this witness on the trusted workstation using the Ed25519 key whose public half is independently pinned in the configuration.

```bash
jq -n --slurpfile cfg network.json --arg utc "$OBSERVED_UTC" --arg snapshot "$SNAPSHOT_SHA256" --argjson gen "$GENERATION" \
  --arg source "$(sha256sum < gateway-recording/refresh-event.log | cut -d' ' -f1)" \
  '{scope:"intel_collateral",event:"background-refresh-succeeded",pilotId:$cfg[0].pilotId,verifierImage:$cfg[0].verifierImage,observedUtc:$utc,snapshotSha256:$snapshot,generation:$gen,eventSha256:$source}' > gateway-recording/refresh.json
openssl pkeyutl -sign -inkey "$OBSERVER_KEY" -rawin -in gateway-recording/refresh.json -out gateway-recording/refresh.sig
test/e2e/offline/network.py audit network.json gateway-recording nginx-run nginx-final-day
```

A passing pilot retains two completed lifecycle runs showing authorized nginx responses after renewal and worker cold boot, and one passing gateway audit. The audit checks both ordered intervals against the continuous recording. The final run must begin within 24 hours of the approved end and finish before it. The pilot-wide checks require OpenSSL, tshark, observed DNS queries from each source, only approved DNS names, zero denied packets, unchanged gateway rules and a capture with zero kernel drops. Retain the site's authenticated selection and snapshot IDs alongside the verdicts. When the site has completed the pilot it can remove the recorder's filter with `sudo nft delete table inet c8s_pilot`.
