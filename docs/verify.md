# Verify a deployment

Prove from outside the cluster that a C8s endpoint is a genuine TEE —
hardware-isolated memory the host cannot read — running code you accept, and
that the router serves the routes you expect. `c8s verify` fetches the
endpoint's attestation evidence, checks it against the AMD or Intel signature
chain and your pins, and prints a verdict. This page covers the two components
an outside verifier reaches: the router (`--kind lb`), the front door that
terminates public TLS and routes application traffic, and the Trust Authority (TA) (`--kind ta`),
which verifies evidence and signs workload certificates. `--kind workload`
verifies a pod's own armTLS certificate, for a verifier that can dial the pod.
Terms are defined in [glossary.md](glossary.md).

Guarantee: [Anyone can verify it](guarantees.md#anyone-can-verify-it).

Prerequisites:

- The `c8s` binary of the release the cluster runs ([releases.md](releases.md)).
- HTTPS to the router, and to the TA at the address the install named with
  `--ta-address`: the front door relays neither TA endpoint used here.
- Outbound HTTPS to `kdsintf.amd.com` for AMD endorsement certificates
  evidence does not carry inline.
- For TDX, outbound HTTPS to `api.trustedservices.intel.com`
  and `certificates.trustedservices.intel.com` for Intel collateral.
- The measurements you accept, from the operator or from the image build.

## Choose the pins and the CA anchor

A launch measurement is the digest of what a confidential VM booted. Each C8s
component runs inside a node CVM, so a pin is that node image's launch
measurement, shared by nodes booted from the same image. Pick one input:

| Input | What it pins |
|---|---|
| `--measurements <SHA384_HEX>`, or `--measurements-file FILE` (one digest per line) | Allowed launch measurements, repeatable or comma-separated. On TDX the value is the MRTD, which measures the firmware only. |
| `--image-manifest FILE` | One TDX guest image: `mrtd`, `rtmr1` and `rtmr2` from a single build, each compared exactly. Excludes both inputs above. |
| `--image-policy-file FILE` | A measurements config: per-image measurement, registers, and optional launch-key anchor. Excludes the three inputs above. |

`c8s measurements derive` builds a measurements config from an image build's
`manifest.json`, and `c8s measurements lint` reports what one pins. On TDX
prefer `--image-manifest`, which pins the guest kernel and rootfs too:
`--measurements` with `--mesh-ca` passes with a warning that both are
unmeasured, and alone it fails. With no measurement input the command still
runs, and the verdict says only that the endpoint is some TEE:

```text
  WARNING:      no --measurements pinned — any genuine TEE is accepted (UNSAFE for production)
```

That leniency is this client-side check's alone: in-cluster armTLS peers refuse
a pin set naming no guest before any request ([armtls.md](armtls.md)).

Pass `--mesh-ca` too with `--kind lb` and `--kind workload`: the mesh CA is
what the TA signs their certificates with, and without it the certificate chains
to a CA the endpoint committed itself, leaving its deployment and its stamped
names unproven. The TA's own serving certificate is self-signed, so `--kind ta`
refuses `--mesh-ca`, `--sandbox-id`, `--workload`, `--client-document` and
`--allowlist`. Read the
bundle from the TA:

```sh
c8s ta ca --ta-url https://<TA_ADDRESS> --ta-image-policy-file cds-pin.json --out mesh-ca.pem
```

`<TA_ADDRESS>` is the `<host>:<port>` the install named with `--ta-address`,
and `cds-pin.json` the document it named with `--ta-pin`, which pins the guest
the TA runs. These commands take that document and no launch digest of their own.
The certificate SHA-256 digests print on stderr; record them: a TA restart
replaces the bundle.

## Derive the pins yourself

An operator can hand you the measurements; you do not have to take their word
for what a published node image measures. Every C8s node image publishes the
`manifest.json` its build recorded, and `c8s measurements derive` turns that
into a measurements config ([measurements.md](measurements.md)). An AKS or GKE
node image is the provider's and publishes none, so its pins are read from a
node instead ([cloud-ta.md](cloud-ta.md#node-pins-on-aks-and-gke)). You need
`oras`, `jq`, outbound HTTPS to `ghcr.io`, and the release tag the cluster runs
([releases.md](releases.md)).

Fetch the manifest layer of the image you intend to accept:

```sh
IMAGE=ghcr.io/confidential-dot-ai/guests/worker
mkdir worker-tdx
LAYER=$(oras manifest fetch "$IMAGE:<RELEASE_TAG>-tdx" | jq -er \
  '[.layers[] | select(.annotations["org.opencontainers.image.title"]
     == "manifest.json")][0].digest')
oras blob fetch "$IMAGE@$LAYER" --output worker-tdx/manifest.json
```

`<RELEASE_TAG>` is the release the cluster runs; the TEE term of the tag is
`tdx` or `sev-snp`. The `-kubevirt` image is the same disk in another format, so
derive from these tags for it too. Derive the config and read back what it pins:

```sh
c8s measurements derive --tee tdx --out measurements.json worker-tdx
c8s measurements lint measurements.json
```

```text
worker-tdx: 1 tdx entry from worker-tdx/manifest.json
ok: tdx, 1 image(s)
  worker-tdx: 2 register pin(s)
```

The two register pins are RTMR[1] and RTMR[2], so the file pins the guest
kernel and rootfs, not the firmware alone. An SNP image has no registers and
contributes one entry per vCPU count. Pass the file as `--image-policy-file`
wherever this page uses `--measurements`; against the TA, name the node
identities it serves with `--served-policy-file` to check the set the TA says it
enforces:

```sh
c8s ta verify https://<TA_ADDRESS> --image-policy-file cds-pin.json \
    --served-policy-file measurements.json
```

Deriving reads what the build measured; it does not rebuild the image.
Released images are signed with a module-signing key that is not published, so
their bytes cannot be reproduced outside the build.

## Run the check

Verify the router's attested handshake, which binds the connection you opened
and the routes the router serves ([routes-evidence.md](routes-evidence.md)
explains `attest-lb` and `attest-pq`). The router serves `attest-lb` on an
installed cluster, where its public TLS mode is `cds`, and on a baked node
whose launch file selects `cds` or `acme`. The TA answers on its own endpoint,
where a hostname or chain mismatch does not fail the run: the evidence is
verified, not WebPKI.

```sh
c8s verify https://<ROUTER_HOST> --kind lb --mode attest-lb \
    --measurements <NODE_MEASUREMENT> --mesh-ca mesh-ca.pem \
    --route-digest <ROUTE_DIGEST>
c8s ta verify https://<TA_ADDRESS> --image-policy-file cds-pin.json
```

`<ROUTER_HOST>` is the router's public host and `<ROUTE_DIGEST>` a digest from
"Check the routes" below. Add `--server-name <HOST>` when the name you dial is
not the name the endpoint serves, as through a port-forward.

## Require a current Intel TCB on TDX

`c8s verify` requires Intel to rate each TDX VM `UpToDate` by default.
Supply the VM's expected image policy to check its measurements in the same
invocation. For example, to check the TA, run

```sh
c8s ta verify https://<TA_ADDRESS> --image-policy-file cds-pin.json \
    --tdx-tcb-status UpToDate
```

Each verification, including `--from-file`, fetches signed TCB information,
quoting enclave (QE) identity, and the PCK and root CA revocation lists from
Intel PCS within a positive `--timeout`. It rejects revoked certificates and
invalid or expired collateral. The platform and QE must each have an accepted
status. The TDX module must also match when the quote carries a nonzero module
version (`TEE_TCB_SVN[1]`).

Supplying `--tdx-tcb-status` replaces the default set. Repeat the flag to
accept multiple statuses. Every component must have a status in the set, so
keep `UpToDate` when you add a weaker one: an out-of-date platform usually has
an up-to-date QE. The CLI reports the status Intel's signed collateral assigns,
not the values of the flag. When the platform, QE and TDX module differ, it
reports the least favourable of them. Statuses run from most to least
favourable:

1. `UpToDate`
2. `SWHardeningNeeded`
3. `ConfigurationNeeded`
4. `ConfigurationAndSWHardeningNeeded`
5. `OutOfDate`
6. `OutOfDateConfigurationNeeded`

The CLI rejects `Revoked` and refuses explicit status requirements for
evidence without a TDX quote. Use `--min-tcb-*` for SEV-SNP. With
`--tdx-offline`, the CLI skips the PCS check and warns on a passing TDX
verdict. Offline mode excludes named TCB statuses.

An online verdict reports Intel's advisories and the earliest signed
`nextUpdate` across the four collateral documents.

```text
  Intel TCB:    UpToDate (Intel PCS collateral, expires 2026-12-17T21:30:01Z)
```

`-o json` carries these as `tdx_tcb_status`, `tdx_advisory_ids` and
`tdx_collateral_expires_at`. A status outside the set fails the verdict
(exit 2), as does a response Intel did not sign or that cannot be parsed.
Collateral that cannot be fetched exits 3, so a gate can retry.

## Read the verdict

The first line is the verdict and the exit code repeats it:

| First line | Exit | Meaning |
|---|---|---|
| `✓ VERIFIED  (attestation-go backend)` | 0 | Evidence verified and every check you asked for passed. |
| `~ PARTIALLY VERIFIED  (attestation-go backend)` | 4 | Evidence verified, but a property it presents is not proven; each prints as `not proven:`. |
| `✗ NOT VERIFIED  (attestation-go backend)` | 2 | Verification or a policy check failed; `reason:` names it. |

Exit 1 (usage) prints only an `error:` line on stderr. Exit 3 prints that line
and no verdict when no evidence, AMD KDS certificate or Intel PCS collateral
could be fetched, and a `✗ NOT VERIFIED` verdict when a policy-history fetch
could not be reached. A passing router
check prints, with `…` for elided lines:

```text
✓ VERIFIED  (attestation-go backend)
  source:       attest-lb endpoint https://router.example.com:443/.well-known/c8s/attest-lb?nonce=<NONCE>
  verified at:  2026-10-27T14:00:00Z
  platform:     snp
  measurement:  <SHA384_HEX>
  …             TCB, serving leaf, cert body, chain anchor, binding
  route digest: <ROUTE_DIGEST>
                pinned: matches --route-digest
  WARNING:      the attested front door was observed on this verify's single connection to a single router replica at a single instant: … clients must verify their own connection
  sandbox id:   <SANDBOX_ID>
                verified: the leaf chains to the supplied mesh CA
```

`WARNING:` names a limit of the policy you gave, such as an unpinned
measurement, or of the observation made: the front-door warning above says the
verdict covers one connection to one router replica at one instant, so every
client has to verify its own connection. A freshness `note:` says freshness is
not proven: no nonce is bound, or the bound nonce was caller-chosen rather than
generated by this run (a saved receipt).

`-o json` always carries `verified` and `measurement_pinned`, and carries
`partial`, `not_proven` and `warnings` when they have content, so a gate
requiring `verified: true` fails closed on a partial verdict.

The `*_note` fields and `chain_anchor` say what stands behind a reported
value. A failed verdict states no passed policy check. Of the fields a check
qualifies it keeps:

- `sandbox_id` and `workload` with their `not verified:` notes.
- `operator_keys` and `operator_keys_note` only when the note says why the set
  was not pinned or not fetched; otherwise both are dropped.
- `binding`, without the front-door handshake clause.

`chain_anchor`, `measured_policies`, `init_data_note` and `route_note` never
appear on a failed verdict. `cert_body` describes how the leaf's body was
authenticated when the evidence was read, and stays on every verdict.

## Check the routes

The attested modes require exactly one route check, which decides the route
digest their evidence has to bind:

| Flag | Check |
|---|---|
| `--route-digest HEX` | The evidence must bind this digest. Repeat the flag to accept the old and the new digest while a route change rolls out. |
| `--operator-keys FILE` | Fetch the manifest from the router's `/.well-known/c8s/routes`, served when route publication is enabled, verify the operator-signed token that authorized the write under these PEM public keys, and require the evidence to bind that manifest's digest. |
| `--routes-floor REV:HEX` | With `--operator-keys`: refuse a published manifest whose revision is below `REV`, or equal with another digest. |

A verified session stays on what it attested: once the manifest or the router's
own allowlist digest changes, the router answers 503 and the client attests
again ([routes-evidence.md](routes-evidence.md#session-binding)).

Get a digest from the operator who wrote the manifest, from a manifest file
with `c8s routes digest FILE`, or from the TA, which refuses an unpinned endpoint:

```sh
c8s routes show --url https://<TA_ADDRESS> --image-policy-file cds-pin.json
```

[releases.md](releases.md) shows which commit a release tag names.
