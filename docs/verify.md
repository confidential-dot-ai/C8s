# Verify a deployment

Prove from outside the cluster that a C8s endpoint is a genuine TEE —
hardware-isolated memory the host cannot read — running code you accept, and
that the router serves the routes you expect. `c8s verify` fetches the
endpoint's attestation evidence, checks it against the AMD or Intel signature
chain and your pins, and prints a verdict. Two components answer a verifier:
the router (`--kind lb`), the front door that terminates public TLS and routes
application traffic, and CDS (`--kind cds`), which verifies evidence and signs
workload certificates. Terms are defined in [glossary.md](glossary.md).

Prerequisites:

- The `c8s` binary of the release the cluster runs ([releases.md](releases.md)).
- HTTPS to the router, and to CDS, which the chart publishes on its own node
  port (`30808`): the front door relays neither CDS endpoint used here.
- Outbound HTTPS to `kdsintf.amd.com` for AMD endorsement certificates
  evidence does not carry inline.
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

Pass `--mesh-ca` too: the mesh CA is what CDS signs workload certificates with,
and without it the certificate chains to a CA the endpoint committed itself,
leaving its deployment and its stamped names unproven. Read the bundle from CDS:

```sh
c8s cds ca --url https://<NODE>:30808 --measurements <NODE_MEASUREMENT> --out mesh-ca.pem
```

`<NODE>` is a node address, `30808` the chart's default CDS node port, and
`<NODE_MEASUREMENT>` a pin from the table. The certificate SHA-256 digests
print on stderr; record them: a measurement identifies the image, not the
instance, and a CDS restart replaces the bundle.

## Run the check

Verify the router's attested handshake, which binds the connection you opened
and the routes the router serves ([routes-evidence.md](routes-evidence.md)
explains `attest-lb` and `attest-pq`). The router serves `attest-lb` when its
public TLS mode is `cds` or `acme` (chart default `cds`); a `webpki` front door
refuses it, leaving `--mode attest-pq`. CDS answers on its own endpoint, where
a hostname or chain mismatch does not fail the run: the evidence is verified,
not WebPKI.

```sh
c8s verify https://<ROUTER_HOST> --kind lb --mode attest-lb \
    --measurements <NODE_MEASUREMENT> --mesh-ca mesh-ca.pem \
    --route-digest <ROUTE_DIGEST>
c8s cds verify https://<NODE>:30808 --measurements <NODE_MEASUREMENT>
```

`<ROUTER_HOST>` is the router's public host and `<ROUTE_DIGEST>` a digest from
"Check the routes" below. Add `--server-name <HOST>` when the name you dial is
not the name the endpoint serves, as through a port-forward.

## Read the verdict

The first line is the verdict and the exit code repeats it:

| First line | Exit | Meaning |
|---|---|---|
| `✓ VERIFIED  (attestation-go backend)` | 0 | Evidence verified and every check you asked for passed. |
| `~ PARTIALLY VERIFIED  (attestation-go backend)` | 4 | Evidence verified, but a property it presents is not proven; each prints as `not proven:`. |
| `✗ NOT VERIFIED  (attestation-go backend)` | 2 | Verification or a policy check failed; `reason:` names it. |

Exit 1 (usage) and exit 3 (no evidence) print no verdict, only an `error:` line
on stderr. A passing router check prints, with `…` for elided lines:

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
with `c8s routes digest FILE`, or from CDS, which refuses an unpinned endpoint:

```sh
c8s routes show --url https://<NODE>:30808 --measurements <NODE_MEASUREMENT>
```

[releases.md](releases.md) shows which commit a release tag names.
