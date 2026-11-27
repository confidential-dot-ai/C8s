# Site collateral for Intel TDX

An operator-controlled HTTPS origin supplies the current generation of Intel
verification collateral and the site's authenticated time. Run the origin
outside the hypervisor, control plane and Trust Authority. Provision its exact
TLS leaf and the media signer's Ed25519 public key on the trusted workstation.
Distribute key rotations over the same independent channel.

Create the verifier profile on that workstation. The target names the
provisioning inventory whose PCK certificates and FMSPC the operator approved.

```sh
jq -n --arg origin https://collateral.site.example --arg target "$INVENTORY_ID" \
  --rawfile tlsCertificate site-tls.crt --rawfile mediaPublicKey media-public.pem \
  '$ARGS.named' > site-profile.json
```

## Site endpoint

A client opens a new TLS 1.3 connection directly to the configured origin for
each selection. It verifies the server's hostname and exact provisioned
certificate. The certificate authenticates the site's clock even at cold boot.
The client checks the leaf's validity interval against the returned site time.

| Request | Response from the site |
| --- | --- |
| `GET /active` with `X-C8s-Challenge` (32 random bytes in hex) | Current selection as JSON, the echoed challenge, and `X-C8s-Time` as RFC 3339 UTC. |
| `GET /snapshots/<sha256>.json` | Exact bytes of the selected manifest. |
| `GET /snapshots/<sha256>.sig` | Raw Ed25519 signature over those bytes. |
| `GET /objects/<sha256>` | Raw bytes named in the manifest. |

For each challenge the origin obtains authenticated current site time, reads
the active selection from operator-controlled storage, and returns both over
that connection. Disable caching and redirects. Return an error if selection or
time is unavailable. Store the active selection separately from replaceable
object storage. After reading the objects, the client confirms the selection again and uses the
new site time to check the Intel collateral. It discards the selection after
each verification.

## Signed manifest

The selection contains a positive integer `generation` and the lowercase
hexadecimal `sha256` of the complete manifest. The manifest binds
`generation`, the site profile's `target`, `expiresAt` (RFC 3339 UTC), and
an `objects` map. Each Intel object is keyed by the exact Intel URL the quote
verifier requests. Its `sha256` covers its body. Its `header` maps HTTP header
names to arrays of original values. Preserve the TCB Info, TD QE identity
and PCK CRL issuer-chain headers, including their percent encoding. The
root CRL has no issuer-chain header. The Intel verifier checks the signed
objects against its own Intel trust root at site time.

Use an independently authenticated build inventory for image and launch pins.
Store the profile under workstation access control or bind it into the measured
guest build. An HTTPS endpoint chosen by the hypervisor cannot supply these
trust anchors.
