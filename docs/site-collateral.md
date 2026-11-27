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

## Prepare Intel verification collateral

On a connected workstation with authenticated current time, use the raw DCAP
quote enrolled for the target. The command authenticates the quote against
the built-in Intel root, requests the four responses for that quote, checks
revocation and requires an `UpToDate` verdict. It prints the earliest UTC
deadline across the signed documents, CRLs and certificates. Select a new
directory for each attempt.

```sh
c8s collateral prepare-intel enrolled-quote.bin "$INVENTORY_ID" 1 candidate
mkdir -p candidate/snapshots
digest=$(sha256sum candidate/manifest.json | cut -d' ' -f1)
mv candidate/manifest.json "candidate/snapshots/$digest.json"
openssl pkeyutl -sign -rawin -inkey "$MEDIA_SIGNING_KEY" \
  -in "candidate/snapshots/$digest.json" -out "candidate/snapshots/$digest.sig"
"$SITE_TIME" | c8s collateral check-intel enrolled-quote.bin site-profile.json \
  "candidate/snapshots/$digest.json" "candidate/snapshots/$digest.sig" candidate/objects
jq -n --arg sha256 "$digest" --argjson generation 1 \
  '{generation:$generation,sha256:$sha256}' >candidate/active
```

Keep the private key on the workstation. A reference quote identifies the Intel
provisioning target during import. Each connection to a running guest still
uses the ordinary attestation flow. These commands prepare the Intel subset;
GPU qualification also needs the assigned devices' RIMs, signed OCSP responses
and the approved maximum status age.

The quote generator also needs the platform's PCK certificates in its
provisioning cache. For a deployment using PCCS in offline mode, register the
platform, export the pending registration, fetch its platform collateral on
the connected machine and use the PCCS admin tool's `put` operation at the
site. Use Intel's procedure for the installed DCAP tool version.
[Intel PCCS cache management flows](https://cc-enabling.trustedservices.intel.com/intel-sgx-tdx-pccs/08/cache_management_flows/)

## Import and serve an Intel generation

Run the authority on the operator's independent system. Use two separately
owned locations, a durable selection directory and a static web directory.
Install the verified `c8s` CLI on its trusted PATH. Set `SITE_TIME` to the
site's executable that performs a fresh authenticated time query, prints one
UTC RFC 3339 timestamp and exits with an error if the clock is unavailable.
It must finish within eight seconds. Keep its credentials on the authority.

```sh
install -d -m 0750 -o root -g www-data /etc/c8s/site
install -m 0640 site-profile.json /etc/c8s/site/profile.json
install -m 0640 enrolled-quote.bin /etc/c8s/site/enrolled-quote.bin
install -m 0750 -o root -g www-data "$SITE_TIME" /etc/c8s/site/site-time
install -d -m 0755 /srv/c8s-collateral/{objects,snapshots}
scripts/airgap/import-intel candidate /etc/c8s/site /srv/c8s-collateral
```

Mount incoming media read-only with `nodev,nosuid,noexec`. For every refresh
run the same import command with the new candidate. The importer stages
candidate bytes, verifies the media signature and target, and validates all
four Intel objects under the enrolled quote. It then writes the immutable
objects and replaces the selection in one rename while holding the import
lock. The receiving machine's web server needs read access to the selection
and execute access to the authenticated clock helper.

For Apache with CGI enabled, install `active.cgi` as
`/usr/lib/cgi-bin/c8s-active`. Configure the site's pinned TLS virtual host
with these mappings, allowing read access to the static directories and
execution of the single CGI. Disable shared caches on this origin. After an
import, check the selection and time under the Apache service identity.

```sh
challenge=$(openssl rand -hex 32)
sudo -u www-data env REQUEST_METHOD=GET HTTP_X_C8S_CHALLENGE="$challenge" \
  /usr/lib/cgi-bin/c8s-active
```

The response must echo the challenge, include the site timestamp and name the
generation just imported. The CGI account has read and execute access only.

```apache
ScriptAlias "/active" "/usr/lib/cgi-bin/c8s-active"
Alias "/objects/" "/srv/c8s-collateral/objects/"
Alias "/snapshots/" "/srv/c8s-collateral/snapshots/"
```

The Intel importer rejects additional objects. Activation of a mixed
Intel/NVIDIA generation requires the qualified NVIDIA verifier to validate
the exact RIMs and OCSP responses for the enrolled GPUs.

## Measured verifier input

`c8s collateral selected-tdx PROFILE` emits the currently selected Intel
responses for an attestation service that supports a site source. It reports
the active generation and manifest digest, site time and manifest expiry in
UTC, standard base64 bodies keyed by their
original URLs, and decoded PEM issuer chains. An unavailable authority or clock
exits with status 3. The receiving service verifies the vendor signatures,
revocation, validity and TCB status for the quote using these inputs.
