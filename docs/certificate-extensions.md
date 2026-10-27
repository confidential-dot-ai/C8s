# Certificate extensions

The X.509 extensions C8s puts on armTLS certificates: the OID each one uses,
what it carries, which certificate has it, and who checks it. armTLS is the
mutual TLS C8s components authenticate each other with, and its certificates
carry attestation evidence from the hardware Trusted Execution Environment
(TEE) the peer runs in. All four extensions are non-critical, so a TLS stack
that does not know them still parses the certificate — nothing is enforced by
certificate parsing. Other terms are defined in [glossary.md](glossary.md);
what the checks prove, and when, is [armtls.md](armtls.md).

C8s assigns them under its own Private Enterprise Number:

```text
1.3.6.1.4.1.66378.1    confidential TEE attestation arc
1.3.6.1.4.1.66378.1.1  armTLS attestation
1.3.6.1.4.1.66378.1.2  attestation-evidence audit digest
1.3.6.1.4.1.66378.1.4  pod sandbox ID
1.3.6.1.4.1.66378.1.5  matched workload
```

## Three kinds of certificate

- **Self-issued armTLS certificate**: a component signs it with the key its own
  evidence binds. Issuer equals subject, so a verifier authenticates the body by
  checking that self-signature, then the evidence inside it.
- **CDS-issued leaf**: the certificate CDS — the Certificate Distribution
  Service, the one cluster pod that verifies evidence and signs workload
  certificates — signs with the mesh CA. It names one pod run when the request
  proved a sandbox. Its signature under the mesh CA is what vouches for
  everything CDS stamped. A member pod's mesh endpoint presents the leaf
  get-cert published for that pod; it issues no certificate of its own.
- **Mesh CA**: `CN=c8s Mesh CA`, P-384, generated in CDS memory, valid for a
  year by default, `keyUsage` certificate and CRL signing. It carries none of
  these extensions.

## What each certificate carries

| OID | On | Carries | Checked by |
|---|---|---|---|
| `…1.1` | Self-issued certificates, and leaves whose CSR carried one | The peer's TEE evidence, bound to this certificate's public key | Every verifier that authenticates a peer by this evidence, through its own attestation-api — the node-local service that checks hardware evidence — and `c8s verify`. A verifier that admitted the peer on a mesh CA chain ignores it |
| `…1.2` | Every leaf CDS signs | SHA-256 of the evidence bytes that authorized the issuance | Nothing reads it; it records which issuance signed this leaf |
| `…1.4` | A leaf whose request proved a sandbox | The pod sandbox ID the container runtime gave the pod this leaf was issued to | CDS, when it serves secrets and volume keys to that pod; the pod's own injected sidecars, get-cert and the mesh endpoint (`c8s-mesh`), reading their own leaf; `c8s verify --sandbox-id` |
| `…1.5` | A leaf whose attested container set matched exactly one allowlist entry | The matched entry name, and the allowlist snapshot the match was decided under | The router, before it writes a request to a workload backend; `c8s verify --workload` and `--allowlist` |

A leaf is signed by the mesh CA, so `…1.2`, `…1.4` and `…1.5` are statements by
CDS: they are worth nothing on a certificate whose chain the reader has not
verified against the mesh CA. `…1.1` is the one extension the hardware vouches
for, and it covers the public key alone.

## armTLS attestation (`…1.1`)

```text
TEEAttestation ::= SEQUENCE {
    teeType            INTEGER,            -- 1 = SEV-SNP, 2 = TDX
    report             OCTET STRING,
    certChain          OCTET STRING,
    runtimeExtensions  [0] EXPLICIT SEQUENCE OF PrintableString OPTIONAL
}
```

- **`teeType`**: the TEE family of the evidence itself, not of the component's
  configured platform. An unknown value is refused rather than read as a
  family.
- **`report`**: raw SEV-SNP report bytes on a native SEV-SNP node; a JSON
  evidence envelope otherwise. Native TDX evidence travels without its
  `cc_eventlog`, which would push the certificate past the 16 KB TLS handshake
  record limit; the quote still carries the registers a policy pins.
- **`certChain`**: the field for DER platform collateral, left empty on every
  C8s certificate. The evidence envelope carries its own collateral instead:
  on native SEV-SNP an inline VCEK — the AMD-signed per-chip certificate that
  signs this node's reports — travels inside the envelope. Verification goes
  through an attestation-api on every platform, which fetches the VCEK from
  AMD's key distribution service (`kdsintf.amd.com`) when the evidence carries
  none. This field is not the certificate chain a peer presents in the
  handshake: that chain is the TLS one, a self-issued certificate alone or a
  CDS-issued leaf under the mesh CA.
- **`runtimeExtensions`**: TDX only, at most 256 entries, each a canonical
  `sha256:<hex>`: the allowlist policies the node extended into RTMR[3], in
  extend order, for a verifier to replay
  ([measurements.md](measurements.md#policy-history)). The list is unattested
  on its own. A verifier refuses it on SEV-SNP evidence, which has no register
  to replay.

The evidence commits to `SHA-384(PKIX-DER(pubkey) ‖ challenge)`. A challenge
appears only in the evidence an issuance request carries, and no certificate
embeds that evidence: what CDS copies onto a leaf is the challenge-free
extension the CSR carried, so possession of the key in the handshake and the
validity window are the freshness bound on a certificate.

## Attestation-evidence audit digest (`…1.2`)

A DER `OCTET STRING` holding SHA-256 of the exact evidence bytes CDS verified
before signing. It ties a leaf to one issuance in the CDS log.

## Pod sandbox ID (`…1.4`)

A DER `UTF8String`, 1 to 128 characters of `[A-Za-z0-9._-]`, in the one
canonical encoding: a value that re-encodes to different bytes is refused, so
two extensions cannot parse to the same ID. CDS stamps it after verifying the
sandbox token signed by the node's admission inventory, the node service that
records which containers ran in which pod sandbox
([armtls.md](armtls.md#sandbox-identity)). A
certificate carrying two of them, or one that does not parse, is an error and
never read as absence.

For a CSR with no DNS or IP SAN and no common name, the issued common name is
the lowercase hex SHA-256 of this ID. Names authorize nothing in the mesh.

## Matched workload (`…1.5`)

```text
MatchedWorkload ::= SEQUENCE {
    formatVersion    INTEGER,            -- exactly 1
    name             IA5String,          -- the allowlist entry name
    allowlistVersion IA5String,          -- the store's version counter
    allowlistDigest  OCTET STRING (32)   -- SHA-256 of the canonical allowlist
}
```

Canonical DER, like the sandbox ID: trailing bytes, a non-minimal encoding or
an unknown `formatVersion` all fail closed. `allowlistVersion` and
`allowlistDigest` say which policy document the match was decided under, so a
relying party holding the same canonical bytes can detect skew between the
policy it pinned and the one CDS enforced
([armtls.md](armtls.md#matched-workload)).

The mesh CA's signature is what vouches for this stamp, never the hardware
evidence, so it is readable only off a leaf the reader has verified against
that CA. A self-issued peer's version of this extension is whatever that peer
chose.

## Subject, key usage and lifetime

| | Self-issued certificate | CDS-issued leaf |
|---|---|---|
| Subject | `CN=armTLS Workload, O=Confidential` unless the component sets its own | The CSR's common name, or the sandbox-ID digest for a `get-cert --no-san` request |
| Key | ECDSA P-256, generated in process memory | The CSR's key, generated in pod memory |
| `keyUsage` | Digital signature | Digital signature |
| `extKeyUsage` | Server and client authentication | Server and client authentication |
| Lifetime | 24 hours by default | At most 24 hours, and at most 6 with a matched-workload stamp |

A verifier grants `notBefore` a 5-minute clock-skew allowance and `notAfter`
none.
