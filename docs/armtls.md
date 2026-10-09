# armTLS: how C8s components authenticate each other

armTLS (attestation-rooted TLS) is C8s's TLS 1.3 authentication model. On the
evidence path, peers verify the hardware attestation embedded in a self-issued
certificate and its binding to the TLS key. On the chain path, the Certificate
Distribution Service verifies the caller's attestation before its CA issues a
leaf, and peers verify the leaf's chain against the mesh CA. Both root the
peer's identity in attested code and hardware.

Mesh traffic between pods, certificate issuance and allowlist reads use these
authenticated channels.

This doc walks the process step by step: what is in an armTLS certificate, how a
handshake verifies it, how CDS issues a leaf from verified evidence, what the
whole construction does and does not guarantee, how it operates on confidential
nodes, and which certificate is used where.

Companion docs: [`cmd/armtls-mesh/README.md`](../cmd/armtls-mesh/README.md) (the
pod mesh endpoint), [install-flows.md](install-flows.md) (which components
deploy in which mode).
The implementation is [`pkg/armtls`](../pkg/armtls/), with the CDS client flow in
[`pkg/attestclient`](../pkg/attestclient/) and
[`pkg/armtls/cdsclient`](../pkg/armtls/cdsclient/).

## The idea: bind a TLS key to the hardware root of trust

A TEE (AMD SEV-SNP or Intel TDX guest) can ask its hardware for an
**attestation report**: a structure, signed by a key fused into the CPU, that
contains the guest's **launch measurement** (a digest of exactly what booted)
and 64 bytes of caller-chosen **REPORTDATA**. C8s puts a hash of a
freshly-generated TLS public key into REPORTDATA. The signed report then says,
with the silicon vendor's authority: *this measured guest supplied this
public-key binding*. The measured code generates and confines the private key.

```text
AMD ARK ──signs──▶ ASK ──signs──▶ VCEK  (per-chip key, TCB-versioned)
(root, in verifier)                  │
                                     │ signs
                                     ▼
                          ATTESTATION_REPORT
                          ├─ MEASUREMENT: launch digest of the guest
                          ├─ REPORTDATA:  SHA-384(TLS pubkey ‖ nonce)
                          └─ policy bits: debug, TCB level, ...
                                     │
                                     │ binds (hash match)
                                     ▼
                          ECDSA P-256 TLS key pair
                          (generated in TEE memory, never on disk)
                                     │
                                     │ authenticates (TLS 1.3 handshake)
                                     ▼
                          the TLS session
```

For TDX the chain is the Intel equivalent (provisioning certification chain →
Quoting Enclave signs the quote) and the pinned measurement is MRTD. Everything
downstream is platform-agnostic.

Evidence-path certificates are self-issued. `NewClientTLSConfig` sets
`InsecureSkipVerify: true` and verifies the embedded evidence and key binding
in a `VerifyPeerCertificate` callback (`pkg/armtls/tls.go`). When a mesh CA is
configured, the callback also accepts certificates chaining to that CA:
CDS checked the requester's attestation before issuance. The TLS handshake
proves possession of the corresponding private key in either path.

## Anatomy of an armTLS certificate

`pkg/armtls` builds those self-issued certificates like this (`cert.go`,
`provider.go`), over the extension format in
[attestation-go/armtls](https://github.com/confidential-dot-ai/attestation-go/tree/main/armtls):

1. **Key generation.** An ECDSA P-256 key pair is generated in process memory.
   It is never written to disk and never leaves the TEE.
2. **Key→report binding.** `REPORTDATA = SHA-384(PKIX-DER(pubkey) ‖ nonce)`,
   zero-padded to the 64-byte REPORTDATA field (same layout on SEV-SNP and
   TDX). The nonce is optional on mesh handshakes (TLS 1.3 already prevents
   replay of the *session*) and mandatory in the CDS issuance flow (it proves
   report freshness). Certificates always use this plain binding
   (`ReportDataForKey`).
3. **Evidence.** The component asks its **local attestation-api** (`POST
   /attest`, the Rust service from
   [attestation-rs](https://github.com/confidential-dot-ai/attestation-rs))
   for evidence over that REPORTDATA. The hardware signs the report inside the
   TEE.
4. **Certificate.** A self-signed X.509 certificate is created with the
   evidence embedded as a custom extension:

   ```text
   OID 1.3.6.1.4.1.66378.1.1  (armTLS attestation extension)
   TEEAttestation ::= SEQUENCE {
       teeType     INTEGER,      -- 1 = SEV-SNP, 2 = TDX
       report      OCTET STRING, -- evidence, two shapes (below)
       certChain   OCTET STRING  -- optional inline VCEK chain
   }
   ```

The full `1.3.6.1.4.1.66378.1` arc a C8s certificate may carry:

| OID | Extension | Stamped by |
|---|---|---|
| `…1.1` | armTLS attestation (`TEEAttestation`) — format owned by attestation-go/armtls, OID assigned here in `pkg/armtls` | the attesting component, on its own certificate and on its CSR |
| `…1.2` | SHA-256 audit digest of the issuance evidence — `pkg/certutil` | CDS, on every issued leaf |
| `…1.4` | pod sandbox ID — `sandbox.go`, see [Sandbox identity](#sandbox-identity-which-workload-is-behind-a-key) | CDS, on a leaf whose requester presented a sandbox token |
| `…1.5` | matched workload — `matchedworkload.go`, see [Matched workload](#matched-workload-which-allowlist-entry-is-behind-a-key) | CDS, on a leaf whose sandbox's high-water inventory uniquely matches one allowlist entry |

`…1.3` was the config-claims extension; it is retired and not reusable.

The `report` field carries one of two shapes, auto-detected on parse by
attestation-go/armtls, which owns the wire format:

- **Native SEV-SNP** (`snp`, `gcp-snp`): the raw 1184-byte `ATTESTATION_REPORT`,
  kept raw so an offline SNP verifier can extract it.
- **Everything else** (`az-snp`, `tdx`, `gcp-tdx`, `az-tdx`): the attestation-api's
  JSON evidence envelope, forwarded verbatim to `/verify` at handshake time. Both
  TDX shapes must use the envelope (C8s deliberately ships no in-process quote
  parser — see `verify.go`): the native ones carry a bulky `cc_eventlog` that is
  stripped before embedding, while Azure-vTPM `az-tdx` (the TD quote wrapped in the
  HCL report, alongside the vTPM quote) has no eventlog and is embedded as-is.
  Azure evidence wrapped in a Hyper-V HCL header is normalized back to the raw
  report where needed.

Certificates live 24h by default. A mesh client runs a timer for each server and
client certificate, checking once per minute for renewal at 50% of TTL even
while idle. Checks honor exponential jittered retry backoff (5s initial
interval, 1 minute maximum base interval), including while expired and
NotReady. Provider upgrades are observed on the next check. Each attempt is
bounded by the rotation timeout.
While valid, the cached certificate remains available during renewal. After
`NotAfter`, handshakes request a fresh certificate or fail; they never receive
an expired credential. Synchronous attempts are single-flighted and failures
are briefly negative-cached. `/ready` requires both cached certificates to be
usable; renewal continues independently of readiness. Renewal logs carry
`cert_role`, and `armtls_mesh_cert_rotation_failures_total` has a `role` label.

## The handshake, step by step

During bootstrap, both sides of a mesh connection verify embedded evidence;
the diagram shows one direction. "attestation-api" is always the verifier's
**own, same-TCB** instance — never one across the network (see Guarantees).
For CDS-issued leaves, the CA-chain path described below can satisfy peer
verification without repeating these hardware-evidence checks.

```text
   A (dialer)                                B (listener)
   ──────────                                ────────────
1. TCP connect ────────────────────────────▶
2.             ◀───────────────────────────  TLS 1.3 ServerHello + leaf cert
                                             [ext 1.3.6.1.4.1.66378.1.1:
                                              report with REPORTDATA =
                                              SHA-384(B's pubkey)]
3. parse cert, extract extension
4. POST /verify to A's LOCAL attestation-api:
     { evidence, expected REPORTDATA,
       allow_debug, min_tcb }
   ◀── verdict: hardware chain valid,
       REPORTDATA matches, policy holds,
       launch digest = M
5. require M ∈ measurement allowlist
6. client cert ────────────────────────────▶ mTLS: B runs steps 3–5 on
                                             A's certificate
7. ◀═════════ application bytes, TLS 1.3 ═════════▶
```

Step by step:

1. **Server certificate provisioning is lazy and cached.** The first handshake
   triggers key generation + attestation (steps 1–4 of "Anatomy"); later
   handshakes reuse the cached certificate until rotation.
2. **Custom peer verification.** `NewClientTLSConfig` sets
   `InsecureSkipVerify: true`; `VerifyPeerCertificate` checks the peer.
3. **Extension extraction.** Missing extension → `ErrNoAttestation`, connection
   refused.
4. **Delegated verification.** The verifier computes the REPORTDATA it
   *expects* from the peer certificate's public key, then forwards evidence +
   expectation + policy to its local attestation-api `POST /verify`. The
   attestation-api checks the hardware signature chain (ARK→ASK→VCEK for SNP,
   Intel collateral for TDX), the REPORTDATA match (key binding), the debug
   policy (`AllowDebug`, default reject), and the minimum TCB (SNP only).
   There is **no in-process verification fallback**: no reachable
   attestation-api means no connection (fail closed).
5. **Measurement policy.** The verified launch digest returned by the
   attestation-api is compared against the caller's allowlist
   (`VerifyPolicy.Policy.Measurements`; SNP LAUNCH_DIGEST or TDX MRTD, 48 bytes). An
   **empty allowlist accepts any genuine TEE** — deliberate bootstrap
   ergonomics, loudly warned, and unsafe in production.
6. **mTLS.** Servers configured with a `ClientPolicy` require a client
   certificate and verify it the same way (steps 3–5, roles swapped).

Verification failures map to typed sentinels (`errors.go`):
`ErrSignatureInvalid` (hardware chain), `ErrKeyBinding` (REPORTDATA mismatch —
the key was not generated in that TEE), `ErrPolicyViolation` (measurement not
allowlisted), `ErrNoAttestation`, `ErrInvalidReport`, `ErrUnsupportedTEE` — the
last three re-exported from attestation-go/armtls.

## The chain path: CDS issuance

Self-issued armTLS verifies embedded hardware evidence at each handshake,
using the local attestation-api. In CDS mode, certificate issuance performs
caller attestation centrally and peers verify the resulting mesh-CA chain.
CDS signs a CSR **only after** verifying fresh evidence bound to its public
key and checking the configured measurement policy. The mesh CA's signature
then vouches for the issued identity.

```text
   requester                        CDS                    local attestation-api
   (get-cert / armtls-mesh)          ───                    ─────────────────────
   ──────────────────────
1. POST /authenticate ────────────▶
   ◀──────────────────────────────  challenge (single-use, 32 B, TTL-bound)
2. generate P-256 key + CSR
   (SAN = workload id / node)
3. REPORTDATA =
   SHA-384(CSR pubkey ‖ challenge)
   POST /attest (REPORTDATA) ─────────────────────────────▶
   ◀───────────────────────────────────── TEE evidence bound to key+challenge
4. POST /attest
   { challenge, evidence, CSR } ──▶
                                    verify evidence (CDS's own
                                    same-TCB attestation-api),
                                    enforce cds.measurements,
                                    validate SAN / CN policy,
                                    sign CSR with the mesh CA
   ◀──────────────────────────────  leaf certificate chain + CA bundle
```

Properties worth noting:

- **The transport for steps 1 and 4 is itself armTLS.** CDS self-provisions an
  armTLS serving certificate bound to its own launch measurement. An injected
  client reads the pins from the node policy the enforcer bind-mounts at
  `/run/c8s/cds-pins.json`, and the endpoint it dials from
  `/run/c8s/cds-address`, refusing pins or a `--cds-url` passed to it; every
  other client pins with `--cds-measurements` and dials `--cds-url`. The
  challenge–response plus the armTLS channel
  close the bootstrap window against a pod-network impostor — *iff*
  measurements are pinned.
- **The mesh CA private key exists only in CDS process memory** (P-384, CN
  `c8s Mesh CA`, 1-year validity, generated at startup). It is never a
  Kubernetes Secret, never on disk. A (singleton) CDS restart mints a fresh
  CA and workloads re-bootstrap.
- **Issued leaves are capped at 24h** and always carry a SHA-256 digest of
  the issuance evidence as an audit extension. When the CSR itself embeds an
  armTLS extension — the mesh client and get-cert both do, bound to the bare
  key with no nonce — CDS copies it onto the leaf, so the leaf carries the
  evidence its issuance verified (`internal/issuer/sign.go`).
- **The challenge is the freshness proof.** Single-use and TTL-bound
  server-side; REPORTDATA commits to it, so recorded evidence cannot be
  replayed into an issuance.
- **CA bundle distribution is continuity-checked.** `GET /ca` is deliberately
  unauthenticated; consumers seed trust from the *authenticated* issuance
  response and afterwards accept only bundle updates signed by an
  already-trusted CA (`pkg/armtls/cdsclient`). A MITM'd `/ca` read cannot
  inject a new root.
- **The serving certificate commits only CDS's key and measurement** — not its
  operator-key set, not its allowlist seed. A verifier cross-checks the key set
  CDS *serves* at `/operator-keys`, fetched over that attested serving cert
  (`c8s cds verify --operator-keys`).

### The two certificate regimes

The evidence path and the chain path are separate, and a peer is verified on
one of them:

1. **Evidence path** (`verifyPeerCallback`, `tls.go`): the peer's certificate
   must be self-issued and carry key-bound evidence, verified per connection as
   above. A chain-signed leaf is refused here, whatever mesh CA the process
   holds, so a CA signature can never stand in for a measurement.
2. **Chain path** (the mesh endpoint profile below): the peer's CDS-issued leaf
   must chain to the mesh CA the endpoint holds.

A peer verified on the chain path proved its measurement **at issuance time**,
not at handshake time: it is "chains to the mesh CA", not "runs launch digest
X". That is the reason the chain path is the per-pod endpoint's alone, where
the pod ruleset and the node enforcer bound what the leaf can reach.

### The mesh endpoint profile

A mesh endpoint presents its pod's CDS-issued leaf and authenticates peers on
the **chain path alone** (`NewMeshServerTLSConfig`, `NewMeshClientTLSConfig`,
`tls.go`). A peer is accepted when, and only when:

1. its leaf chains to the mesh CA the endpoint holds, at the current time and
   with no not-before allowance,
2. the leaf permits the purpose the peer's role needs — `serverAuth` for a
   server, `clientAuth` for a client,
3. its key is ECDSA P-256 or P-384, and
4. the leaf carries exactly one well-formed sandbox-ID extension.

A failed chain is never retried against the leaf's embedded evidence, so a
self-signed peer and a peer from another mesh CA both fail.

This profile authenticates member-to-member traffic only: a credential client
reaches CDS on the evidence path, and the router is itself a member.

Both roles require the ALPN protocol `c8s-mesh/1` and refuse a connection that
negotiates anything else, so no application byte moves on a peer that does not
speak the mesh protocol.

### No session resumption

Every armTLS configuration sets `SessionTicketsDisabled` and holds no client
session cache. `crypto/tls` re-runs no peer verification on a resumed
handshake and gives a client no revalidation hook, so a resumed connection
would outlive the checks that admitted it — the current CA trust and sandbox
ID on the chain path, the current pins on the evidence path.

## What armTLS guarantees — and what it does not

Direct evidence verification against a pinned policy establishes the claims
below, assuming C8s's trust assumptions hold. The CA-chain path relies on
CDS's checks at issuance time, as described above.

1. **Genuine TEE.** The peer's evidence was signed by real AMD/Intel silicon —
   a hypervisor, control plane, or network attacker cannot forge it.
2. **Key binding.** REPORTDATA binds the TLS public key to the evidence, and
   the handshake proves possession of its private key. Generation and
   confinement of that private key depend on the trusted measured code.
3. **Code identity.** The guest booted exactly an allowlisted image: its
   launch digest (SNP LAUNCH_DIGEST / TDX MRTD) is in the verifier's pinned
   set. *This guarantee only exists when measurements are pinned.*
4. **Runtime policy floor.** Debug-mode guests are rejected by default;
   on SNP a minimum TCB (microcode/SNP firmware level) can be enforced.
5. **Channel security.** TLS 1.3 with ephemeral key exchange protects
   confidentiality and integrity; certificates rotate halfway through their
   TTL (24h default).
6. **Issuance freshness** (CDS flow): the challenge nonce in REPORTDATA
   prevents replaying recorded evidence into new certificates.

What it does **not** guarantee:

- **Nothing, with an empty measurement allowlist.** Any genuine TEE — including
  an attacker's own CVM on the pod network — is accepted. Both CDS and
  the mesh clients ship with empty pins, warn loudly, and export
  `armtls_mesh_measurement_pinning=0` for alerting. Pinning is the operator's
  explicit production step.
- **A trustworthy verdict from an untrusted verifier.** The attestation-api's
  `/verify` response is **unsigned**; whoever can impersonate the configured
  `AttestationApiURL` forges "valid". Every deployment therefore keeps the
  verifier in the same TCB as the verifying component: the node-local Unix
  socket the DaemonSet's attest-proxy serves (node-as-CVM — the client checks
  the socket's owner and mode on every dial). Do not point it across a trust boundary.
- **Per-handshake measurement of CA-verified peers.** See "Dual verification"
  above: after the CDS upgrade, mesh peers are verified by CA chain only.
- **Full TDX runtime measurement, unless RTMRs are pinned.** On TDX the
  launch digest covers the TDVF firmware alone; the guest kernel measures
  into RTMR[1] and the command line — carrying the dm-verity root hash — into
  RTMR[2]. In-cluster those registers are pinned by `cds.rtmrs` /
  `armtlsMesh.rtmrs` (`c8s install --rtmrs 1=<hex>,2=<hex>`): CDS requires
  them of TDX callers on `/attest`, and every component
  dialing CDS (and every mesh peer policy) enforces them on the handshake.
  Left empty — the default, warned on a TDX install — the in-cluster pins
  confer **no guest-code identity**: any TD booting the pinned firmware is
  accepted. The RTMR pin is one register set for the whole fleet, not a
  per-image tuple (GAP). A `Policy.MinTcb` floor names SEV-SNP components, so
  TDX evidence is refused outright rather than verified under no floor. Operator-side, `c8s verify --image-manifest` pins the full
  MRTD+RTMR[1]+RTMR[2] image tuple exactly — which is why it replaces
  `--measurements` rather than combining with it — and `--rtmr 3=`
  (or `--operator-pkey`, which derives the same value from the operator public
  key) pins the runtime register, requiring the image pin because the host
  chooses the image and the runtime chain alone identifies nothing;
  `c8s get-kubeconfig` requires the
  full tuple plus the operator-key/workload RTMR[3] chain. `c8s verify` does
  not silently drop `--min-tcb-*` on TDX the way the mesh policy does: an
  SNP-shaped floor against TDX evidence is a policy failure naming the
  platform, and on SNP the floor is re-checked against the verified claims.
- **Workload-granular identity beyond the TEE boundary.** The unit of
  hardware attestation is the TEE: the whole node in node-as-CVM. The sandbox ID narrows this — a leaf names the pod sandbox CDS
  issued it to, and CDS issues only after the sandbox's own inventory reports
  images that are all allowlisted (see Sandbox identity) — but that ID is
  vouched by the mesh CA signature, not by hardware evidence, and it is only as
  good as the inventory's honesty about what it admitted. The gate is
  membership, not composition, so it does not say the pod runs one particular
  workload. Enforcing per-workload measurement at `/attest` is unimplemented.
- **Post-boot integrity.** The launch digest covers boot state; runtime
  compromise inside a measured node is out of scope for launch attestation.
- **Availability.** A hostile host can always refuse service; armTLS turns
  host compromise into DoS, not data exposure.

## Sandbox identity: which workload is behind a key

The attestation so far binds the *key* and the *launch measurement* — the image
that booted. It says nothing about **which workload** stands behind a mesh key
when the TEE holds more than one. A CDS-issued leaf names the **CRI pod
sandbox** it was issued to:

```text
OID 1.3.6.1.4.1.66378.1.4  (pod sandbox ID extension)
SandboxID ::= UTF8String    -- e.g. containerd's 64-hex sandbox ID
```

A leaf carries exactly one `…1.4`: one DER UTF8String whose value matches
`[A-Za-z0-9._-]{1,128}`.

The **inventory** is the component that admitted the pod's containers —
nri-image-policy on node-CVM — so it is
the arbiter of both which sandbox a process belongs to and what runs in that
sandbox. It serves two disjoint surfaces (`pkg/workloadclaims`):

| Surface | Route | Listener | Caller bound by |
|---|---|---|---|
| tokens | `POST /sandbox` | a node-local Unix socket | kernel peer credentials (`SO_PEERCRED` + `SO_PEERPIDFD`) |
| identity + digests | `GET /identity`, `GET /digests/{sandboxID}` | `:1019` (`workloadclaims.DigestsPort`), mutually-attested armTLS | the client leaf's launch measurement (CDS's) |

The token surface cannot enumerate other sandboxes; the network surface cannot
mint identity.

### The privileged port is the inventory's identity

`DigestsPort` is a compiled constant, not a deployment value, and it is
privileged (`< 1024`, IANA-unassigned). Binding it requires the node's own
network namespace, which the chart's `deny-host-namespaces`
ValidatingAdmissionPolicy withholds from tenant pods
(`hostNamespacePolicy.enabled`, on by default). A pod can bind any port inside
its own netns, so an unprivileged port would let any workload answer as the
inventory.

That is what CDS's trust in the sandbox-token signing key rests on, because
measurement cannot make the distinction: on node-CVM every pod shares the node's
launch digest, so "attested TEE on an allowed measurement" is satisfied by every
tenant. "Answers on `:1019` in the node's network namespace, at an address inside
the node bound" is not.

Two things this rests on that attestation does not enforce:

- the default `deny-host-namespaces` ValidatingAdmissionPolicy (or an equivalent
  control) holds. It enforces Restricted controls and denies host namespaces,
  host ports, privilege, and every tenant `hostPath` volume, including on
  ephemeral-container updates to existing Pods. Encrypted volumes
  (docs/volumes.md) use `emptyDir`s that volumed fills; node-CVM credential
  sidecars receive the read-only inventory socket directory through NRI below the Pod
  spec. The policies exempt the release namespace, `kube-system`,
  `local-path-storage`, and explicitly configured
  `hostNamespacePolicy.exemptNamespaces`. In `local-path-storage` RBAC grants
  pod verbs to the local-path provisioner's service account alone, whose
  hostPath helper pods are the reason for the exemption — any RoleBinding
  widening pod creation there widens the exemption with it.
- privileged node DaemonSets — CNI, CSI, the NVIDIA GPU operator — *can* bind
  the port. They are already root inside the node CVM and can read another
  pod's memory directly, so they are effectively part of the node's TCB;
  sandbox identity does not narrow that set.

### The sandbox token

get-cert fetches the CDS challenge for this issuance first, then POSTs its CSR
public key and that challenge to `/sandbox`. The inventory resolves the
*caller's* identity to a sandbox — nothing the caller sends names the pod. On a
node with a mesh policy it answers `403` unless the enforcer verifies that
sandbox as a member pod whose live ruleset is the one trusted policy defines
and the caller is still the live process. Then it signs

```text
SandboxToken ::= SEQUENCE {
    version        INTEGER,            -- 2
    sandboxId      IA5String,
    keyDigest      OCTET STRING (32),  -- SHA-256(requester PKIX pubkey DER)
    nonce          OCTET STRING,       -- the CDS challenge for this issuance
    inventoryHost  IA5String           -- IP of the node/guest serving :1019
}
```

with an in-process P-256 key. The signature is ECDSA over
`SHA-256("c8s/sandbox-token/v1\0" ‖ tokenDER)`, and the envelope
(`workloadclaims.SignedSandboxToken`) is just `token` and `signature`: it
carries **no** credential for the signing key. CDS resolves the key by dialing
`GET /identity` at the signer's own privileged port.

`inventoryHost` is an IP only — the port is not carried, since CDS holds it. The
key is never persisted; an inventory restart mints a new one, which CDS picks up
because it re-reads `/identity` on every issuance rather than caching a
credential.

### Issuance

get-cert forwards the envelope opaquely in the `/attest` request body
(`sandbox_token`). **It never reports its pod's images.** CDS then, in order
(`internal/cmds/cds/attest.go`):

1. reads `inventoryHost` out of the *unverified* token
   (`workloadclaims.UnverifiedInventoryHost`). The host names the endpoint
   holding the key that would verify the signature, so it has to be read before
   verification can happen; it is trusted for nothing else. It only selects a
   dial target, and a wrong value simply yields a key the signature fails under.
2. requires that host to be a routable unicast IP literal (no names — DNS would
   decide the destination after the check — and no loopback, link-local/IMDS,
   multicast, or unspecified address) inside the node bound: the operator's
   `--sandbox-inventory-cidr` CIDRs, or one host route per node derived live
   from the cluster's node list when that is unset. With no known node
   addresses CDS refuses every request carrying a sandbox token. A pod's IP is
   in the pod CIDR, so a workload cannot name itself as its node's inventory.
3. fetches the signing key from `https://<host>:1019/identity` over
   mutually-attested armTLS (`workloadclaims.DigestsClient.InventoryKey`,
   pinning the same measurement allowlist `/attest` uses and presenting CDS's
   own armTLS certificate).
4. verifies the token signature under that key, requires `version == 2`,
   requires `nonce` to be the same single-use challenge it is consuming for this
   request, requires `keyDigest` to name the CSR key — whose possession the CSR
   signature and evidence binding already prove — and requires the sandbox ID to
   be syntactically valid.
5. verifies the requester's evidence, measurement, and CSR policy as usual.
6. asks `GET /digests/{sandboxID}` at the same endpoint and gates issuance on
   the answer: every image the sandbox is running must be allowlisted.
7. stamps the sandbox ID into the leaf's signed area
   (`internal/issuer/sign.go`).

So the ID is redeemable only by the get-cert holding the bound key, usable only
for the one issuance whose challenge it carries — no clock, no replay window —
and signed by a key that answered on a privileged port inside the operator's
node range. An unreachable inventory, an unknown sandbox, or a non-allowlisted
image refuses the certificate, and so does an **empty** digest set — a sandbox
always runs at least the sidecar that is asking, so an empty answer is no
evidence at all rather than "nothing to check". A request carrying no token gets
a leaf with no sandbox ID.

Because the digests are fetched live from the admitting component rather than
reported by the requester, the binding holds at **first** issuance: get-cert's
own sidecar container is already tracked when it asks for the token, and step 6
reads whatever the sandbox is running at that instant.

The gate is **membership only** — it does not require the running set to match a
whole workload entry. Issuance lands at arbitrary points in the pod lifecycle
(a user init container running, main containers coming up one at a time, one
restarting, completed init containers reaped), and in each the running set is a
strict subset of what the pod declares. Requiring the whole set would deny
ordinary lifecycle states, permanently so once init containers are reaped.
Membership is subset-safe, so it holds in all of them.

The consequence: a leaf's sandbox ID says *this key belongs to pod X*, not *pod
X runs exactly workload Y*. Whole-set enforcement belongs where the pod is
complete and the stake is high — secrets release — and is not implemented yet.
Per-container digest and argv policy is still enforced continuously at
admission by nri-image-policy
([allowlist-and-capabilities.md](allowlist-and-capabilities.md)).

### What vouches for the ID

The sandbox ID rides the leaf's **signed area**; it is **not** folded into
REPORTDATA. The mesh CA signature, not the hardware evidence, is what
authenticates it. The verifier encodes that:

- No TLS path enforces the pin: `CheckSandboxPin`'s only caller is
  `c8s verify`, which has verified the chain itself. The mesh endpoint's chain
  path requires the extension to be present and well-formed, and does not
  compare it to an expected ID.

A self-issued armTLS peer can put any string in the extension, so only a leaf
whose chain the relying party verified carries a meaningful ID.

**Residual trust.** The key's provenance is "answered on `:1019` at an address
inside the node bound, over armTLS on an allowed measurement". That narrows to a
*node*, not to a process: anything able to bind that port on a node — the
inventory, or a privileged node DaemonSet — can sign for any sandbox that
node admitted. Fleet-wide the residual is
a peer node: it shares the launch measurement, and the threat model already
grants the host the ability to serve its own TEE attestation on the pod network,
so a hostile node could in principle answer for a node whose traffic it can
intercept ([getcert-workload-binding.md](getcert-workload-binding.md),
Corners 6–7).

### Reading a peer's sandbox ID

Pinning answers "is this peer *X*?"; a relying party often needs "*which*
workload is this?" — to authorize, route, or log.
`armtls.PeerSandboxID(*tls.ConnectionState)` returns a verified peer's sandbox
ID off a live connection (an HTTP server passes `r.TLS`), or `""` when the leaf
carries none. It reads the extension and does **not** re-verify. Call it only
on a connection your verify callback admitted, and only where that callback had
a CA pool: on the attestation fallback the extension is peer-chosen and means
nothing.

### Verifying from outside

`c8s verify --sandbox-id <id>` pins the ID and **requires** `--mesh-ca`, a PEM
bundle the target's leaf must chain to — that chain is what authenticates the
reported ID. Whenever the evidence verifies and the leaf carries an ID, the
verdict reports `sandbox_id` alongside a `sandbox_id_note` naming what stands
behind it ("not verified: … pass `--mesh-ca`" or "verified: the leaf chains to
the supplied mesh CA"), so an unqualified ID never reads as attested.

### Deployment

The node inventory is wired through NRI.

- **node-CVM.** nri-image-policy — a host process containerd launches, not a pod
  — serves the token socket in `nriImagePolicy.hostPaths.runtimeDir`, which it
  bind-mounts read-only into the `c8s-cert` sidecar at container creation (an
  NRI mount, so the pod spec carries no hostPath and stays admissible under
  PodSecurity `restricted`), and `/identity` + `/digests` on `:1019`. The node IP it signs into tokens comes from the
  installer DaemonSet's downward API `status.hostIP`, written to a `node-ip`
  file beside the socket; `nriImagePolicy.sandboxDigests.advertiseHost`
  overrides it. Route inference is the last resort and is wrong under the
  chart's own default, since the plugin dials the CDS NodePort over loopback.
CDS must be able to reach every node on `:1019`, and the
bound must cover those addresses: `cds.sandboxInventoryCIDRs` (`c8s install
--node-cidr`) when set, else one host route per node derived live from the node
list — a node added later is covered without a CDS restart.

An empty measurement allowlist does not disable any of this — it tracks the same
posture `/attest` takes (see "What armTLS guarantees"): both ends still require
a hardware-attested armTLS peer, they just pin no measurement, so any TEE can
answer as the inventory and any TEE can read what a node runs. Both ends log it
as UNSAFE outside development. The token verification and the issuance-time
allowlist gate are unaffected. A `--measurements` entry that is not hex fails
CDS startup rather than silently unpinning the callback.

What does disable the callback is a CDS with no `--armtls-platform`: it has no
armTLS identity to present, so it makes no callback and **refuses** any request
carrying a sandbox token. CDS measurements that fail to *parse* (a typo, as
opposed to being unset) fail the node plugin's config validation at startup.

A digests endpoint that fails to start is logged, not fatal, by the NRI
inventory: containerd sets `required_plugins`, so a plugin exit takes
container creation down node-wide, whereas a missing digests endpoint only
degrades issuance — CDS refuses the tokens it cannot check.

### Cross-implementation note

A non-Go verifier (e.g. `c8s-verify-js`) reading a sandbox ID needs only the DER
UTF8String at OID `1.3.6.1.4.1.66378.1.4` plus a mesh-CA chain check.
The token and digests formats above are internal to the inventory↔CDS path and
are never presented to a relying party.

## Matched workload: which allowlist entry is behind a key

The sandbox ID names a pod; it does not say *which workload* that pod is. A
CDS-issued leaf additionally names the single allowlist entry the pod's
attested container inventory uniquely matched at issuance:

```text
OID 1.3.6.1.4.1.66378.1.5  (matched-workload extension, non-critical)
MatchedWorkload ::= SEQUENCE {
    formatVersion    INTEGER,           -- exactly 1
    name             IA5String,         -- 1..63 bytes; allowlist workload-name grammar
    allowlistVersion IA5String,         -- 1..20 ASCII decimal digits, no leading zero
    allowlistDigest  OCTET STRING (32)  -- SHA-256(Allowlist.Canonical()) of that document
}
```

Parsers are strict (`pkg/armtls/matchedworkload.go`): minimal DER only, no
trailing bytes or fields, exactly one extension with this OID, format version
1, and the same name grammar and 63-byte bound `pkg/allowlist` enforces on
entry names — so the `confidential.ai/cw` selector, an allowlist entry, and
this stamp admit exactly the same values. Anything else fails closed; a
verifier must never read damage as absence.

### How CDS decides

In `/attest`, after the sandbox token, evidence, measurement, and CSR policy
verify, CDS makes one unified inventory decision
(`resolveSandboxWorkload`, `internal/cmds/cds/attest.go`):

1. fetch the sandbox's inventory answer **exactly once** (both the
   deduplicated digests view and the per-container `(digest, argv)` view);
2. load **one immutable policy snapshot** from a single `Store.LoadAll()` —
   the parsed allowlist, its version, its canonical bytes, and their SHA-256.
   The version is never read separately from the document, and an unavailable
   store fails issuance rather than stamping from stale cached state;
3. run the existing membership gate against the digests view and that
   snapshot; failure refuses issuance (unchanged contract — see
   [Sandbox identity](#sandbox-identity-which-workload-is-behind-a-key));
4. require the containers view, canonicalize its digests, and cross-check the
   two views against each other; a disagreement is logged loudly (bounded to
   the sandbox and inventory identities), suppresses the stamp, and preserves
   the membership-only decision from the independent digests view;
5. drop the platform's injected containers using the same
   `secrets.WorkloadContainers` implementation secrets release uses;
6. run `allowlist.MatchWorkload` — argv-aware, "nothing foreign, every main
   present" — once against the snapshot.

A unique match stamps `(name, snapshot version, snapshot digest)`. Everything
else — an old inventory with no containers view, a malformed answer, no match
mid-lifecycle, an ambiguous match — issues the existing **membership-only
(unnamed) leaf**: incomplete pods need a mesh certificate to bootstrap, so the
stamp is purely additive, and a verifier configured with a workload or
allowlist pin fails closed on its absence. The digest pins *which policy* the
match was decided under, so a client holding the same canonical bytes detects
skew between the policy it pinned and the one CDS enforced.

### Identity lifecycle

A sandbox's workload identity is `Unnamed → Named` (first renewal after the
pod completes) or `→ Removed` (teardown). There is no invalidated state and no
component that kills a named pod: the high-water inventory is the only
authority. A foreign admission is intended to make the sandbox unmatchable for
as long as that inventory lives — the record is never pruned — so every later
renewal issues unnamed and the **named-leaf TTL** bounds how long
the last named leaf survives (`--named-cert-ttl`, default
`issuer.MaxNamedLeafTTL` = 6h, chart value `cds.namedCertTTL`). The stale
bound for a named identity is therefore the shorter of the remaining leaf
lifetime and the time until the serving process reloads a replacement unnamed
leaf.

get-cert discovers `Unnamed → Named` through renewal: with a renewal loop it
fast-polls while the published leaf is unnamed, starting at 2s and doubling up to `--unnamed-renew-interval` (default
30s, plus jitter), and settles to
`--renew-interval` once named. A pod that stays unnamed backs off toward
`--renew-interval` after a few polls, since being unnamed can be permanent.
Poll timing never changes the match decision.

The ordinary renewal delay is the earlier of `--renew-interval` and half the
installed leaf's remaining lifetime, randomly shortened on each cycle by up to
`--renew-jitter-percent` to spread refreshes across pods.
Unnamed fast polling retains its existing jitter; the minimum delay still applies.
Certificate expiry is unchanged. A failed renewal retries on a short backoff
rather than after a full interval.
Once the installed leaf has **expired** and renewals still fail, get-cert exits
instead of retrying forever: as a native sidecar it restarts with fresh client
state and re-runs the full issuance.
The named-leaf TTL is the shortest CDS issues and `certutil` does not backdate
`NotBefore`, so a renewal interval alone — the chart's `renewInterval` — is not
a safe schedule: it must stay strictly below `cds.namedCertTTL`, and the
leaf-derived cap is the backstop when it does not.

### What vouches for the name

Exactly the sandbox-ID posture: the stamp rides the leaf's **signed area**, is
vouched by the mesh CA signature, and is *not* part of any hardware
transcript.

- No TLS path enforces the stamp as a pin: a relying party reads it off a leaf
  whose chain it has verified (`MatchedWorkloadFromCert`,
  `PeerMatchedWorkload`).
- `armtls.PeerMatchedWorkload(tls.ConnectionState)` reads a verified peer's
  stamp off a live connection for relying parties that route or authorize by
  name; it refuses a connection whose chain was not verified. It therefore
  requires a `ServerConfig.ClientCA` listener — the only branch where
  crypto/tls builds the chain and fills `VerifiedChains`. A `ClientPolicy`
  listener (which admits a self-issued armTLS peer by design) and every mesh
  client (`InsecureSkipVerify`) leave it empty, so the function errors there.
  That is the contract: on those connections nothing vouches for the stamp.
  A caller that needs the name on such a hop must verify the leaf against the
  mesh CA itself and use `MatchedWorkloadFromCert`, not weaken the check.

A compromised mesh CA can mint any name — the stamp is CA-vouched, not
hardware-bound.

### Verifying from outside

`c8s verify --workload <name>` pins the name; `c8s verify --allowlist <file>`
hashes the file's exact canonical bytes (as served by `GET /allowlist` — no
reserialization), checks the stamped digest, then resolves the stamped name in
the document. Both **require `--mesh-ca`**, exactly like `--sandbox-id`, and
the chain check runs before the stamp is reported. The verdict distinguishes
`workload_absent`, `workload_malformed`, `workload_name_mismatch`,
`allowlist_digest_mismatch`, `workload_unresolved`, and `workload_verified`;
exit codes are unchanged.

### Cross-implementation note

A non-Go verifier needs the strict DER parse above plus a mesh-CA chain check.
The one canonical encoding of `{v1, "api", "7", 0x11×32}` is pinned as a
golden vector in `pkg/armtls/matchedworkload_test.go` and shared with the other
parsers so they cannot drift.

## Operation on confidential nodes

The node is the TEE boundary: its components share its attested identity.

```text
NODE-AS-CVM — one TEE, one identity, per node
╔═ node CVM (SEV-SNP/TDX guest; measured IGVM+UKI+dm-verity boot) ══════╗
║  workload pods (runc) ─┐ injected endpoint + get-cert sidecars         ║
║  CDS (one pod)        ─┼─ share the NODE's TEE identity                ║
║  nri-image-policy     ─┘ (the enforcer, a node process)               ║
║  attestation-api DaemonSet ── evidence from the node's TEE device     ║
║    (/dev/sev-guest, TDX TSM configfs, or vTPM on AKS)                 ║
╚═══════════════════════════════════════════════════════════════════════╝
   host / hypervisor: untrusted, sees ciphertext

```

### Node-as-CVM (base layout on CVM nodes)

The whole Kubernetes node is one confidential VM; pods are ordinary runc
containers inside it. (This is the base component layout — `c8s install` with
`--cvm-mode bare-metal|gke|aks` wiring the right TEE device — deployed onto nodes
that are themselves CVMs. Base on non-CVM nodes has the same layout and no
confidentiality.)

- **Evidence source:** the per-node attestation-api DaemonSet mounts the host
  TEE interface (`/dev/sev-guest`; TSM ConfigFS reports on TDX hosts; vTPM on
  AKS). The API binds pod loopback and its attest-proxy sidecar serves it on a
  node-local Unix socket, so `/attest` is reachable only by on-node callers
  and always produces evidence for the *caller's own node* — nothing
  routable can request evidence, and `/verify` verdicts never cross a node
  boundary.
- **armTLS endpoints:** every covered pod runs its own injected endpoint
  (outbound :15001, inbound :15006, probes :15021). The node enforcer installs
  the pod's packet rules before any of its containers runs, so the pod's
  application TCP leaves it only through that endpoint over armTLS; the
  delivery hop inside the pod is plaintext *inside the node's encrypted
  memory* (see [`cmd/armtls-mesh/README.md`](../cmd/armtls-mesh/README.md)).
- **Identity granularity:** one launch digest covers the node — kubelet, CNI,
  every pod. All pods share the node's TEE identity; a workload leaf's SAN
  names the workload, but the attestation behind it is the node's quote. Pods
  are only kernel-isolated from each other.
- **Certificates:** each pod's get-cert sidecar fetches a mesh-CA leaf from
  CDS through the node's attestation flow, and publishes it to that pod's own
  endpoint.

- **DNS.** The pod ruleset admits UDP/53 to the resolver trusted policy
  names, and nothing else. A resolver sits outside the guest's trust
  boundary whatever its address, so its answers are untrusted input: they
  select which endpoint a workload dials, and the armTLS handshake at that
  endpoint is what authenticates the peer. A host that swaps, forges or
  drops a DNS answer redirects or denies a connection it cannot read, which
  it can do at the network layer regardless. The carve-out is scoped to the
  cw pod ipset and to UDP/53; every other non-TCP from a cw pod still
  drops.

## Which certificate is used where

| Certificate | Private key lives | Signed by | Presented where | Verified by | Purpose |
|---|---|---|---|---|---|
| Self-issued armTLS cert | the holding process's memory (in the TEE) | itself — trust is the embedded attestation | the evidence-path listeners and dials (CDS, the inventory, the credential clients) | peer's armTLS verification: local attestation-api `/verify` + measurement allowlist | attested transport with no CA in it |
| CDS armTLS serving cert | CDS process memory | itself — attestation bound to CDS's own measurement | CDS API (:8443) | injected clients read the node policy the enforcer mounts; armtls-mesh, allowlist CLI and nri-image-policy pin `--cds-measurements` | protect the issuance/allowlist API from pod-network impostors |
| Mesh CA (P-384, CN `c8s Mesh CA`, 1y) | CDS process memory only — never a Secret, never disk | self-signed root | never served as a leaf; public bundle via `GET /ca` and issuance responses | continuity check: new bundle must be signed by an already-trusted CA | root of trust for the chain path |
| CDS-issued workload leaf (≤ 24h) | pod volume published by get-cert as one generation (`/etc/c8s/certs`, keys 0640 with fsGroup) — inside the node TEE | mesh CA, after challenge–attest–certify | workload's own listeners; router upstream mTLS | chain to the mesh CA bundle | nameable workload identity (SAN = workload id / `c8s-<id>` Service), plus the sandbox-ID extension when the requester presented a sandbox token |
| router public leaf | router pod volume — get-cert init container (mode `cds`) or the `c8s acme` sidecar's Memory-medium emptyDir (mode `acme`) — or an operator-supplied `publicTLS` Secret (mode `webpki`, host-visible) | mesh CA (`cds`), ACME CA (`acme`), or external CA (`webpki`) | public HTTPS front door | browsers: standard TLS; verifiers: `cds-attest` binds the leaf SPKI or session keys into REPORTDATA | TLS termination for external clients, attestably bound to the TEE |
| Inventory identity/digests certs (self-signed armTLS, both ends) | nri-image-policy process memory; CDS process memory for the client side | itself — attestation bound to the node's own measurement | the inventory's `:1019` endpoint (fixed, privileged), mTLS both ways | mutual: CDS pins the inventory measurement, the inventory pins CDS's | let CDS resolve the sandbox-token signing key and ask what a pod sandbox is running before issuing that pod a leaf |

Related authentication surfaces:

- **The admission webhook's TLS** is ordinary Kubernetes PKI (Secret +
  `caBundle`) — it is availability/injection machinery, not a confidentiality
  boundary, and its material is visible to etcd readers.
- **Browser verification:** browser JavaScript cannot inspect and verify
  certificate evidence during TLS handshakes. It uses challenge–response
  attestation and a post-quantum over-encrypted channel — see
  [c8s-verify-js](https://github.com/confidential-dot-ai/c8s-verify-js).
- **Attested RKE2 credential release** (`c8s cred-release`) and the
  operator/allowlist CLIs are armTLS *clients* of the surfaces above rather
  than new certificate types.

## Reading order for the curious

1. [attestation-go/armtls](https://github.com/confidential-dot-ai/attestation-go/tree/main/armtls)
   — the key binding and the extension wire format (start here).
2. [`pkg/armtls/tls.go`](../pkg/armtls/tls.go) + [`verify.go`](../pkg/armtls/verify.go)
   — handshake wiring, rotation, peer verification on both paths.
3. [`pkg/attestclient/client.go`](../pkg/attestclient/client.go) — the CDS
   challenge–attest–certify flow.
4. [`internal/podmesh/ruleset`](../internal/podmesh/ruleset/) — the pod rules
   that put it on every connection.
5. [`pkg/workloadclaims`](../pkg/workloadclaims/) — the inventory's two
   surfaces, the sandbox token, and the digests callback.
6. [getcert-workload-binding.md](getcert-workload-binding.md) — how a pod's
   sandbox identity is established and how CDS gates issuance on what that
   sandbox runs.
