# Route evidence

How a client proves which routes the router serves. The router's `cds-attest`
sidecar binds the digest of the route manifest it routes by into the evidence of
both attested handshakes — attest-pq, which runs an X-Wing key exchange so a
client can over-encrypt its requests inside ordinary TLS, and attest-lb, which
binds the exact serving leaf of the connection a client is already on — so a
verifier learns which manifest the router applied when it admitted the session,
and the session routes by that manifest alone. Attestation authenticates it;
backend TLS authenticates the destinations it names. The operator side is
[operator.md](operator.md#route-manifest), the checks [verify.md](verify.md).

## What the evidence proves

Four changes a control plane without an operator key can attempt, and what
catches each:

- **Manifest tampering.** The router refuses a manifest whose write token does
  not verify and keeps its last valid one. The evidence then binds that older
  manifest, so a client pinning the new digest fails, while a client checking
  the operator keys accepts it unless its floor refuses the revision.
- **Endpoint substitution.** Repointing DNS or a Service changes no manifest
  byte, so attestation still succeeds. The router's backend check rejects the
  substitute: a workload backend must present a leaf carrying the manifest's
  workload name, whatever address the name resolved to.
- **Policy redefinition.** An allowlist write can redefine an entry, so a pod
  running other code earns the same workload name. The router takes a workload
  backend only under the allowlist digest stamped on its own leaf — the policy
  snapshot that named the match ([armtls.md](armtls.md#matched-workload)) — and
  the evidence binds the stamped leaf that carries it. A router leaf with no
  stamp binds no policy digest and checks the workload name alone; a client
  pinning the digest sees the stamp missing and fails closed.
- **Post-handshake update.** A manifest applied after the handshake, or a
  router leaf renewed under another allowlist digest, does not route the
  session — [Session binding](#session-binding).

## Session binding

A handshake binds the route digest it reported and the router's own allowlist
digest, empty while the router's leaf carries no stamp; the session routes by
those two and nothing else — attest-pq by its session id, attest-lb by the
public connection the front door names in `X-C8s-Connection`. A handshake that
reaches `cds-attest` without that header binds nothing.

`cds-attest` then refuses that session's requests with 503 rather than forward
them: `route_digest_changed` once another manifest is applied,
`router_digest_changed` once the router's leaf renewed under another allowlist
digest, and `binding_expired` once an attest-lb connection has carried no
request for two minutes. The client attests again: the first refusal ends an
attest-pq session, whose later requests get 401 `channel_error`, while an
attest-lb connection keeps answering 503. The check runs as a request is
admitted, so a response already streaming runs to its end.

A handshake is refused with 503 `routes_unavailable` before the first manifest
is applied, `routes_stale` once the applied one is older than its
`maxAgeSeconds` without a refresh, and `sessions_busy` while a replica, or this
client's share of it, is at its attest-lb binding capacity; all three are worth
retrying. `binding_unavailable` means the router's leaf is renewing, or, when
its stamp does not parse, that no handshake succeeds until the leaf is
replaced.

A routed request is refused with the bare code as a plain-text body; the
handshake and tunnel endpoints return the JSON error envelope.

## The route digest

The route digest is the SHA-256 of the manifest bytes as stored on CDS.
`c8s routes show` and `c8s routes digest FILE` print it as 64 lowercase hex
characters, the form `c8s verify --route-digest` takes.

## Transcripts

Each transcript is SHA-384 over length-prefixed fields, where `LP(x)` is the
4-byte big-endian length of `x` followed by `x`. The route digest is the last
field of both.

attest-pq, binding id `c8s/attest-pq/v1`:

```text
SHA-384( LP("c8s-verify/v1") || LP(mode) || LP(SHA-256(mesh_CA_DER)) ||
         LP(SHA-256(mesh_leaf_DER)) || LP(xwing_ek) || LP(xwing_ct) ||
         LP(session_id) || LP(nonce) || LP(route_digest) )
```

attest-lb, binding id `c8s/attest-lb/v1`:

```text
SHA-384( LP("c8s/attest-lb/v1") || LP(mode) || LP(nonce) ||
         LP(SHA-256(serving_leaf_DER)) || LP(SHA-256(mesh_leaf_DER)) ||
         LP(SHA-256(mesh_CA_DER)) || LP(route_digest) )
```

- `route_digest` is exactly 32 bytes; any other length is refused, an empty one
  included.
- `xwing_ek` and `xwing_ct` are the client's X-Wing encapsulation key and the
  router's ciphertext; X-Wing is the post-quantum KEM attest-pq uses.
- `mode` is the front-door mode the router committed to
  ([operator.md](operator.md)). The attest-pq domain string `c8s-verify/v1` is
  shared with the HKDF labels and the tunnel tags, and the attest-pq
  transcript is also the HKDF salt.
- There is no negotiation. The bundle's `version` carries the binding id, and a
  client rejects any other value.
- The bundle also carries `route_digest` in hex. A client may recompute the
  transcript with it, since a forged value fails verification, but that proves
  only which manifest the router applied: `report_data` alone binds the
  digest. To require a particular manifest, a client pins its digest or
  verifies the published one, and `c8s verify` requires one of the two.

The golden vectors in `pkg/overenc/testdata/` pin both layouts; they are the
contract an independent implementation is checked against.

## Publication

With `router.routePublication.enabled: true` (default `false`, and set by
`c8s node-image render` for baked nodes) the router serves the applied signed
manifest at `GET /.well-known/c8s/routes`, byte for byte the CDS `GET /routes`
envelope and with `Cache-Control: no-store`:

```json
{"manifest": "<standard padded base64 of the manifest bytes>", "token": "<write token>"}
```

The path answers 404 when publication is off, before the first apply, and when
the attestation endpoints are off. A manifest that has gone stale — the
`routes_stale` state above, where no poll has succeeded within `maxAgeSeconds` —
is still the applied manifest, so it is still published and still routes.
Publication is off by default because the manifest names hosts, backends and
workload names; without it, clients pin the digest. A baked node always
publishes, so keep private names out of its manifest.

An independent verifier checks the envelope in this order: the token is a JWS
whose algorithm matches the operator key's curve; it carries `iat` and `exp`
with a lifetime inside five minutes; `htm` is `PUT` and `htu` is `/routes`; its
payload body hash claim `pbh` is the unpadded base64url SHA-256 of the decoded
manifest bytes; and the bytes satisfy the manifest schema. The token authorized
a write, and CDS checked its time claims then, so do not reject a publication on
`exp`, `nbf`, or `iat` when reading the token back. Do not check time on the
manifest either: `notBefore` gates when the router applies it, and freshness is
the router's own state since its last successful fetch, which a client cannot
see. Admission of the attested handshake is the freshness check.
