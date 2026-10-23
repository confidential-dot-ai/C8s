# Route evidence

The router's attestation sidecar (`cds-attest`) binds the digest of the route manifest it routes by into the evidence of both attested handshakes. A client that verifies the evidence learns the digest of the manifest the router had applied when it admitted the session. The router routes the session only by that manifest: once another one is applied, it refuses the session's requests and the client attests again. Attestation authenticates that manifest; backend TLS authenticates the destinations it names.

## What the evidence proves

Four changes a control plane without an operator key can attempt, and what catches each:

- **Manifest tampering.** The router refuses a manifest whose write token does not verify and keeps its last valid manifest. The evidence then binds that older manifest, so a client pinning the new digest fails, while a client checking the operator keys accepts it unless its floor refuses the revision.
- **Endpoint substitution.** Repointing DNS or a Service changes no manifest byte, so attestation still succeeds. The router's backend TLS check rejects the substitute: a workload backend must present a leaf carrying the manifest's workload name, whatever address the name resolved to.
- **Policy redefinition.** An allowlist write can redefine an entry, so a pod running other code obtains the same workload name under a new allowlist digest. The router requires a workload backend's stamped allowlist digest to equal the one on its own mesh leaf, which the evidence binds, so it refuses a same-name backend admitted under another allowlist. The router and its backends renew independently, so after an allowlist write a workload route answers 502 `backend_digest_mismatch` until both carry the new digest: up to the slower of their `--ca-watch-interval`s, plus half an interval of jitter, plus one issuance, or until the next scheduled renewal where the watch is off. Connections pooled under the router's previous digest retire on the next route poll. A router whose leaf carries no stamp binds no policy digest and checks workload backends by name alone; a client sees that from the absent stamp on the router's leaf and a pinning client fails closed.
- **Post-handshake update.** A manifest applied after the handshake, or a router leaf renewed under another allowlist digest, does not route the session: the router refuses its requests. See [Server](#server).

The route digest is the SHA-256 of the manifest bytes as stored on CDS. `c8s routes show` and `c8s routes digest FILE` print it as 64 lowercase hex characters, the form `c8s verify --route-digest` takes.

## Transcripts

Each transcript is SHA-384 over length-prefixed fields, where `LP(x)` is the 4-byte big-endian length of `x` followed by `x`. The route digest is the last field of both.

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

- `route_digest` is exactly 32 bytes. `pkg/overenc` refuses any other length, including an empty one.
- The attest-pq domain string is `c8s-verify/v1`, shared with the HKDF labels and tunnel AAD tags (`c8s-verify/v1/...`); the attest-pq transcript is also the HKDF salt. The attest-lb domain is its binding id.
- There is no negotiation. The bundle's `version` carries the binding id, and a client rejects any other value.
- The bundle carries `route_digest` in hex. A client may recompute the transcript with it, since a forged value fails verification, but that proves only which manifest the router applied. To require a specific manifest, a client pins its digest or verifies the published manifest. `c8s verify` requires one of the two. It uses the field to choose among `--route-digest` pins, to trigger the V2 re-fetch, and to name a mismatch early; `report_data` alone binds the digest.

The golden vectors in `pkg/overenc/testdata/` pin both layouts.

### Upgrade from the earlier layout

The route digest field redefines both transcripts, and the attest-pq channel keys derived from them, under the same binding ids. No version field marks the layout (only a new router sets `route_digest`), so this is a breaking replacement. Only new against new works; any mixed pair fails verification, and an attest-pq channel fails to open, with no version error to say why.

Each independent implementation of a transcript must change:

| Consumer | Transcript | Vectors it must reproduce |
|---|---|---|
| `c8s verify` and the router | both | `pkg/overenc/testdata/*` (in tree) |
| TEErminator | attest-lb | `attest_lb_transcript_vectors.json` |
| `c8s-verify-js` | attest-pq | `attest_pq_channel_vectors.json` |

No workflow enforces this order. Release by hand in this order:

1. Release TEErminator and `c8s-verify-js` versions whose tests reproduce these vectors. The `c8s-verify-js` version must also seal `Host` in every tunnel request ([Route by the manifest](operator.md#route-by-the-manifest)).
2. Record those versions in the c8s release notes as the minimum compatible clients.
3. Release c8s. The CLI, router image and chart share one version ([Releases](releases.md)), so `c8s verify` and the router match.
4. Upgrade the router and every client in one window. Attested handshakes from clients not yet upgraded fail until they are; plain routing is unaffected.

To roll back, redeploy the previous c8s chart and pin clients to the versions before step 1. Rollback is the same breaking change in reverse, with the same window.

Evidence saved before the change no longer verifies. Keep the c8s release that produced it to check it again.

## Server

Each handshake loads the applied manifest once, at admission, and binds that manifest's digest; it never loads a second one. `cds-attest` refuses the handshake with HTTP 503 and one of these codes:

- `routes_unavailable` before the router has applied a manifest;
- `routes_stale` while the applied manifest is older than its `maxAgeSeconds` without a refresh.

A session is bound to what its handshake bound: the route digest, and the allowlist digest of the router stamp on the mesh leaf (empty for an unstamped leaf). An attest-pq session is bound by its session ID. An attest-lb handshake binds the public TLS connection it arrived on, which nginx names in `X-C8s-Connection` (`$pid.$connection`, replacing any client value). A request on a bound session is routed only while the applied manifest's digest and the router's digest, as of its last route poll, equal the bound ones. Otherwise `cds-attest` refuses it with HTTP 503, without forwarding it:

- `route_digest_changed` when another manifest is applied;
- `router_digest_changed` when the router's leaf renewed under another allowlist digest.

The tunnel answers with the JSON error body and ends the attest-pq session. The routing listener answers with the code as a plain-text body and keeps the connection bound, so every later request on it is refused until the client attests again. A request on a connection with no attest-lb handshake routes by the applied manifest. A handshake rereads the router's credential first, and refuses with 503 `binding_unavailable` while the leaf it would bind carries another digest than the router checks requests against, as during a renewal.

An attest-lb binding lives for 2 minutes after the last request on its connection, longer than nginx keeps an idle connection open (65s). Each replica holds at most 65536; at that bound `cds-attest` refuses a new attest-lb handshake with 503 `sessions_busy` rather than drop a binding. A handshake that did not come through nginx carries no connection identifier and binds nothing; `cds-attest` logs that once at Warn. nginx restarts its connection counter when it restarts, so for up to 2 minutes a new connection can take the identifier of a bound one and be refused with its code. A binding holds only for the connection its handshake arrived on: a request on another connection, which may reach another replica, routes by the applied manifest.

`cds-attest` refuses to start without `--cds-url`, so a running sidecar always has a route source.

## Publication

Helm `router.routePublication.enabled: true` (default `false`; `c8s node-image render` sets it for baked nodes) renders `cds-attest --publish-routes`. `GET /.well-known/c8s/routes` then returns the applied signed manifest, byte for byte the CDS `GET /routes` envelope:

```json
{"manifest": "<standard padded base64 of the manifest bytes>", "token": "<write token>"}
```

The response carries `Cache-Control: no-store`. The path returns 404 when publication is off, before the first apply, and when the attestation endpoints are off. A stale manifest is still the applied one and is still served. Publication is off by default because the manifest names hosts, backend addresses and workload names. Without publication, clients pin `--route-digest`. A baked node always publishes: `c8s node-image render` sets the value in the measured image, so keep names that must stay private out of a baked node's manifest. `cds-attest` refuses `--publish-routes` without `--cds-url` or with `--attest-endpoints=false`, and the chart refuses the value with `router.attest.enabled: false`.

## Verify with `c8s verify`

`--mode attest-pq` and `--mode attest-lb` require exactly one of these route checks:

| Flag | Check |
|---|---|
| `--route-digest HEX` | V1. Recomputes the transcript with this digest, so evidence that binds any other digest fails. Repeat the flag to accept any of several digests. |
| `--operator-keys FILE` | V2. Fetches `/.well-known/c8s/routes` before the handshake, verifies the write token under these PEM public keys (see [Verify a published manifest](#verify-a-published-manifest)), and recomputes the transcript with the manifest's digest. If the bundle's `route_digest` names another digest, fetches the publication once more and accepts its manifest, whatever its revision, if it passes the same checks and matches; anything else fails. |
| `--routes-floor REV:HEX` | With `--operator-keys`. Refuses a published manifest whose revision is lower than `REV`, or equal with another digest (rollback). Without it, any revision an operator signed is accepted. |

```sh
c8s verify https://router.example --mode attest-lb --measurements DIGEST \
    --route-digest "$(c8s routes digest routes.json)"
c8s verify https://router.example --mode attest-pq --measurements DIGEST \
    --operator-keys operator.pub --routes-floor 12:ROUTE_DIGEST
```

- `DIGEST`: the router's launch measurement.
- `operator.pub`: the operator public keys the manifest must be signed under.
- `ROUTE_DIGEST`: the digest of the last revision you accepted, here revision 12.

The verdict prints the route digest, the published revision with `--operator-keys`, and which check supplied it; JSON output carries `route_digest`, `route_revision` and `route_note`. With more than one router replica, the publication fetch and the handshake can land on different replicas, so a pin or V2 check can fail for up to one poll interval after an update. Discovery and armtls-cert evidence carries no route digest. To check a saved attest-pq bundle or attest-lb receipt (`--from-file`), pass `--route-digest`. `--expected-report-data` replaces the transcript, so it applies only to bare evidence: the attested modes and saved attest-pq or attest-lb responses refuse it, and `--kind cds` refuses `--operator-keys` in them.

### Change routes with pinned clients

A client pinning `--route-digest` fails once the router applies a new manifest. To change routes without failing it:

1. Pass both the old and the new digest: `--route-digest OLD --route-digest NEW`.
2. Write the new manifest.
3. Wait until every router replica has applied it.
4. Remove the old digest.

`c8s routes show` reports the stored manifest, which a router may still be staging or may not have polled yet. To see the digest a replica has applied, read the `route_digest` field of a handshake against that replica.

### Keep a rollback floor

`c8s verify` stores no state; the caller keeps the floor:

1. To bootstrap, take the revision and digest from the operator who wrote the manifest, or from `c8s routes show`. A first run without `--routes-floor` trusts whatever revision the router publishes.
2. Store `REV:HEX` per router, in storage the control plane cannot write or revert. A floor restored to an older value accepts the revisions it had refused.
3. After each verified run, update the floor from the verdict's `route_revision` and `route_digest` in one atomic compare-and-update, or with runs serialized per router. Write only a higher revision; never replace the floor with a lower one. An equal revision with another digest is a rollback: keep the floor and investigate. Never update it on a failed run.

A CDS database reset lets an operator write any revision again. To keep floors valid, write the next revision above the last published one. If a lower revision is legitimate, `c8s verify` refuses it as a rollback: confirm the new revision and digest with the operator out of band, then set the floor to them by hand.

## Verify a published manifest

An independent verifier checks the envelope from `/.well-known/c8s/routes` in this order:

1. The token is a JWS signed with ES256, ES384 or ES512 under one of the operator keys. Refuse any other algorithm.
2. `htm` is `PUT` and `htu` is `/routes`.
3. `pbh` is the unpadded base64url SHA-256 of the decoded manifest bytes.
4. The manifest bytes satisfy the manifest schema (`pkg/routes` `Parse`).

The token authorized a write, and CDS checked its time claims then. The c8s signer stamps a 60-second lifetime by default; CDS accepts any `exp - iat` up to five minutes, plus its configured clock skew. Ignore `exp`, `nbf` and `iat` when reading the token back: a standard JWT expiry check accepts a manifest published within its token's lifetime, then rejects it once the token expires. `pkg/routes` `VerifySigned` does all four checks.

Do not check time on the manifest either. `notBefore` gates when the router applies a manifest, so a published one has already passed it on the router's clock. Freshness is the router's state, measured from its last successful fetch from CDS, not from signing time: `cds-attest` refuses handshakes with `routes_stale` once `maxAgeSeconds` passes without one. A client cannot see that state, so admission of the handshake is the freshness check.
