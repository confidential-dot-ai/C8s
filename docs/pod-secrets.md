# Pod secret release through a KMS

A Pod CVM can read secrets that live in a key management service (KMS) the
operator runs. CDS does not store them. CDS is a broker: it checks which
verified pod is asking, signs a statement saying so, and forwards the request
to the KMS. The KMS decides and returns the value. CDS relays the value to the
pod and keeps no copy: no store, no cache, no log line.

This page defines the pod side, the CDS side and the CDS-to-KMS wire. Any KMS
that implements the wire below can serve C8s pods.
[`deploy/kms`](../deploy/kms) is a reference KMS.

```text
pod CVM ──mTLS, pod leaf──▶ CDS ──TLS, pinned key──▶ KMS
        ◀───── value ──────     ◀────── value ──────
```

## What the pod asks for

The signed pod manifest names the secrets in the annotation
`confidential.ai/pod-secrets`: a comma-separated list of at most 8 names. A
name is 1 to 128 characters of `[A-Za-z0-9._-]`, never `.` or `..`.

```yaml
metadata:
  annotations:
    confidential.ai/pod-secrets: agent-token,db-password
```

The guest broker (the NRI plugin in the Pod CVM) waits until the pod holds its
CDS leaf. Then it asks CDS for each name and writes the values into the pod's
memory `emptyDir` named `c8s-pod-secrets`, one file per name, mode `0444`.
It writes all values or none. Release is all-or-nothing per pod: if CDS
refuses any requested name, the pod gets none of them and the broker keeps
retrying the whole set. Only workload containers may mount that volume, and
only read-only. The mesh endpoint and other platform containers may not
mount it. A consumer waits for its file to appear.

The broker retries until CDS releases every name: before the leaf exists, and
while the KMS refuses. There is one fetch per pod and no rotation.

## Pod to CDS

`POST /pod-secrets` on the CDS armTLS port. The pod presents its CDS-issued
leaf as its TLS client certificate. CDS verifies the chain against its mesh
CA in the handshake.

```json
{"secret": "agent-token", "client_document": "<base64 client document>"}
```

CDS refuses with `403 secret_refused` unless all of these hold:

- the leaf chains to the mesh CA;
- the leaf names a pod (`…1.4`) and carries a client document digest
  (`…1.9`). CDS stamps `…1.9` only on a Pod CVM leaf whose claims it verified
  ([certificate-extensions.md](certificate-extensions.md));
- `SHA-256(client_document)` equals the leaf's `…1.9` digest.

On success the answer is `200 {"value": "<base64>"}`. A KMS refusal is relayed
as `403 secret_refused` with the KMS's reason in `message`. A KMS that does not
answer, or answers with a 5xx, gives `502 kms_unavailable`.

The pod leaf's private key never leaves the guest broker and the mesh
endpoint's credential volume, so only that pod can present the leaf.

## CDS to KMS

CDS serves `/pod-secrets` only when its measured configuration names a KMS:

```yaml
kms:
  url: https://kms.example/v1/release
  tlsKeySHA256: <64 lowercase hex>
```

Pass `--kms-url` and `--kms-tls-key-sha256` to `c8s cds config new`. A KMS
needs a `podImagePolicy`, because only a Pod CVM leaf can ask.
`tlsKeySHA256` is SHA-256 of the DER SubjectPublicKeyInfo of the KMS's TLS
certificate. CDS authenticates the KMS by this key alone, not by a CA. The
configuration is measured, so a client that verified CDS also knows which KMS
it brokers to.

### Broker key

Each CDS replica generates its own ECDSA P-256 broker key in memory at start.
Replicas do not share it. The mesh CA issues the key a certificate:

- subject `CN=c8s CDS broker`;
- lifetime 1 hour, reissued after 30 minutes or when the mesh CA certificate
  changes;
- one extended key usage, `1.3.6.1.4.1.66378.1.10` (CDS broker). It has no
  server or client authentication usage, so no TLS stack accepts it as a
  mesh peer.

A KMS trusts a broker certificate because it chains to the mesh CA key the KMS
pinned. A single CDS mints its mesh CA key at start; a replica set holds one
for the life of its chain, handed to every replica that joins, until it is
re-rooted ([cds-ha.md](cds-ha.md)). A KMS must re-pin when either changes. Pin the key you read from `GET /ca` over attested
TLS, as `c8s verify` does.

### Request

CDS sends `POST <kms.url>` with `Content-Type: application/json`:

```json
{
  "version": "c8s-secret-release/v1",
  "statement": "<base64 statement bytes>",
  "signature": "<base64 ASN.1 ECDSA signature>",
  "broker_chain": ["<base64 DER broker certificate>", "<base64 DER mesh CA certificate>"],
  "client_document": "<base64 client document>"
}
```

`statement` is the exact signed bytes, a JSON object:

```json
{
  "version": "c8s-secret-statement/v1",
  "pod": "pcvm-<64 hex>",
  "workload": {"name": "agent", "allowlist_version": "12", "allowlist_digest": "<64 hex>"},
  "client_document_digest": "<64 lowercase hex>",
  "secret": "agent-token",
  "issued_at": "2026-11-08T21:00:00Z",
  "nonce": "<base64, 32 bytes>"
}
```

- `pod`: the pod instance the leaf names (`…1.4`).
- `workload`: the allowlist entry the leaf's `…1.5` names, if it has one.
  Omitted otherwise.
- `client_document_digest`: the leaf's `…1.9`.
- `secret`: the requested name, under the rules above.
- `issued_at`: RFC 3339, UTC, whole seconds.
- `nonce`: 32 random bytes, fresh per statement.

`signature` is ECDSA with the broker key over
`SHA-256("c8s-secret-statement/v1" || 0x00 || statement)`, ASN.1 DER encoded.

### What the KMS checks

A KMS must refuse the request unless all of these hold
(`secretbroker.Verifier` implements the first six):

1. `version` is `c8s-secret-release/v1`, and the statement's `version` is
   `c8s-secret-statement/v1`.
2. `broker_chain` is exactly two certificates. SHA-256 of the second one's
   SubjectPublicKeyInfo is the mesh CA key the KMS pinned.
3. The broker certificate is signed by that CA, is valid now and carries the
   CDS broker extended key usage.
4. `signature` verifies over `statement` under the broker certificate's key.
5. `SHA-256(client_document)` equals `client_document_digest`.
6. `issued_at` is within 5 minutes of the KMS clock.
7. The `nonce` was not seen within that window.
8. The KMS's own policy allows the release. CDS never reads the client
   document. Who the client is, and what it may read, is the KMS's decision:
   it checks whatever signature or claims its client document format carries.

### Response

- `200` with `{"version": "c8s-secret-release/v1", "value": "<base64>"}`. The
  value is at most 64 KiB. CDS does not relay a `200` with another `version`,
  no `value` or a larger value: the pod gets `502 kms_unavailable`.
- Any `4xx` with `{"error": "<reason>"}` is a refusal. CDS relays the reason,
  cut to 256 bytes, to the pod.
- Anything else means the KMS is unavailable.

## Trust

- A KMS that releases on this wire trusts CDS to state the pod and its client
  document truthfully. That is the same trust a client places in a CDS-issued
  leaf ([armtls.md](armtls.md)).
- The value crosses CDS memory once, inside the request that carries it. CDS
  does not write it to its store, its replicated log or its logs.
- The client document carries no secrets: the pod's annotation and the
  assignment that carry it are visible to the control plane.
