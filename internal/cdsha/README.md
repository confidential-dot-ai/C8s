# internal/cdsha — CDS high availability

Implements the proposed c8s-workspace spec *CDS High Availability*
(`docs/specification/policy/cds-ha.md`, branch `spec/cds-ha`). Several CDS replicas share one
mesh CA key. The Kubernetes control plane only sees public records and signed operator intents.

On baked nodes, CDS enables it with `--ha-config=/run/c8s-node/cds-ha.json`, which node-services
publishes from the signed launch document of a `cds`-role node. Without it, CDS is the usual singleton.

| File | Role |
|---|---|
| `record.go` | Signed epoch chain: epoch 0 is self-signed, each next record is signed by the previous key and embeds its decree. |
| `decree.go` | Operator-signed `Genesis` / `UpdateMeasurements` / `RotateKey` and their checks. |
| `state.go` | `Next`: the acceptance rule (accept only a newer chain that extends ours; a key must match the tail). |
| `attest.go` | Peer TLS: self-signed cert carrying evidence bound to `cluster_id`, the TLS key and the launch-key anchor. |
| `nodeattest.go` | `node` attestor: evidence and verification through the node's attestation-api (TDX and SEV-SNP). |
| `tdxattest.go` | `tdx` attestor: own quote via configfs-tsm; peers verified in-process with attestation-go. |
| `peer.go` | `/ha/v1/heartbeat` and `/ha/v1/sync` (chain + key). |
| `replica.go`, `writer.go` | Heartbeat loop, Lease, genesis, decree application, retirement, CDSEpoch publishing. |
| `store.go` | `CDSEpoch` / `CDSDecree` as ConfigMaps (untrusted hints). |

Invariants:
- Nothing is minted without an operator `Genesis` decree; epoch 0 carries it.
- Every epoch after 0 carries the operator decree that produced it. Holding the previous key is not enough to author an epoch.
- A joined replica never adopts a fork. A replica with no chain takes a chain and key only if the chain's tail pins both
  the source and itself.
- Peers must present valid evidence bound to this cluster and the TLS key, and the same launch-key anchor
  (TDX RTMR3 / SNP HOST_DATA). A joined replica also checks the peer's measurement against the current pins.
- A replica never holds an epoch it has no matching key for. A key is accepted only if it matches `root_cert`.
- A key is sent only over mutually attested TLS, and only to a peer whose measurement is pinned by the epoch being sent.
- A replica whose own measurement is unpinned drops its key and leaves the Lease.
- A replica that sees a verified CDSEpoch for a rotation whose key it lacks stops serving (BehindRotation).
- Only a serving replica, or a replica with no chain that reaches peers, contends for the Lease.

`lease_duration` must be whole seconds, because the Lease API stores seconds.

Attestors: `node` (production; the chart uses it), `tdx` (in-process DCAP verification against Intel PCS
collateral), and `mock` (unsigned, `-tags c8s_dev` only; it must not ship). `tdx` verification is tested against a
real captured quote (`CDSHA_TDX_EVIDENCE=<batch.json> go test -run TDX ./internal/cdsha`). The multi-replica tests
(`cluster_test.go`) run several replicas in-process with a test-only attestor.

Run replicas with a readiness probe on the main port. Otherwise a rollout can remove every key holder before the
replacements have synced.
