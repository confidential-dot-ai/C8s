# internal/cdsha — CDS high availability (prototype)

Prototype of the proposed c8s-workspace spec *CDS High Availability*
(`docs/specification/policy/cds-ha.md`, branch `spec/cds-ha`). Several CDS replicas share one
mesh CA key. The Kubernetes control plane only sees public records and signed operator intents.

Enable with `c8s cds --ha-cluster-id=<id> --ha-peers-dns=<headless svc> --ha-attestor=... --ha-replica-pins=...`.
Without `--ha-cluster-id`, CDS is the usual singleton.

| File | Role |
|---|---|
| `record.go` | Signed epoch chain: epoch 0 is self-signed, each next record is signed by the previous key. |
| `decree.go` | Operator-signed `UpdateMeasurements` / `RotateKey` and their checks. |
| `state.go` | `Next`: the acceptance rule (accept only a newer chain that extends ours; a key must match the tail). |
| `tdxattest.go` | TDX attestor: own quote via configfs-tsm; peers verified with attestation-go. |
| `attest.go` | Peer TLS: self-signed cert carrying evidence bound to `cluster_id` and the TLS key. |
| `peer.go` | `/ha/v1/heartbeat` and `/ha/v1/sync` (chain + key). |
| `replica.go`, `writer.go` | Heartbeat loop, Lease, genesis, decree application, retirement. |
| `store.go` | `CDSEpoch` / `CDSDecree` as ConfigMaps (untrusted hints). |

Invariants:
- Every epoch after 0 carries the operator decree that produced it. Holding the previous key is not enough to author an epoch.
- A joined replica never adopts a fork. A cold replica takes a chain only from a peer that the chain pins.
- A replica never holds an epoch it has no matching key for. A key is accepted only if it matches `root_cert`.
- A key is sent only over mutually attested TLS, and only to a peer whose measurement is pinned by the epoch being sent.
- A replica whose own measurement is unpinned drops its key and leaves the Lease.
- Genesis needs the Lease, and every peer must report no key or be unreachable at the TCP level for `genesis_timeout`.
  A peer that answers but fails attestation blocks genesis.

`lease_duration` must be whole seconds, because the Lease API stores seconds.

Attestors: `tdx` (default; the TD's DCAP quote, verified with attestation-go against Intel PCS collateral)
and `mock` (unsigned, `-tags c8s_dev` only; it must not ship). `tdx` verification is tested against a real
captured quote (`CDSHA_TDX_EVIDENCE=<batch.json> go test -run TDX ./internal/cdsha`). Quote generation needs a TD.
Run a deployment with a readiness probe on the main port. Otherwise a rollout can remove every key holder before the replacements have synced.
