// Package cdsha is a prototype of CDS high availability: several CDS replicas
// share one mesh CA key without the Kubernetes control plane ever seeing it.
//
// It follows the proposed c8s-workspace specification "CDS High Availability"
// (docs/specification/policy/cds-ha.md, branch spec/cds-ha). Requirement IDs in
// comments (G1, E1, ...) refer to that document. Interim answers to its open
// questions are recorded beside the prototype, not here.
//
// Shape:
//   - record.go:  the signed CDSEpoch chain (O2, O3, E2).
//   - decree.go:  operator-signed decrees (D1-D4).
//   - state.go:   the acceptance rules (E1, E4, E5, L6) as pure functions.
//   - attest.go:  replica-to-replica TLS with attestation evidence in the cert.
//   - peer.go:    heartbeat, sync and key transfer between replicas (H, K).
//   - store.go:   CDSEpoch / CDSDecree persistence in ConfigMaps (a hint only, O6).
//   - replica.go: the loops tying it together (lease, genesis, decrees).
package cdsha
