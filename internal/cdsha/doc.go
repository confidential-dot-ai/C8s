// Package cdsha makes CDS highly available: replicas on cds-role nodes form
// one Raft group (hashicorp/raft) over mutually attested TLS and replicate
// everything a CDS holds: the mesh CA, the allowlist store, the secret store
// and the sandbox ledger.
//
//   - attest.go, nodeattest.go, tdxattest.go: peer evidence and its checks.
//   - transport.go: Raft and a control channel on one attested port; Raft
//     addresses name the member, and live connections follow the pin set.
//   - fsm.go, core.go: the replicated state machine and the agreed core.
//   - node.go: bootstrap from a Genesis decree, join, voter seats and
//     non-voters, forwarded writes, freshness (lease, clock jumps), decrees,
//     Recover, sealed backups and Restore.
//   - decree.go, decrees.go: operator decrees and their ConfigMaps.
//   - backup.go: backups sealed to the operator's offline recovery key.
//
// The proposal and its rules are in the CDS-HA spec section (cds-ha-v2).
package cdsha
