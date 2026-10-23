// Package cdsha makes CDS highly available: replicas on cds-role nodes form
// one Raft group (hashicorp/raft) over mutually attested TLS and replicate
// everything a CDS holds: the mesh CA, the allowlist store, the secret store
// and the sandbox ledger.
//
//   - node.go, members.go, leader.go: the replica, its membership and seats,
//     and the leader's tasks (decrees, Recover and Restore, backups).
//   - fsm.go, format.go, decree.go: the replicated state and operator decrees.
//   - transport.go, attest.go, nodeattest.go: the attested peer port.
//   - kubedecrees.go, backup.go: decree and backup ConfigMaps.
//
// The proposal and its rules are in the CDS-HA spec section (cds-ha-v2).
package cdsha
