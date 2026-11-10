package cdsconfig

import (
	"strconv"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// BindReplicaSetFlags names the replica set a cluster's CDS runs as into set,
// as `c8s cds config` takes it. Omit it for a singleton or object-backed replicas.
func BindReplicaSetFlags(
	fs *pflag.FlagSet,
	set *HA,
) {
	fs.StringArrayVar(
		&set.Replicas,
		"replica",
		nil,
		"DNS name or IPv4 address resolving to one peer replica of this cluster's CDS, never to a load-balanced address; repeatable, and no entry carries a port. Omit for singleton or object-backed CDS (docs/cds-ha.md)",
	)
	fs.IntVar(
		&set.Voters,
		"voters",
		0,
		"voter seats the replica set starts with, odd and up to "+strconv.Itoa(cdsdecree.MaxVoterSeats)+"; a voters decree moves it later",
	)
}
