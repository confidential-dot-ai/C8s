package taconfig

import (
	"strconv"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/tadecree"
)

// BindReplicaSetFlags names the replica set a cluster's Trust Authority runs as into set,
// as `c8s ta config` takes it. A document naming none of it runs one Trust Authority as
// the cluster's singleton.
func BindReplicaSetFlags(fs *pflag.FlagSet, set *HA) {
	fs.StringArrayVar(&set.Replicas, "replica", nil,
		"DNS name or IPv4 address resolving to one replica of this cluster's Trust Authority, never to a load-balanced address; repeatable, and no entry carries a port. Without one, the cluster's Trust Authority is a singleton (docs/ta-ha.md)")
	fs.IntVar(&set.Voters, "voters", 0,
		"voter seats the replica set starts with, odd and up to "+strconv.Itoa(tadecree.MaxVoterSeats)+"; a voters decree moves it later")
}
