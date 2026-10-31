// Both generators name one cluster's replica set by these flags. `c8s cds
// config` takes them as they are; `c8s launch-config`, whose flags describe
// the nodes as well, prefixes each with cds-.

package cdsconfig

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// ReplicaSetFlags is one cluster's replica set as an operator names it: the
// block itself, and the file holding the key its backups seal to.
type ReplicaSetFlags struct {
	Set HA
	// RecoveryKeyFile holds the public half of that key.
	RecoveryKeyFile string
	// prefix is how this generator names the flags, so an error names the one
	// the operator passed.
	prefix string
}

// BindReplicaSetFlags names the replica set a cluster's CDS runs as into
// named. A document naming none of it runs one CDS as the cluster's
// singleton.
func BindReplicaSetFlags(fs *pflag.FlagSet, prefix string, named *ReplicaSetFlags) {
	named.prefix = prefix
	fs.StringArrayVar(&named.Set.Replicas, prefix+"replica", nil,
		"DNS name or IPv4 address resolving to one replica of this cluster's CDS, never to a load-balanced address; repeatable, and no entry carries a port. Without one, the cluster's CDS is a singleton (docs/cds-ha.md)")
	fs.IntVar(&named.Set.Voters, prefix+"voters", 0,
		"voter seats the replica set starts with, odd and up to "+strconv.Itoa(cdsdecree.MaxVoterSeats)+"; a voters decree moves it later")
	fs.StringVar(&named.Set.Board.Endpoint, prefix+"board-endpoint", "",
		"https://host[:port] of the object store an operator may leave this cluster's decrees in and its backups travel through")
	fs.StringVar(&named.Set.Board.Bucket, prefix+"board-bucket", "", "bucket on that store holding the boards")
	fs.StringVar(&named.Set.Board.Prefix, prefix+"board-prefix", "",
		"path under that bucket to put this cluster's board under (default the bucket root)")
	fs.StringVar(&named.RecoveryKeyFile, prefix+"recovery-key", "",
		"PEM public key (P-256) the cluster's leader seals its backups to before it appends them to the board; its private half stays with the operator, offline, and is what opens one")
}

// ReplicaSet is the block these flags name, with the recovery key read from
// the file they name.
func ReplicaSet(named ReplicaSetFlags) (HA, error) {
	set := named.Set
	if named.RecoveryKeyFile == "" {
		return set, nil
	}
	pemBytes, err := os.ReadFile(named.RecoveryKeyFile)
	if err != nil {
		return HA{}, fmt.Errorf("--%srecovery-key: %w", named.prefix, err)
	}
	if set.RecoveryKey, err = RecoveryKey(pemBytes); err != nil {
		return HA{}, fmt.Errorf("--%srecovery-key: %w", named.prefix, err)
	}
	return set, nil
}
