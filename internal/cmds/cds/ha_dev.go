//go:build c8s_dev

package cds

import (
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

// A c8s_dev build serves a cluster's CDS as a replica set, so a test can run
// a cluster of them outside a TEE deployment.
const servesReplicas = true

// haTiming runs the replicas fast enough for a test to watch an election and
// a lease lapse. Every timer it leaves unset is the release's own.
var haTiming = cdsha.Timing{
	Heartbeat: 200 * time.Millisecond,
	Election:  200 * time.Millisecond,
	Lease:     time.Second,
	Tick:      100 * time.Millisecond,
}
