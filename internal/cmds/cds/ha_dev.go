//go:build c8s_dev

package cds

import (
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

// haTimingOverride runs the replicas fast enough for a test to watch an
// election, a lease lapse, a seat change and a backup. Every timer it leaves
// unset is the release's own.
var haTimingOverride = cdsha.Timing{
	Heartbeat:  200 * time.Millisecond,
	Election:   200 * time.Millisecond,
	Lease:      time.Second,
	Tick:       100 * time.Millisecond,
	DeadAfter:  5 * time.Second,
	Checkpoint: time.Second,
	Backup:     2 * time.Second,
}
