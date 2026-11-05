//go:build integration && linux

package cdsha_test

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/objectwal"
)

// Admission peaks are per actor since process start, including bootstrap. They
// are not a queue-depth sum across replicas or a sampled maximum. Restart reads
// include the restarted actor's initialization and readiness work. The other
// processes and the storage service stay warm; this is not a cold-storage test.
type scaleRuntime struct {
	Replicas             []objectwal.Stats `json:"replicas_after_load,omitempty"`
	MaximumCheckpointLag uint64            `json:"maximum_checkpoint_lag_commands"`
	ColdProcessReadyMS   float64           `json:"cold_process_ready_ms"`
	RestartedActor       *objectwal.Stats  `json:"restarted_actor,omitempty"`
	SameCAAfterRestart   bool              `json:"same_ca_after_restart"`
}

func (c *cluster) actorStats(r *replica) objectwal.Stats {
	c.t.Helper()
	code, body := c.get(r, "/ha/object-wal/status")
	var s objectwal.Stats
	if code != http.StatusOK || json.Unmarshal(body, &s) != nil {
		c.t.Fatalf("replica %d actor stats: HTTP %d", r.index, code)
	}
	if s.PeakAdmitted > uint64(s.AdmissionLimit) || s.PeakAdmittedBytes > s.AdmissionByteLimit || s.Admitted < 0 || s.AdmittedBytes < 0 {
		c.t.Fatalf("replica %d exceeded admission budget: %+v", r.index, s)
	}
	return s
}

func (c *cluster) scaleRuntime() *scaleRuntime {
	r := &scaleRuntime{}
	if c.objectWAL != nil {
		for _, replica := range c.replicas {
			s := c.actorStats(replica)
			r.Replicas = append(r.Replicas, s)
			if s.Applied >= s.Snapshot {
				r.MaximumCheckpointLag = max(r.MaximumCheckpointLag, s.Applied-s.Snapshot)
			}
		}
	}
	return r
}

func (c *cluster) measureRestart(r *replica, stats *scaleRuntime, originalCA string) {
	started := time.Now()
	c.restart(r)
	if c.objectWAL != nil {
		c.provisionObjects(r)
	}
	c.waitServing(time.Minute)
	stats.ColdProcessReadyMS = float64(time.Since(started)) / float64(time.Millisecond)
	if c.objectWAL != nil {
		s := c.actorStats(r)
		stats.RestartedActor = &s
	}
	for _, replica := range c.replicas {
		if c.servedCA(replica) != originalCA {
			c.t.Fatal("process replacement changed the cluster CA")
		}
	}
	stats.SameCAAfterRestart = true
}
