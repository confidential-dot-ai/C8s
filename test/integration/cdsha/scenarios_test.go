//go:build integration && linux

package cdsha_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// threeReplicas is the cluster most scenarios run on: three replicas, and
// three voter seats for them to fill.
var threeReplicas = shape{voters: 3, replicas: 3}

// The cluster starts where the operator decreed it, and the replicas that did
// not start it join it, serve the same mesh CA, and serve the workloads its
// configuration seeded.
func TestTheDecreedReplicaStartsTheClusterAndTheRestJoinIt(t *testing.T) {
	c := newCluster(t, threeReplicas)

	started, _ := c.status(c.decreed)
	if !started.Joined {
		t.Errorf("the decreed replica reports %+v, want it holding the cluster", started)
	}
	leading := c.waitLeader(30 * time.Second)
	c.waitFor("every replica in the cluster's configuration", 30*time.Second, func() bool {
		return len(c.members(leading)) == len(c.replicas)
	})
	members := c.members(leading)
	for _, r := range c.replicas {
		member, _ := c.status(r)
		if !slices.Contains(members, member.ID) {
			t.Errorf("the cluster names members %v, and replica %d is member %s", members, r.index, member.ID)
		}
		if member.CAFingerprint != started.CAFingerprint {
			t.Errorf("replica %d serves mesh CA %s, and the cluster's is %s", r.index, member.CAFingerprint, started.CAFingerprint)
		}
		if code, body := c.get(r, "/ca"); code != http.StatusOK || !strings.Contains(string(body), "BEGIN CERTIFICATE") {
			t.Errorf("replica %d serves /ca = %d %s, want the cluster's mesh CA", r.index, code, body)
		}
		if code, body := c.get(r, "/allowlist"); code != http.StatusOK || !strings.Contains(string(body), seededWorkload) {
			t.Errorf("replica %d serves /allowlist = %d %s, want the workload the configuration seeded", r.index, code, body)
		}
		c.requirePinDecree(r)
	}
}

// requirePinDecree reads the decree behind the images a CDS of this cluster
// may run: what a node follows, and the Genesis decree until another pins
// them.
func (c *cluster) requirePinDecree(r *replica) {
	c.t.Helper()
	code, body := c.get(r, "/ha/pins")
	if code != http.StatusOK {
		c.t.Fatalf("replica %d serves /ha/pins = %d %s, want the applied pin decree", r.index, code, body)
	}
	var pinned struct {
		Decree struct {
			Kind string `json:"kind"`
		} `json:"decree"`
	}
	if err := json.Unmarshal(body, &pinned); err != nil {
		c.t.Fatalf("replica %d serves a pin decree that does not decode: %v: %s", r.index, err, body)
	}
	if pinned.Decree.Kind != string(cdsdecree.Genesis) {
		c.t.Errorf("replica %d serves a %s pin decree, want the Genesis the cluster started on", r.index, pinned.Decree.Kind)
	}
}

// A write taken by any replica reaches every replica: one that does not lead
// hands it to the leader, and the log carries it to the rest.
func TestAWriteTakenByAnyReplicaReachesEveryReplica(t *testing.T) {
	c := newCluster(t, threeReplicas)
	leading := c.waitLeader(30 * time.Second)
	taking := c.others(leading)[0]

	const workload = "written-through-a-replica-that-does-not-lead"
	c.replaceAllowlist(taking, workload)
	c.waitFor("every replica to serve the written allowlist", 30*time.Second, func() bool {
		return c.allServe(workload)
	})
}

// The one voter the cluster's Genesis seated is lost, and every replica stops
// serving: a replica answers a read under a lease its leader confirmed, so
// one that cannot reach a leader fails closed instead of answering from the
// state it still holds. Filling a second seat, so another replica can lead,
// comes with the voter seats.
func TestEveryReplicaStopsServingWhenTheClusterLosesItsVoter(t *testing.T) {
	notShort(t)
	c := newCluster(t, threeReplicas)
	leading := c.waitLeader(30 * time.Second)
	c.waitVoter(leading, 30*time.Second)

	if reported, _ := c.status(leading); len(reported.Voters) != 1 {
		t.Fatalf("the leader reports voters %v, want it holding the cluster's one vote", reported.Voters)
	}
	c.kill(leading)
	c.waitFor("every replica to stop serving", time.Minute, func() bool {
		return len(c.serving()) == 0
	})
	for _, r := range c.others(leading) {
		if code, body := c.get(r, "/allowlist"); code != http.StatusServiceUnavailable {
			t.Errorf("replica %d serves /allowlist = %d %s, want it refused", r.index, code, body)
		}
		if code, _ := c.get(r, "/readyz"); code != http.StatusServiceUnavailable {
			t.Errorf("replica %d answers /readyz = %d, want it unready", r.index, code)
		}
	}
}

// A replica whose process restarts rejoins as a new member and serves the
// state the cluster holds, including the writes it missed.
func TestARestartedReplicaRejoinsItsCluster(t *testing.T) {
	notShort(t)
	c := newCluster(t, threeReplicas)
	leading := c.waitLeader(30 * time.Second)
	restarting := c.others(leading)[0]
	c.waitWithoutAVote(restarting, 30*time.Second)
	was, _ := c.status(restarting)

	c.kill(restarting)
	const workload = "written-while-a-replica-was-down"
	c.replaceAllowlist(leading, workload)
	c.restart(restarting)

	c.waitFor("the restarted replica to serve its cluster", time.Minute, func() bool {
		return slices.Contains(c.serving(), restarting)
	})
	rejoined, _ := c.status(restarting)
	if rejoined.ID == was.ID {
		t.Errorf("the restarted replica reports member %s again; a new process is a new member", rejoined.ID)
	}
	if code, body := c.get(restarting, "/allowlist"); code != http.StatusOK || !strings.Contains(string(body), workload) {
		t.Errorf("the restarted replica serves /allowlist = %d %s, want the write it missed", code, body)
	}
}

// A cluster with more replicas than votes: the replicas holding none serve
// reads and hand their writes to the one that leads.
func TestReplicasThatHoldNoVoteStillServe(t *testing.T) {
	notShort(t)
	c := newCluster(t, shape{voters: 1, replicas: 3})
	leading := c.waitLeader(30 * time.Second)
	for _, r := range c.others(leading) {
		c.waitWithoutAVote(r, 30*time.Second)
	}

	if reported, _ := c.status(leading); len(reported.Voters) != 1 {
		t.Fatalf("the leader reports voters %v, want one vote in the cluster", reported.Voters)
	}
	const workload = "written-to-a-cluster-with-one-vote"
	c.replaceAllowlist(c.others(leading)[0], workload)
	c.waitFor("every replica to serve the written allowlist", 30*time.Second, func() bool {
		return c.allServe(workload)
	})
}

// allServe reports every replica serving an allowlist that names workload.
func (c *cluster) allServe(workload string) bool {
	for _, r := range c.replicas {
		code, body := c.get(r, "/allowlist")
		if code != http.StatusOK || !strings.Contains(string(body), workload) {
			return false
		}
	}
	return true
}

// replaceAllowlist writes the whole allowlist document through r, naming one
// workload the test reads back. A cluster refuses an operator token issued
// before it started plus the clock skew, so the write is retried with a fresh
// token until the cluster takes one.
func (c *cluster) replaceAllowlist(r *replica, workload string) {
	c.t.Helper()
	document := []byte(`{"schema":"c8s.allowlist/v1","workloads":{"` + workload +
		`":{"label":"ghcr.io/x/` + workload + `:v1","containers":[{"digest":"sha256:` +
		strings.Repeat("22", 32) + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`)
	var code int
	var body []byte
	c.waitFor(fmt.Sprintf("replica %d to take an operator write", r.index), 30*time.Second, func() bool {
		code, body = c.put(r, "/allowlist", document)
		return code == http.StatusNoContent
	})
	if code != http.StatusNoContent {
		c.t.Fatalf("PUT /allowlist through replica %d = %d %s", r.index, code, body)
	}
}

// notShort skips the scenarios the -short subset leaves to the full run.
func notShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("not in the -short subset")
	}
}
