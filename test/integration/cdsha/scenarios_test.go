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
		c.requirePinDecree(r, cdsdecree.Genesis, c.genesisIntent)
	}
}

// requirePinDecree reads the decree behind the images a CDS of this cluster may
// run, which is what a node follows.
func (c *cluster) requirePinDecree(r *replica, kind cdsdecree.Kind, intent string) {
	c.t.Helper()
	code, body := c.get(r, "/ha/pins")
	if code != http.StatusOK {
		c.t.Fatalf("replica %d serves /ha/pins = %d %s, want the applied pin decree", r.index, code, body)
	}
	var pinned cdsdecree.Signed
	if err := json.Unmarshal(body, &pinned); err != nil {
		c.t.Fatalf("replica %d serves a pin decree that does not decode: %v: %s", r.index, err, body)
	}
	if pinned.Decree.Kind != kind || pinned.Decree.IntentID != intent {
		c.t.Errorf("replica %d serves the %s decree %s, want the %s decree %s",
			r.index, pinned.Decree.Kind, pinned.Decree.IntentID, kind, intent)
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

// A cluster of one voter seat loses that voter, and every replica stops
// serving: a replica answers a read under a lease its leader confirmed, so
// one that cannot reach a leader fails closed instead of answering from the
// state it still holds.
func TestEveryReplicaStopsServingWhenTheClusterLosesItsVoter(t *testing.T) {
	notShort(t)
	c := newCluster(t, shape{
		voters:   1,
		replicas: 3,
	})
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
	c.waitVoter(restarting, 30*time.Second)
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

// The cluster of the seat scenarios: five replicas for three seats.
var fiveReplicas = shape{
	voters:   3,
	replicas: 5,
}

// The replicas left over hand their writes to the leader.
func TestTheVoterSeatsAreFilledAndTheReplicasLeftOverServeReads(t *testing.T) {
	c := newCluster(t, fiveReplicas)
	leading := c.waitLeader(30 * time.Second)
	c.waitRollSafe(time.Minute)

	if seated, spare := c.seated(), c.withoutAVote(); len(seated) != fiveReplicas.voters || len(spare) != 2 {
		t.Fatalf("the cluster seats %v and holds %v without a vote, want %d seats of five replicas",
			seated, spare, fiveReplicas.voters)
	}
	const workload = "written-through-a-replica-that-holds-no-vote"
	c.replaceAllowlist(c.others(leading)[0], workload)
	c.waitFor("every replica to serve the written allowlist", 30*time.Second, func() bool {
		return c.allServe(workload)
	})
}

// The cluster is no cluster to replace a replica of from the moment that voter
// stops answering, and one again once its seat is filled.
func TestADeadVoterGivesItsSeatToAReplicaWithoutAVote(t *testing.T) {
	notShort(t)
	c := newCluster(t, fiveReplicas)
	leading := c.waitLeader(30 * time.Second)
	c.waitRollSafe(time.Minute)
	c.waitEveryReplicaJoined(time.Minute)
	dying := c.holdingAVote(leading)
	lost, _ := c.status(dying)

	c.kill(dying)

	c.waitFor("the cluster to report no replica of it replaceable", devDeadAfter/2, func() bool {
		safe := c.leaderReport().RollSafe
		return safe != nil && !safe.OK
	})
	taken := "the lost voter's seat taken by a replica that held no vote"
	c.waitFor(taken, 2*time.Minute, func() bool {
		seated := c.seated()
		return len(seated) == fiveReplicas.voters && !slices.Contains(seated, lost.ID)
	})
	c.waitRollSafe(time.Minute)
}

// A replacement is a membership change, and the log carries writes and
// membership both.
func TestAVoterIsReplacedWhileTheClusterTakesWrites(t *testing.T) {
	notShort(t)
	c := newCluster(t, fiveReplicas)
	leading := c.waitLeader(30 * time.Second)
	c.waitRollSafe(time.Minute)
	c.waitEveryReplicaJoined(time.Minute)
	dying := c.holdingAVote(leading)

	c.kill(dying)
	for i := range writesWhileASeatChanges {
		c.replaceAllowlist(leading, fmt.Sprintf("written-while-a-seat-changed-%d", i))
	}

	last := fmt.Sprintf("written-while-a-seat-changed-%d", writesWhileASeatChanges-1)
	c.waitFor("the replicas that stayed to serve the last write", time.Minute, func() bool {
		return c.allServing(c.others(dying), last)
	})
	c.waitRollSafe(2 * time.Minute)
}

const writesWhileASeatChanges = 5

// A replica cut off and back is no replica's to replace.
func TestAVoterThatAnswersAgainKeepsItsSeat(t *testing.T) {
	notShort(t)
	c := newCluster(t, fiveReplicas)
	leading := c.waitLeader(30 * time.Second)
	c.waitRollSafe(time.Minute)
	c.waitEveryReplicaJoined(time.Minute)
	seated := c.seated()
	paused := c.holdingAVote(leading)

	c.pause(paused)
	time.Sleep(devDeadAfter / 2)
	held := c.seated()
	c.resume(paused)

	if !slices.Equal(held, seated) {
		t.Errorf("the cluster seats %v, want the %v it seated while the cut voter answers again within DeadAfter",
			held, seated)
	}
	c.waitServing(time.Minute)
	c.waitRollSafe(time.Minute)
}

// The DeadAfter a c8s_dev build runs with: the scenarios above cut a replica
// off for half of it.
const devDeadAfter = 5 * time.Second

// The cluster fills the seats a SetVoters decree adds, and takes the vote of
// the voters the seats it leaves no longer hold.
func TestASetVotersDecreeMovesTheSeatsOfTheCluster(t *testing.T) {
	notShort(t)
	c := newCluster(t, fiveReplicas)
	leading := c.waitLeader(30 * time.Second)
	started, _ := c.status(leading)

	intent, _ := c.decreeVoters(leading, started.Version, fiveReplicas.replicas)

	c.waitFor("every replica seated", time.Minute, func() bool {
		return c.allApplied(intent, started.Version+1) && len(c.seated()) == fiveReplicas.replicas
	})
	c.waitRollSafe(time.Minute)

	back, _ := c.decreeVoters(c.waitLeader(30*time.Second), started.Version+1, fiveReplicas.voters)

	c.waitFor("the seats back to three", 2*time.Minute, func() bool {
		return c.allApplied(back, started.Version+2) && len(c.seated()) == fiveReplicas.voters
	})
	c.waitRollSafe(time.Minute)
	if spare := c.withoutAVote(); len(spare) != 2 {
		t.Errorf("the cluster holds %v without a vote, want the two the seats no longer hold",
			spare)
	}
}

func (c *cluster) allServe(workload string) bool {
	return c.allServing(c.replicas, workload)
}

func (c *cluster) allServing(replicas []*replica, workload string) bool {
	for _, r := range replicas {
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

// The operator pins the CDS images of the cluster by decree: a replica that
// does not lead hands the posted decree to the leader, the operator reads the
// version it produced, and every replica then serves it as the decree a node
// and a client follow.
func TestAPinDecreeOfTheOperatorAppliesAtEveryReplica(t *testing.T) {
	c := newCluster(t, threeReplicas)
	leading := c.waitLeader(30 * time.Second)
	started, _ := c.status(leading)

	intent, delivered := c.decreePins(c.others(leading)[0], started.Version)

	if delivered.Version != started.Version+1 || delivered.Refused != "" {
		t.Errorf("the cluster answered %+v for the decree, want it applied at version %d", delivered, started.Version+1)
	}
	c.waitFor("every replica to hold the pin decree", time.Minute, func() bool {
		return c.allApplied(intent, started.Version+1)
	})
	for _, r := range c.replicas {
		c.requirePinDecree(r, cdsdecree.UpdateMeasurements, intent)
	}
}

// A RotateKey decree forks the cluster's mesh: its leader mints a mesh CA
// through the log, and every replica serves and issues under the certificate
// the log carries.
func TestARotateKeyDecreeGivesTheClusterAMeshCAOfItsOwn(t *testing.T) {
	notShort(t)
	c := newCluster(t, threeReplicas)
	leading := c.waitLeader(30 * time.Second)
	started, _ := c.status(leading)

	intent, _ := c.decreeRotateKey(leading, started.Version)

	c.waitFor("every replica to serve the mesh CA the decree minted", time.Minute, func() bool {
		return c.allApplied(intent, started.Version+1) && c.allServeOneOtherCA(started.CAFingerprint)
	})
	for _, r := range c.replicas {
		reported, _ := c.status(r)
		if served := c.servedCA(r); served != reported.CAFingerprint {
			t.Errorf("replica %d serves mesh CA %s at /ca and reports %s", r.index, served, reported.CAFingerprint)
		}
	}
}

// allServeOneOtherCA reports every replica serving one mesh CA between them,
// and none of them the one was names.
func (c *cluster) allServeOneOtherCA(was string) bool {
	serving := map[string]bool{}
	for _, r := range c.replicas {
		reported, answered := c.status(r)
		if !answered || reported.CAFingerprint == "" || reported.CAFingerprint == was {
			return false
		}
		serving[reported.CAFingerprint] = true
	}
	return len(serving) == 1
}
