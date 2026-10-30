package cdsha

import (
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// raiseDoubt records the Recover decree a leader sighted, and answers what
// the entry produced.
func (r *replica) raiseDoubt(sighted cdsdecree.Signed) DecreeResult {
	r.t.Helper()
	res := r.apply(Entry{
		Kind:  KindDoubt,
		Doubt: &sighted,
	})
	if res.Decree == nil {
		r.t.Fatalf("a doubt entry answered no decree result: %+v", res)
	}
	return *res.Decree
}

// renounce records that the member a doubt names gave the Recover decree up,
// as a leader that asked it does.
func (r *replica) renounce(doubt Doubt) DecreeResult {
	r.t.Helper()
	res := r.apply(Entry{
		Kind:     KindRenounce,
		Renounce: &RenounceEntry{Intent: doubt.Intent, Member: doubt.Member},
	})
	if res.Decree == nil {
		r.t.Fatalf("a renunciation answered no decree result: %+v", res)
	}
	return *res.Decree
}

// A leader that sees a signed Recover naming a member it cannot account for
// commits the doubt, so it outlives that leader and a host that withholds the
// decree from the next one.
func TestASightedRecoverBecomesADoubtOnTheLog(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	sighted := r.sign(r.decree(cdsdecree.Recover))
	if res := r.raiseDoubt(sighted); res.Refused != "" {
		t.Fatal(res.Refused)
	}
	doubts := r.ClusterState().Doubts
	if len(doubts) != 1 || doubts[0].Intent != sighted.Decree.IntentID || doubts[0].Member != sighted.Decree.TargetMember {
		t.Fatalf("doubts %+v, want the Recover's intent and member", doubts)
	}
	if res := r.raiseDoubt(sighted); res.Refused != "" || len(r.ClusterState().Doubts) != 1 {
		t.Fatalf("the same decree raised a second doubt: %+v, %+v", res, r.ClusterState().Doubts)
	}
	if r.ClusterState().Version != 1 {
		t.Fatal("a doubt counted as an operator command")
	}

	dismiss := r.decree(cdsdecree.DismissRecover)
	dismiss.RecoverIntent = sighted.Decree.IntentID
	if res := r.applyDecreeEntry(r.entryFor(dismiss)); res.Refused != "" {
		t.Fatal(res.Refused)
	}
	if len(r.ClusterState().Doubts) != 0 {
		t.Fatalf("the doubt survived its DismissRecover: %+v", r.ClusterState().Doubts)
	}

	// The host holds every decree the operator ever signed, dismissed ones
	// included.
	if res := r.raiseDoubt(sighted); res.Refused != "" || len(r.ClusterState().Doubts) != 0 {
		t.Fatalf("a dismissed Recover was doubted again: %+v, %+v", res, r.ClusterState().Doubts)
	}
}

// Only the operator raises a doubt, and only with a Recover: the board it
// travels on is the host's.
func TestOnlyASignedRecoverRaisesADoubt(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	forged := r.sign(r.decree(cdsdecree.Recover))
	forged.Decree.TargetMember = "another-member"
	notARecover := r.sign(r.decree(cdsdecree.RotateKey))
	for name, sighted := range map[string]cdsdecree.Signed{
		"an edited decree": forged,
		"another kind":     notARecover,
	} {
		t.Run(name, func(t *testing.T) {
			if res := r.raiseDoubt(sighted); res.Refused == "" {
				t.Fatal("raised a doubt")
			}
			if len(r.ClusterState().Doubts) != 0 {
				t.Fatalf("doubts %+v", r.ClusterState().Doubts)
			}
		})
	}
}

// A Recover this cluster applied is its own history: the decree is on the
// board for every replica to see, and it must not fence the cluster it
// started.
func TestAnAppliedRecoverRaisesNoDoubt(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	applied := r.decree(cdsdecree.Recover)
	if res := r.applyDecreeEntry(r.entryFor(applied)); res.Refused != "" {
		t.Fatal(res.Refused)
	}
	if res := r.raiseDoubt(r.sign(applied)); res.Refused != "" {
		t.Fatal(res.Refused)
	}
	if len(r.ClusterState().Doubts) != 0 {
		t.Fatalf("the cluster doubts the Recover it applied: %+v", r.ClusterState().Doubts)
	}
}

// A replica that recorded a doubt and then applied that very Recover is the
// cluster the decree started: the doubt goes with it.
func TestApplyingADoubtedRecoverLiftsItsDoubt(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	sighted := r.sign(r.decree(cdsdecree.Recover))
	r.raiseDoubt(sighted)
	if len(r.ClusterState().Doubts) != 1 {
		t.Fatal("the sighted Recover raised no doubt")
	}
	applied := DecreeEntry{
		Decree: sighted,
		AtMS:   time.Now().UnixMilli(),
	}
	if res := r.applyDecreeEntry(applied); res.Refused != "" {
		t.Fatal(res.Refused)
	}
	if len(r.ClusterState().Doubts) != 0 {
		t.Fatalf("the cluster doubts the Recover it applied: %+v", r.ClusterState().Doubts)
	}
}

// A recovery ends the doubt of the Recover it applies and no other: a doubt
// of another member's Recover is the fence that keeps this cluster from
// serving beside the cluster that member may be carrying, and the operator's
// DismissRecover is what lifts it.
func TestARecoveryEndsTheDoubtOfItsOwnRecoverAlone(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	elsewhere := r.decree(cdsdecree.Recover)
	elsewhere.TargetMember = "another-member-of-another-replica"
	sighted := r.sign(elsewhere)
	r.raiseDoubt(sighted)
	if len(r.ClusterState().Doubts) != 1 {
		t.Fatal("the sighted Recover raised no doubt")
	}

	if res := r.applyDecreeEntry(r.entryFor(r.decree(cdsdecree.Recover))); res.Refused != "" {
		t.Fatal(res.Refused)
	}
	doubts := r.ClusterState().Doubts
	if len(doubts) != 1 || doubts[0].Intent != sighted.Decree.IntentID {
		t.Fatalf("the recovered cluster holds the doubts %+v, want the one of Recover %s", doubts, sighted.Decree.IntentID)
	}
	// The decree record is what a backup seals as this cluster's history, so
	// a Recover this cluster never applied must not stand in it.
	if r.ClusterState().accountedFor(sighted.Decree.IntentID) {
		t.Fatalf("the recovery recorded another member's Recover as applied: %+v", r.ClusterState().AppliedDecrees)
	}

	dismiss := r.decree(cdsdecree.DismissRecover)
	dismiss.RecoverIntent = sighted.Decree.IntentID
	if res := r.applyDecreeEntry(r.entryFor(dismiss)); res.Refused != "" {
		t.Fatal(res.Refused)
	}
	if doubts := r.ClusterState().Doubts; len(doubts) != 0 {
		t.Fatalf("the doubt survived its DismissRecover: %+v", doubts)
	}
}

// A DismissRecover names the doubt it lifts, and the cluster must hold it.
func TestDismissRecoverNamesADoubtTheClusterHolds(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	dismiss := r.decree(cdsdecree.DismissRecover)
	dismiss.RecoverIntent = cdsdecree.NewIntentID()
	res := r.applyDecreeEntry(r.entryFor(dismiss))
	if !strings.Contains(res.Refused, "no doubt") {
		t.Fatalf("refusal %q", res.Refused)
	}
}

// A renunciation ends the doubt of the Recover decree it names, and accounts
// for that decree, so the board the host still serves raises it no more.
func TestARenunciationEndsTheDoubtItNames(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	sighted := r.sign(r.decree(cdsdecree.Recover))
	r.raiseDoubt(sighted)
	doubts := r.ClusterState().Doubts
	if len(doubts) != 1 {
		t.Fatal("the sighted Recover raised no doubt")
	}

	if res := r.renounce(doubts[0]); res.Refused != "" {
		t.Fatal(res.Refused)
	}
	if held := r.ClusterState().Doubts; len(held) != 0 {
		t.Fatalf("the doubt survived its renunciation: %+v", held)
	}
	if res := r.raiseDoubt(sighted); res.Refused != "" || len(r.ClusterState().Doubts) != 0 {
		t.Fatalf("a renounced Recover was doubted again: %+v, %+v", res, r.ClusterState().Doubts)
	}
	if r.ClusterState().Version != 1 {
		t.Fatal("a renunciation counted as an operator command")
	}
}

// Only the member a doubt names ends it, and only while the cluster holds
// that doubt: the entry is the leader's word for what that member answered.
func TestARenunciationNamesADoubtTheClusterHolds(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	sighted := r.sign(r.decree(cdsdecree.Recover))
	r.raiseDoubt(sighted)
	held := r.ClusterState().Doubts[0]
	for name, renounced := range map[string]Doubt{
		"another intent": {Intent: cdsdecree.NewIntentID(), Member: held.Member},
		"another member": {Intent: held.Intent, Member: "another-member"},
	} {
		t.Run(name, func(t *testing.T) {
			if res := r.renounce(renounced); !strings.Contains(res.Refused, "no doubt") {
				t.Fatalf("refusal %q", res.Refused)
			}
			if len(r.ClusterState().Doubts) != 1 {
				t.Fatalf("the doubt ended on %+v", renounced)
			}
		})
	}
}
