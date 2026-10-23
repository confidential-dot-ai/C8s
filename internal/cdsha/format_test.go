package cdsha

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// A replica that meets an entry it cannot read stops serving instead of
// skipping it: Raft would move on, and the replica would serve state the
// rest of the group does not have.
func TestFSMStopsOnEntryItCannotRead(t *testing.T) {
	_, opPub := operatorKey(t)
	for name, e := range map[string]any{
		"newer format": Entry{Kind: KindSecret, Format: Format + 1, Secret: &secrets.Command{Op: secrets.OpPut, Path: "/p", Value: []byte("v")}},
		"unknown kind": Entry{Kind: "from-the-future"},
		"newer agreed": Entry{Kind: KindFormat, SetFormat: Format + 1},
		"no payload":   Entry{Kind: KindSecret},
		"undecodable":  json.RawMessage("[1]"),
	} {
		t.Run(name, func(t *testing.T) {
			f := newTestFSM(t, opPub)
			res := applyAt(f, 3, e)
			if _, ok := res.(error); !ok || f.Stuck() == "" {
				t.Fatalf("applied %v, stuck %q", res, f.Stuck())
			}
			if f.AppliedIndex() != 3 {
				t.Fatal("the index still moves: Raft has moved on")
			}
		})
	}
	// An entry it reads is not a reason to stop, nor is a secret store refusal.
	f := newTestFSM(t, opPub)
	if res := applyAt(f, 1, Entry{Kind: KindFormat, SetFormat: Format}); res != nil || f.Stuck() != "" {
		t.Fatalf("current format: %v, stuck %q", res, f.Stuck())
	}
}

// The agreed format only rises, and a snapshot carries it: a replica that
// reads less refuses the snapshot rather than install state it cannot
// follow.
func TestSnapshotInANewerFormatIsRefused(t *testing.T) {
	_, opPub := operatorKey(t)
	f := newTestFSM(t, opPub)
	f.readable = Format + 1
	applyAt(f, 1, Entry{Kind: KindFormat, SetFormat: Format + 1})
	applyAt(f, 2, Entry{Kind: KindFormat, SetFormat: Format}) // never lowers
	if got := f.Core().format(); got != Format+1 {
		t.Fatalf("agreed format %d", got)
	}
	if err := restoreCopy(t, f, newTestFSM(t, opPub)); !errors.Is(err, ErrNewerFormat) {
		t.Fatalf("older replica installed a newer snapshot: %v", err)
	}
	same := newTestFSM(t, opPub)
	same.readable = Format + 1
	if err := restoreCopy(t, f, same); err != nil || same.Core().format() != Format+1 {
		t.Fatalf("same release: %v, format %d", err, same.Core().format())
	}
}

// A rollout: old and new replicas share the group in the old format; the
// format rises only once the last old replica is gone, and from then on a
// replica of the old release cannot join.
func TestFormatRisesOnlyWhenEveryMemberReadsIt(t *testing.T) {
	c := newCluster(t, 3)
	next := Format + 1
	c.reads["n0"], c.reads["n1"] = next, next
	c.genesis("n0", "n1", "n2")
	if _, err := c.nodes["n0"].sec.Put(t.Context(), "/before", []byte("v")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * testTiming.Tick)
	for _, r := range c.live() {
		if f := r.node.Core().format(); f != Format {
			t.Fatalf("%s: format %d with an old replica in the group", r.name, f)
		}
	}
	// Roll the old replica to the new release.
	c.stopReplica(c.nodes["n2"])
	c.reads["n2"] = next
	c.start("n2", "m1")
	c.settled(15 * time.Second)
	eventually(t, 10*time.Second, "format raised everywhere", func() bool {
		for _, r := range c.live() {
			if r.node.Core().format() != next {
				return false
			}
		}
		return true
	})
	for _, r := range c.live() {
		if st := r.node.Status(); !st.Serving || st.Stuck != "" {
			t.Fatalf("%s after the raise: %+v", r.name, st)
		}
		eventually(t, 3*time.Second, "secret on "+r.name, func() bool { v, _ := r.sec.Get(t.Context(), "/before"); return string(v) == "v" })
	}
	// A replica of the old release is refused and never serves.
	c.reads["n3"] = Format
	old := c.start("n3", "m1")
	time.Sleep(2 * time.Second)
	if st := old.node.Status(); st.Joined || st.Serving {
		t.Fatalf("old release joined after the raise: %+v", st)
	}
	l := c.leader()
	if l == nil {
		t.Fatal("no leader")
	}
	if st := l.node.Status(); len(st.Voters)+len(st.NonVoters) != 3 {
		t.Fatalf("membership changed: %+v", st)
	}
}
