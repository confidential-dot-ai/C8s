package cdsha

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Value rot regressions: one value of the leader's
// SQLite allowlist changes while the replica runs. Before, the leader kept
// serving it and shipped it through InstallSnapshot to a joiner and through
// the sealed backup to a restored cluster, while the followers that
// replayed the log held the right value.

func victimDigest(r *replica) string {
	al, _, err := r.al.LoadAll()
	if err != nil {
		return "err: " + err.Error()
	}
	w, ok := al.Workloads["victim"]
	if !ok || len(w.Containers) == 0 {
		return "absent"
	}
	return w.Containers[0].Digest.String()
}

// seedVictim writes the victim and enough entries that a joiner gets a
// snapshot rather than a log replay.
func seedVictim(t *testing.T, l *replica) string {
	t.Helper()
	if err := l.al.PutWorkload("victim", mkWorkload(t, 0)); err != nil {
		t.Fatal(err)
	}
	for i := range 300 {
		if err := l.al.PutWorkload(fmt.Sprintf("f%03d", i), mkWorkload(t, 1000+i)); err != nil {
			t.Fatal(err)
		}
	}
	return mkWorkload(t, 0).Containers[0].Digest.String() // sha256:0…01
}

// rotUnder changes the victim's digest in r's database file through a
// connection of its own: the store's hooks never see it, as with memory or
// disk corruption.
func rotUnder(t *testing.T, r *replica, good string) {
	t.Helper()
	raw, err := sql.Open("sqlite", r.alPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE workload_entry SET entry_json = replace(entry_json, '01"', '00"') WHERE name = 'victim'`); err != nil {
		t.Fatal(err)
	}
	if victimDigest(r) == good {
		t.Fatal("test setup: the served value did not change")
	}
}

// restoreFromBackup replaces every replica with a cluster restored from
// the stored backup and returns what each serves for the victim.
func restoreFromBackup(t *testing.T, c *cluster) []string {
	t.Helper()
	bk, _ := c.backups.get()
	snap, err := OpenBackup(c.recKey, bk)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range c.live() {
		c.stopReplica(r)
	}
	for _, n := range []string{"n0", "n1", "n2"} {
		c.start(n, "m1")
	}
	res, err := c.nodes["n1"].node.Restore(context.Background(), signDecree(t, c.opKey, Decree{Kind: Restore, BootstrapNode: "n1", TargetMember: c.nodes["n1"].node.ID(), SnapshotSHA256: SnapshotSHA256(snap)}), snap)
	if err != nil {
		t.Fatalf("restore: %v %+v", err, res)
	}
	c.settled(20 * time.Second)
	var out []string
	for _, r := range c.live() {
		out = append(out, victimDigest(r))
	}
	return out
}

// A leader whose stored value rotted stops at its next snapshot (the backup
// one) or checkpoint: it ships neither InstallSnapshot nor a backup of it, hands off, and
// the joiner, the backup and a cluster restored from it hold the good value.
func TestLeaderValueRotIsNotShipped(t *testing.T) {
	c := newCluster(t, 3)
	c.fileStores = true
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	good := seedVictim(t, l)
	rotUnder(t, l, good)
	rottedAt := time.Now()
	if err := l.al.PutWorkload("tick", mkWorkload(t, 5)); err != nil {
		t.Fatal(err)
	}
	// Whichever sees it first: the next snapshot (the local check), or the
	// next checkpoint (the leader's next write journals a document built
	// from the rotted row, which the followers' documents are not).
	eventually(t, 10*time.Second, "the rotted leader stopped", func() bool {
		s := l.node.fsm.Stuck()
		return strings.Contains(s, "no longer matches") || strings.Contains(s, ErrDiverged.Error())
	})
	t.Logf("leader stopped after %s: %.200s", time.Since(rottedAt).Round(time.Millisecond), l.node.fsm.Stuck())
	var nl *replica
	eventually(t, 10*time.Second, "a new leader", func() bool { nl = c.leader(); return nl != nil && nl != l })
	j := c.start("n3", "m1")
	eventually(t, 20*time.Second, "n3 joined and serves", j.node.Serving)
	if d := victimDigest(j); d != good {
		t.Fatalf("joiner serves %s, want %s", d, good)
	}
	if err := nl.al.PutWorkload("tock", mkWorkload(t, 6)); err != nil {
		t.Fatal(err)
	}
	want := nl.node.fsm.AppliedIndex()
	eventually(t, 10*time.Second, "a backup of the new leader's state", func() bool { b, ok := c.backups.get(); return ok && b.Meta.Index >= want })
	for _, d := range restoreFromBackup(t, c) {
		if d != good {
			t.Fatalf("restored cluster serves %s, want %s", d, good)
		}
	}
}

// A follower whose stored value rotted stops at its next snapshot and,
// restarted, holds the good value again.
func TestFollowerValueRotIsCaughtAtItsSnapshot(t *testing.T) {
	c := newCluster(t, 3)
	c.fileStores = true
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	good := seedVictim(t, l)
	f := followers(c)[0]
	eventually(t, 10*time.Second, "follower caught up", func() bool { return victimDigest(f) == good && f.node.fsm.AppliedIndex() >= l.node.fsm.AppliedIndex() })
	rotUnder(t, f, good)
	if err := f.node.r().Snapshot().Error(); err == nil {
		t.Fatal("the rotted follower's snapshot succeeded")
	}
	if !strings.Contains(f.node.fsm.Stuck(), "no longer matches") || f.node.Serving() {
		t.Fatalf("rotted follower not stopped: %q serving=%v", f.node.fsm.Stuck(), f.node.Serving())
	}
	c.stopReplica(f)
	again := c.start(f.name, "m1")
	eventually(t, 20*time.Second, "restarted follower serves", again.node.Serving)
	if d := victimDigest(again); d != good {
		t.Fatalf("restarted follower serves %s, want %s", d, good)
	}
}

// The leader's allowlist is replaced by an image with one value bit flipped
// (allowlist.Store.Restore, whose PRAGMA quick_check passes). Its own
// digests then agree with what it holds, so its snapshot is not refused; the
// two followers outvote it at the next checkpoint. It stops, and every
// replica that serves, the backup and a cluster restored from it hold the
// good value.
func TestLeaderValueRotIsOutvoted(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	good := seedVictim(t, l)
	img, err := l.al.Dump()
	if err != nil {
		t.Fatal(err)
	}
	pat := []byte(`victim{"initContainers"`)
	for o := 0; victimDigest(l) == good; {
		p := bytes.Index(img[o:], pat)
		if p < 0 {
			t.Fatal("no candidate row changed the served value")
		}
		row := o + p
		o = row + 1
		at := row + bytes.Index(img[row:], []byte(good[len(good)-8:])) + 7
		cp := bytes.Clone(img)
		cp[at] ^= 0x01
		if err := l.al.Restore(cp); err != nil {
			t.Fatalf("rotted image refused by Restore: %v", err)
		}
	}
	rottedAt := time.Now()
	if err := l.node.r().Snapshot().Error(); err != nil {
		t.Logf("leader snapshot after the rot: %v", err)
	}
	j := c.start("n3", "m1")
	if err := l.al.PutWorkload("tick", mkWorkload(t, 5)); err != nil {
		t.Logf("write after the rot: %v", err)
	}
	eventually(t, 15*time.Second, "the rotted leader stopped", func() bool { return strings.Contains(l.node.fsm.Stuck(), ErrDiverged.Error()) })
	t.Logf("leader outvoted after %s", time.Since(rottedAt).Round(time.Millisecond))
	var nl *replica
	eventually(t, 10*time.Second, "a new leader", func() bool { nl = c.leader(); return nl != nil && nl != l })
	// The joiner may have taken the rotted state from the old leader; then
	// the new leader's majority stops it too.
	eventually(t, 20*time.Second, "every serving replica holds the good value", func() bool {
		for _, r := range c.live() {
			if r.node.Serving() && victimDigest(r) != good {
				return false
			}
		}
		return true
	})
	// Wait until a checkpoint of the new leader judged the joiner: it either
	// stopped, or serves holding the leader's latest checkpoint.
	eventually(t, 20*time.Second, "the joiner judged", func() bool {
		if j.node.fsm.Stuck() != "" {
			return true
		}
		st, lst := j.node.Status(), nl.node.Status()
		return j.node.Serving() && st.Checkpoint != nil && lst.Checkpoint != nil && *st.Checkpoint == *lst.Checkpoint
	})
	if j.node.fsm.Stuck() != "" {
		t.Logf("joiner stopped: %.120s", j.node.fsm.Stuck())
		c.stopReplica(j)
		j = c.start("n3", "m1")
		eventually(t, 20*time.Second, "joiner serves", j.node.Serving)
	}
	if d := victimDigest(j); d != good {
		t.Fatalf("joiner serves %s, want %s", d, good)
	}
	if err := nl.al.PutWorkload("tock", mkWorkload(t, 6)); err != nil {
		t.Fatal(err)
	}
	want := nl.node.fsm.AppliedIndex()
	eventually(t, 10*time.Second, "a backup of the new leader's state", func() bool { b, ok := c.backups.get(); return ok && b.Meta.Index >= want })
	for _, d := range restoreFromBackup(t, c) {
		if d != good {
			t.Fatalf("restored cluster serves %s, want %s", d, good)
		}
	}
}
