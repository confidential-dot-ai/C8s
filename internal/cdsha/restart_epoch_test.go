package cdsha

import (
	"strings"
	"testing"
	"time"
)

// Nodes order pin decrees by base_epoch, so the epoch must not go back when
// the cluster starts again: a Restore of an older backup, or a Recover on a
// survivor that missed decrees, resumes after the epoch the operator signs
// (resume_epoch), the highest the operator knows the cluster reached.
func TestRestartResumesAfterTheSignedEpoch(t *testing.T) {
	x := newRestartFixture(t, time.Now().UnixMilli())
	x.write(1)
	for range 2 { // epoch 3, so a resume_epoch below it is not 0 (none given)
		sd := signDecree(t, x.op, Decree{Kind: SetVoters, BaseEpoch: x.f.Core().Epoch, Voters: 3})
		x.apply(Entry{Kind: KindDecree, Decree: &DecreeEntry{Decree: sd, AtMS: time.Now().UnixMilli()}})
	}
	backup := x.backup()
	be := x.f.Core().Epoch
	backupMeta := BackupMeta{ClusterID: testCluster, Epoch: be, Index: x.index, AppliedDecrees: x.f.Core().AppliedDecrees, EpochFrom: x.f.Core().EpochFrom}

	restore := func(resume uint64) (*FSM, DecreeResult) {
		t.Helper()
		fresh := newTestFSM(t, x.pub)
		sd := signDecree(t, x.op, Decree{Kind: Restore, BootstrapNode: "n0", ResumeEpoch: resume, SnapshotSHA256: SnapshotSHA256(backup)})
		return fresh, applyAt(fresh, 1, Entry{Kind: KindRestore, Restore: &RestoreEntry{Decree: sd, AtMS: time.Now().UnixMilli(), Snapshot: backup}}).(DecreeResult)
	}
	// The lost cluster applied 4 decrees after the backup.
	fresh, res := restore(be + 4)
	c := fresh.Core()
	if res.Err != "" || res.Epoch != be+5 || c.Epoch != be+5 {
		t.Fatalf("restore resuming after %d: %+v, epoch %d", be+4, res, c.Epoch)
	}
	if uint64(len(c.AppliedDecrees)) != c.Epoch || uint64(len(c.EpochFrom)) != c.Epoch {
		t.Fatalf("epoch %d with %d decrees and %d origins", c.Epoch, len(c.AppliedDecrees), len(c.EpochFrom))
	}
	after := BackupMeta{ClusterID: testCluster, Epoch: c.Epoch, Index: 1, AppliedDecrees: c.AppliedDecrees, EpochFrom: c.EpochFrom}
	if !after.Follows(backupMeta) {
		t.Fatal("the restored cluster's backup does not follow the one it restored")
	}
	// The next decree is signed at the resumed epoch and applies there.
	next := signDecree(t, x.op, Decree{Kind: SetVoters, BaseEpoch: be + 5, Voters: 3})
	if r := applyAt(fresh, 2, Entry{Kind: KindDecree, Decree: &DecreeEntry{Decree: next, AtMS: time.Now().UnixMilli()}}).(DecreeResult); r.Err != "" || r.Epoch != be+6 {
		t.Fatalf("decree after the resumed epoch: %+v", r)
	}
	// Resuming after the backup's own epoch, or naming none, is +1.
	for _, resume := range []uint64{be, 0} {
		if _, res := restore(resume); res.Err != "" || res.Epoch != be+1 {
			t.Fatalf("restore resuming after %d: %+v", resume, res)
		}
	}
	for name, resume := range map[string]uint64{
		"below the backup": be - 1,
		"too far ahead":    be + maxResumeGap + 1,
	} {
		if _, res := restore(resume); !strings.Contains(res.Err, "resume_epoch") {
			t.Errorf("restore with resume_epoch %s (%d): %+v", name, resume, res)
		}
	}

	// Recover on the survivor x resumes the same way.
	cur := x.f.Core().Epoch
	bad := signDecree(t, x.op, Decree{Kind: Recover, BootstrapNode: "n0", BaseEpoch: cur, ResumeEpoch: cur - 1})
	x.index++
	if r := applyAt(x.f, x.index, Entry{Kind: KindDecree, Decree: &DecreeEntry{Decree: bad, AtMS: time.Now().UnixMilli()}}).(DecreeResult); !strings.Contains(r.Err, "resume_epoch") {
		t.Fatalf("Recover resuming below the survivor's epoch: %+v", r)
	}
	rd := signDecree(t, x.op, Decree{Kind: Recover, BootstrapNode: "n0", BaseEpoch: cur, ResumeEpoch: cur + 2})
	if r := x.apply(Entry{Kind: KindDecree, Decree: &DecreeEntry{Decree: rd, AtMS: time.Now().UnixMilli()}}).(DecreeResult); r.Epoch != cur+3 {
		t.Fatalf("Recover resuming after %d: %+v", cur+2, r)
	}
	if c := x.f.Core(); uint64(len(c.AppliedDecrees)) != c.Epoch || uint64(len(c.EpochFrom)) != c.Epoch || c.AppliedDecrees[c.Epoch-1] != rd.Decree.IntentID {
		t.Fatalf("after Recover: %+v", c)
	}
}

// Only Restore and Recover resume; every other kind refuses the field.
func TestResumeEpochOnlyOnRestarts(t *testing.T) {
	op, pub := operatorKey(t)
	keyed := Core{ClusterID: testCluster, OperatorPubKey: pub, Epoch: 3, RootCert: []byte{1}}
	for _, d := range []Decree{
		{Kind: UpdateMeasurements, BaseEpoch: 3, Measurements: []string{"m1"}, ResumeEpoch: 5},
		{Kind: SetVoters, BaseEpoch: 3, Voters: 3, ResumeEpoch: 5},
		{Kind: RotateKey, BaseEpoch: 3, ResumeEpoch: 5},
	} {
		if err := CheckDecree(signDecree(t, op, d), keyed, time.Now()); err == nil || !strings.Contains(err.Error(), "resume_epoch") {
			t.Errorf("%s with resume_epoch: %v", d.Kind, err)
		}
	}
	bare := PreGenesis(testCluster, pub)
	if err := CheckDecree(signDecree(t, op, Decree{Kind: Genesis, BootstrapNode: "n0", ResumeEpoch: 5}), bare, time.Now()); err == nil || !strings.Contains(err.Error(), "resume_epoch") {
		t.Errorf("Genesis with resume_epoch: %v", err)
	}
	if err := CheckDecree(signDecree(t, op, Decree{Kind: Recover, BootstrapNode: "n0", BaseEpoch: 3, ResumeEpoch: 9}), keyed, time.Now()); err != nil {
		t.Errorf("Recover with resume_epoch: %v", err)
	}
	// The leader refuses a Recover that would move the epoch back before it
	// commits it.
	for _, resume := range []uint64{2, 3 + maxResumeGap + 1} {
		if err := CheckDecree(signDecree(t, op, Decree{Kind: Recover, BootstrapNode: "n0", BaseEpoch: 3, ResumeEpoch: resume}), keyed, time.Now()); err == nil || !strings.Contains(err.Error(), "resume_epoch") {
			t.Errorf("Recover with resume_epoch %d at epoch 3: %v", resume, err)
		}
	}
}
