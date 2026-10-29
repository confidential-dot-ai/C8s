package cdsha

import (
	"testing"
	"time"
)

// Spent operator tokens are part of the replicated state, so a Restore (back
// to the backup's spends) or a Recover (the survivor's) forgets the ones spent
// since. Tokens issued before such a start are refused (Core.GenesisAtMS):
// none could have been spent unseen after it.
func TestRestartMovesTheTokenFloor(t *testing.T) {
	genesisAt := time.Now().Add(-time.Hour).UnixMilli()
	x := newRestartFixture(t, genesisAt)
	if got := x.f.Core().GenesisAtMS; got != genesisAt {
		t.Fatalf("floor %d after Genesis at %d", got, genesisAt)
	}
	backup := x.backup()

	restoreAt := time.Now().UnixMilli()
	fresh := newTestFSM(t, x.pub)
	sd := signDecree(t, x.op, Decree{Kind: Restore, BootstrapNode: "n0", SnapshotSHA256: SnapshotSHA256(backup)})
	if res := applyAt(fresh, 1, Entry{Kind: KindRestore, Restore: &RestoreEntry{Decree: sd, AtMS: restoreAt, Snapshot: backup}}).(DecreeResult); res.Err != "" {
		t.Fatal(res.Err)
	}
	if got := fresh.Core().GenesisAtMS; got != restoreAt {
		t.Errorf("floor %d after a Restore at %d: tokens spent after the backup replay", got, restoreAt)
	}

	recoverAt := restoreAt + 1000
	rd := signDecree(t, x.op, Decree{Kind: Recover, BootstrapNode: "n0", BaseEpoch: x.f.Core().Epoch})
	x.apply(Entry{Kind: KindDecree, Decree: &DecreeEntry{Decree: rd, AtMS: recoverAt}})
	if got := x.f.Core().GenesisAtMS; got != recoverAt {
		t.Errorf("floor %d after a Recover at %d: tokens the lost replicas recorded replay", got, recoverAt)
	}
}
