package cdsha

import (
	"testing"
	"time"
)

// A cluster that starts again starts no earlier than the operator signed the
// start decree (issued_at_ms), whatever clock the replica that applies it
// has. With that replica's clock an hour before the backup, the token floor
// and the allowlist version still pass every token spent and every version
// served before the loss.
func TestRestartFloorsFollowTheSignedIssueTime(t *testing.T) {
	x := newRestartFixture(t, time.Now().Add(-30*time.Minute).UnixMilli()) // started after the replica's clock below
	x.write(2)
	backup := x.backup()
	backupAt := time.Now()
	x.write(3) // served after the backup, then lost
	served := version(t, x.f)
	issued := time.Now().Add(time.Second).UnixMilli() // the operator signs after the loss
	behind := backupAt.Add(-time.Hour).UnixMilli()    // the restoring replica's clock

	fresh := newTestFSM(t, x.pub)
	sd := signDecree(t, x.op, Decree{Kind: Restore, BootstrapNode: "n0", SnapshotSHA256: SnapshotSHA256(backup), IssuedAtMS: issued})
	if res := applyAt(fresh, 1, Entry{Kind: KindRestore, Restore: &RestoreEntry{Decree: sd, AtMS: behind, Snapshot: backup}}).(DecreeResult); res.Err != "" {
		t.Fatal(res.Err)
	}
	if got := fresh.Core().GenesisAtMS; got < issued {
		t.Errorf("Restore: token floor %d is before the signed issue time %d: tokens spent after the backup replay", got, issued)
	}
	if v := version(t, fresh); v <= served || v < uint64(issued) {
		t.Errorf("Restore: version %d, served before the loss %d, issued %d: nodes ignore later writes", v, served, issued)
	}

	before := version(t, x.f)
	rd := signDecree(t, x.op, Decree{Kind: Recover, BootstrapNode: "n0", BaseEpoch: x.f.Core().Epoch, IssuedAtMS: issued})
	x.apply(Entry{Kind: KindDecree, Decree: &DecreeEntry{Decree: rd, AtMS: behind}})
	if got := x.f.Core().GenesisAtMS; got < issued {
		t.Errorf("Recover: token floor %d is before the signed issue time %d", got, issued)
	}
	if v := version(t, x.f); v <= before || v < uint64(issued) {
		t.Errorf("Recover: version %d (before %d), issued %d", v, before, issued)
	}

	g := newTestFSM(t, x.pub)
	ca := mustCA(t)
	key := mustPKCS8(t, ca)
	gd := signDecree(t, x.op, Decree{Kind: Genesis, BootstrapNode: "n0", GenesisCA: caFP(ca), IssuedAtMS: issued})
	if res := applyAt(g, 1, Entry{Kind: KindDecree, Decree: &DecreeEntry{Policy: g.LocalPolicy(), Decree: gd, AtMS: behind, Pins: []string{"m1"}, RootCert: ca.Cert.Raw, Key: key}}).(DecreeResult); res.Err != "" {
		t.Fatal(res.Err)
	}
	if got := g.Core().GenesisAtMS; got < issued {
		t.Errorf("Genesis: token floor %d is before the signed issue time %d", got, issued)
	}
	if v := version(t, g); v < uint64(issued) {
		t.Errorf("Genesis: version %d below the signed issue time %d", v, issued)
	}
}

// A start decree carries its issue time, and only start decrees do; a
// Genesis names its CA.
func TestIssuedAtOnlyOnStartDecrees(t *testing.T) {
	op, pub := operatorKey(t)
	pre := PreGenesis(testCluster, pub)
	unsigned := signDecree(t, op, Decree{Kind: Genesis, BootstrapNode: "n0"})
	unsigned.Decree.IssuedAtMS = 0
	if s, err := SignDecree(unsigned.Decree, op); err != nil {
		t.Fatal(err)
	} else if err := CheckDecree(s, pre, time.Now()); err == nil {
		t.Error("a Genesis decree without issued_at_ms applied")
	}
	noCA := signDecree(t, op, Decree{Kind: Genesis, BootstrapNode: "n0"})
	noCA.Decree.GenesisCA = ""
	if s, err := SignDecree(noCA.Decree, op); err != nil {
		t.Fatal(err)
	} else if err := CheckDecree(s, pre, time.Now()); err == nil {
		t.Error("a Genesis decree without genesis_ca applied")
	}
	joined := pre
	joined.RootCert = []byte{1}
	if err := CheckDecree(signDecree(t, op, Decree{Kind: SetVoters, Voters: 3, IssuedAtMS: 1}), joined, time.Now()); err == nil {
		t.Error("a SetVoters decree with issued_at_ms applied")
	}
}

// A start decree is not issued after it expires: an operator clock far ahead
// would otherwise set a start time that refuses every operator token until
// then.
func TestIssuedAtNotAfterExpiry(t *testing.T) {
	op, pub := operatorKey(t)
	pre := PreGenesis(testCluster, pub)
	now := time.Now()
	ahead := signDecree(t, op, Decree{Kind: Genesis, BootstrapNode: "n0", ExpiresAt: now.Add(10 * time.Minute), IssuedAtMS: now.Add(365 * 24 * time.Hour).UnixMilli()})
	if err := CheckDecree(ahead, pre, now); err == nil {
		t.Error("a Genesis decree issued a year after it expires applied")
	}
	ok := signDecree(t, op, Decree{Kind: Genesis, BootstrapNode: "n0", ExpiresAt: now.Add(10 * time.Minute), IssuedAtMS: now.UnixMilli()})
	if err := CheckDecree(ok, pre, now); err != nil {
		t.Errorf("a Genesis decree issued now: %v", err)
	}
}
