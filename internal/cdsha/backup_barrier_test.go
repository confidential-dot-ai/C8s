package cdsha

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// Raft barriers move the storage boundary, not the authenticated state floor.
func TestBackupBarrierStateIndex(t *testing.T) {
	key, pub := operatorKey(t)
	recovery, _ := operatorKey(t)
	ds := newMemDecrees()
	backups := &memBackups{}
	cfg := soloConfig(t, "n0", freeAddr(t), pub, ds)
	cfg.RecoveryKey, cfg.Backups = mustPKIX(t, &recovery.PublicKey), backups
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.shutdown()
	// No Run loop: only this test can request a backup or read barrier.
	decree := signDecree(t, key, Decree{Kind: Genesis, BootstrapNode: "n0"})
	n.bootstrap(context.Background(), PendingDecree{Name: "genesis", Decree: decree})
	if !n.Core().Joined() {
		t.Fatal("Genesis did not commit")
	}
	state := n.fsm.AppliedIndex()
	if n.Status().AppliedIndex != state {
		t.Fatal("status is not the state watermark")
	}
	if err := n.r().Barrier(time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	if n.r().LastIndex() <= state || n.fsm.AppliedIndex() != state {
		t.Fatal("barrier did not create state-neutral index gap")
	}
	n.maybeBackup(context.Background())
	b, ok := backups.get()
	if !ok {
		t.Fatal("production backup writer did not publish")
	}
	pin := certutil.CertFingerprint(n.Core().RootCert)
	if err := VerifyBackupSource(b, pin); err != nil {
		t.Fatal(err)
	}
	body, err := OpenBackup(recovery, b)
	if err != nil {
		t.Fatal(err)
	}
	sn, err := decodeSnapshot(bytes.NewReader(body), Format, true)
	if err != nil {
		t.Fatal(err)
	}
	metas, err := n.snaps.List()
	if err != nil || len(metas) == 0 {
		t.Fatalf("snapshot: %v", err)
	}
	t.Logf("indices: raft=%d snapshot=%d inner=%d outer=%d state=%d", n.r().LastIndex(), metas[0].Index, sn.Index, b.Meta.Index, state)
	if metas[0].Index <= sn.Index || sn.Index != state || b.Meta.Index != sn.Index {
		t.Fatal("backup conflated Raft and state watermarks")
	}
	if err := ValidateRecoverySnapshot(body, b.Meta, b.Meta.Epoch, state); err != nil {
		t.Fatal(err)
	}
	if ValidateRecoverySnapshot(body, b.Meta, b.Meta.Epoch, state+1) == nil {
		t.Fatal("barrier bypassed higher state floor")
	}
	bad := b
	bad.Meta.Index++
	if VerifyBackupSource(bad, pin) == nil {
		t.Fatal("modified signed index accepted")
	}
	if ValidateRecoverySnapshot(body, bad.Meta, 0, 0) == nil {
		t.Fatal("inner/outer index mismatch accepted")
	}
}
