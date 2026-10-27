package cdsha

import (
	"context"
	"testing"
)

// Invalid authorization must win over invalid snapshot encoding. This pins
// rejection precedence, rather than measuring runtime or decoder allocation.
func TestRestoreAuthorizationPrecedesInvalidEncoding(t *testing.T) {
	_, pub := operatorKey(t)
	cfg := soloConfig(t, "n0", freeAddr(t), pub, nil)
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.shutdown()
	other, _ := operatorKey(t)
	body := []byte("ordinary invalid snapshot")
	sd := signDecree(t, other, Decree{Kind: Restore, BootstrapNode: "n0", SnapshotSHA256: SnapshotSHA256(body)})
	want := VerifyDecreeSignature(sd, pub)
	if want == nil {
		t.Fatal("fixture must have invalid authorization")
	}
	beforeLog := n.r().LastIndex()
	_, err = n.Restore(context.Background(), sd, body)
	if err == nil || err.Error() != want.Error() {
		t.Fatalf("want signature rejection %q before decoding; got %v", want, err)
	}
	if n.member() || n.Core().Joined() || n.r().LastIndex() != beforeLog {
		t.Fatal("unauthorized restore changed membership or log")
	}
}
