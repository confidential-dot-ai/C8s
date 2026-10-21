package cdsha

import (
	"errors"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// A write that does not commit (here: a replica that has not joined) is
// reported as unavailable to both stores, so their handlers answer 503.
func TestReplicateFailureIsUnavailable(t *testing.T) {
	al, sec, led := testStores(t)
	n, err := NewNode(Config{ClusterID: testCluster, NodeName: "n0", Bind: "127.0.0.1:0", Advertise: "127.0.0.1:1", Attestor: testAttestor{"m1"},
		Seats: 3, Allowlist: al, Secrets: sec, Ledger: led})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Replicate(allowlist.Command{Op: allowlist.OpConsumeToken, Token: "t"}); !errors.Is(err, allowlist.ErrUnavailable) {
		t.Errorf("allowlist: %v", err)
	}
	if _, err := n.ReplicateSecret(secrets.Command{Op: secrets.OpPut, Path: "/p", Value: []byte("v")}); !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("secrets: %v", err)
	}
}
