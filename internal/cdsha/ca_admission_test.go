package cdsha

import (
	"errors"
	"testing"
)

func TestCANotServingSentinel(t *testing.T) {
	al, sec, led := testStores(t)
	n, err := NewNode(Config{ClusterID: testCluster, NodeName: "n0", Bind: "127.0.0.1:0", Advertise: "127.0.0.1:1", Attestor: MockAttestor{"m1"},
		Seats: 3, Allowlist: al, Secrets: sec, Ledger: led})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := n.CA()
	if ca != nil || !errors.Is(err, ErrNotServing) {
		t.Fatalf("unjoined replica CA = %p, error = %v", ca, err)
	}
	if err.Error() != "cds-ha: replica is not serving (not joined, not pinned, or not fresh)" {
		t.Fatalf("changed admission message: %v", err)
	}
}
