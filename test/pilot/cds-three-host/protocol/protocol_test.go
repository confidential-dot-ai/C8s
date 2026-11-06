package protocol

import "testing"

func TestFixedPhaseBoundary(t *testing.T) {
	for _, q := range []Request{{Operation: "exec"}, {Operation: "seed", Target: 3}, {Operation: "seed", OperatorKey: []byte("key")}, {Operation: "init"}, {Operation: "init", OperatorKey: make([]byte, 4096)}} {
		if q.Valid() {
			t.Fatalf("unsafe phase accepted: %s", q.Operation)
		}
	}
	for _, op := range []string{"status", "provision", "seed", "attach", "burst", "prepare", "refuse", "survive", "heal", "revoke", "revoked", "overlap", "admit", "retire", "roll-safe"} {
		if !(Request{Operation: op, Target: 2}).Valid() {
			t.Fatalf("fixed phase refused: %s", op)
		}
	}
}
