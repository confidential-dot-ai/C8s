package protocol

import (
	"encoding/json"
	"testing"
)

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

func TestProtectedPhaseBoundary(t *testing.T) {
	for _, q := range []Request{
		{Operation: "custody-accept"},
		{Operation: "custody-accept", Custody: make(json.RawMessage, 8192)},
		{Operation: "custody-accept", Custody: json.RawMessage(`{}`), OperatorKey: []byte("key")},
		{Operation: "recovery-enroll", Custody: json.RawMessage(`{}`)},
		{Operation: "init", OperatorKey: []byte("key"), Custody: json.RawMessage(`{}`)},
	} {
		if q.Valid() {
			t.Fatalf("unsafe protected phase accepted: %s", q.Operation)
		}
	}
	if !(Request{Operation: "custody-accept", Custody: json.RawMessage(`{}`)}).Valid() {
		t.Fatal("bounded encrypted grant refused by framing")
	}
	for _, op := range []string{"custody-request", "recovery-enroll", "recovery-restore", "recovery-genesis", "recovery-checkpoint", "recovery-check", "recovery-refuse"} {
		if !(Request{Operation: op, Target: 2}).Valid() {
			t.Fatal(op)
		}
	}
}
