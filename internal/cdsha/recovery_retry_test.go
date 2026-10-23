package cdsha

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
)

func TestRecoveryFatalReplayRetryDoesNotRestart(t *testing.T) {
	for _, tc := range []struct {
		name         string
		fatal, prior bool
	}{
		{"ordinary refusal", false, true},
		{"fatal with prior snapshot", true, true},
		{"fatal without prior snapshot", true, false},
	} {
		fatal := tc.fatal
		t.Run(tc.name, func(t *testing.T) {
			key, pub := operatorKey(t)
			ds := newMemDecrees()
			cfg := soloConfig(t, "n0", freeAddr(t), pub, ds)
			n, err := NewNode(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := n.Start(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); _ = n.Run(ctx) }()
			t.Cleanup(func() { cancel(); <-done; n.shutdown() })
			ds.put(signDecree(t, key, Decree{Kind: Genesis, BootstrapNode: "n0"}))
			eventually(t, 5*time.Second, "Genesis", n.Serving)
			at := time.Now().UnixMilli()
			if got, err := n.applyEntry(Entry{Kind: KindBinding, Binding: &sandboxledger.Command{SandboxID: "s", Host: "original", AtMS: at}}); err != nil || got != true {
				t.Fatalf("binding: %v %v", got, err)
			}
			if tc.prior {
				if err := n.r().Snapshot().Error(); err != nil {
					t.Fatal(err)
				}
			}
			if n.fsm.Stuck() != "" {
				t.Fatal("live FSM already stuck")
			}
			cancel()
			<-done
			old := n.r()
			index, err := n.logs.LastIndex()
			if err != nil {
				t.Fatal(err)
			}
			entry := Entry{Kind: KindBinding, Binding: &sandboxledger.Command{SandboxID: "s", Host: "conflict", AtMS: at + 1}}
			if fatal {
				entry = Entry{Kind: "unknown-replay-command"}
			}
			raw, err := json.Marshal(entry)
			if err != nil {
				t.Fatal(err)
			}
			if err := n.logs.StoreLog(&raft.Log{Index: index + 1, Term: old.CurrentTerm(), Type: raft.LogCommand, Data: raw}); err != nil {
				t.Fatal(err)
			}
			decree := signDecree(t, key, Decree{Kind: Recover, BootstrapNode: "n0", BaseEpoch: n.Core().Epoch})
			n.snaps.mu.RLock()
			priorExists, priorID, priorDigest := n.snaps.exists, n.snaps.meta.ID, SnapshotSHA256(n.snaps.body)
			n.snaps.mu.RUnlock()
			if priorExists != tc.prior {
				t.Fatalf("prior snapshot fixture: got %v want %v", priorExists, tc.prior)
			}
			first, err := n.logs.FirstIndex()
			if err != nil {
				t.Fatal(err)
			}
			priorLogs := make(map[uint64]raft.Log)
			for i := first; i <= index+1; i++ {
				var log raft.Log
				if err := n.logs.GetLog(i, &log); err != nil {
					t.Fatal(err)
				}
				priorLogs[i] = log
			}
			assertPreserved := func() {
				t.Helper()
				for i, want := range priorLogs {
					var got raft.Log
					if err := n.logs.GetLog(i, &got); err != nil || !reflect.DeepEqual(got, want) {
						t.Errorf("fatal recovery changed log %d: %v", i, err)
					}
				}
				n.snaps.mu.RLock()
				same := n.snaps.exists == priorExists && n.snaps.meta.ID == priorID && SnapshotSHA256(n.snaps.body) == priorDigest
				n.snaps.mu.RUnlock()
				if !same {
					t.Error("fatal recovery replaced prior snapshot")
				}
			}
			n.recover(context.Background(), PendingDecree{Name: "recover-test", Decree: decree})
			if fatal {
				// Regression: the first call must not launder the unreadable tail
				// into a snapshot that a second call silently accepts.
				assertPreserved()
				n.recover(context.Background(), PendingDecree{Name: "recover-test", Decree: decree})
				if n.r() != old || n.r().State() != raft.Shutdown || n.Serving() {
					t.Fatal("fatal partial replay restarted")
				}
				assertPreserved()
			} else {
				if n.r() == old || n.r().State() != raft.Leader {
					t.Fatal("ordinary refusal stopped valid recovery")
				}
				cert, err := n.confirmRead(time.Second)
				if err != nil || !n.validReadCertificate(cert) {
					t.Fatalf("new recovery instance cannot confirm reads: %v", err)
				}
				if _, err := n.readBarrier(old, time.Second); err == nil {
					t.Fatal("old recovered instance admitted read")
				}
				if got, ok := cfg.Ledger.Lookup("s"); !ok || got != "original" {
					t.Fatalf("refused replay changed binding: %q %v", got, ok)
				}
				current := n.r()
				// A stale stop must neither clear fresh-generation admission nor
				// overwrite its stopping marker after that generation shuts down.
				n.readCert.Store(cert)
				if err := n.stopRaft(old); err != nil {
					t.Fatal(err)
				}
				if n.readCert.Load() != cert || !n.validReadCertificate(cert) {
					t.Fatal("stale stop cleared current freshness")
				}
				if err := n.stopRaft(current); err != nil {
					t.Fatal(err)
				}
				if err := n.stopRaft(old); err != nil {
					t.Fatal(err)
				}
				n.readCert.Store(cert)
				if n.stoppingReads.Load() != current || n.validReadCertificate(cert) || n.Serving() {
					t.Fatal("stale stop reopened current generation")
				}
			}
		})
	}
}
