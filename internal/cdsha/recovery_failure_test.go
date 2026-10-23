package cdsha

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/hashicorp/raft"
)

func TestRecoveryFatalReplayDoesNotRestart(t *testing.T) {
	for _, fatal := range []bool{false, true} {
		name := "ordinary refusal"
		if fatal {
			name = "fatal unknown command"
		}
		t.Run(name, func(t *testing.T) {
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
			n.recover(context.Background(), PendingDecree{Name: "recover-test", Decree: decree})
			if fatal {
				if n.r() != old || n.r().State() != raft.Shutdown || n.Serving() {
					t.Fatal("fatal partial replay restarted")
				}
			} else {
				if n.r() == old || n.r().State() != raft.Leader {
					t.Fatal("ordinary refusal stopped valid recovery")
				}
				if got, ok := cfg.Ledger.Lookup("s"); !ok || got != "original" {
					t.Fatalf("refused replay changed binding: %q %v", got, ok)
				}
			}
		})
	}
}
