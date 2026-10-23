package cdsha

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
)

func TestRecoveryLogStoreConfigurationAccounting(t *testing.T) {
	logs := raft.NewInmemStore()
	scratch := &FSM{}
	wrapped := recoveryLogStore{LogStore: logs, scratch: scratch}
	for i, kind := range []raft.LogType{raft.LogConfiguration, raft.LogCommand, raft.LogBarrier, raft.LogNoop} {
		entry := &raft.Log{Index: uint64(i + 1), Type: kind}
		if kind == raft.LogConfiguration {
			entry.Data = raft.EncodeConfiguration(raft.Configuration{})
		}
		if err := logs.StoreLog(entry); err != nil {
			t.Fatal(err)
		}
		var got raft.Log
		if err := wrapped.GetLog(entry.Index, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, *entry) || scratch.AppliedIndex() != 1 {
			t.Fatalf("kind %v: index %d", kind, scratch.AppliedIndex())
		}
	}
	var absent raft.Log
	if err := wrapped.GetLog(99, &absent); err == nil {
		t.Fatal("missing log accepted")
	}
	if scratch.AppliedIndex() != 1 {
		t.Fatal("failed read advanced state")
	}
}

// No Run loop or application no-op masks the final configuration entry.
// Direct authorized recovery isolates correctness; normal Run requires quorum loss.
func TestRecoveryConfigurationTailPreservesState(t *testing.T) {
	for _, barrier := range []bool{false, true} {
		t.Run(fmt.Sprintf("barrier=%v", barrier), func(t *testing.T) {
			key, pub := operatorKey(t)
			cfg := soloConfig(t, "n0", freeAddr(t), pub, newMemDecrees())
			n, err := NewNode(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := n.Start(); err != nil {
				t.Fatal(err)
			}
			defer n.shutdown()
			genesis := signDecree(t, key, Decree{Kind: Genesis, BootstrapNode: "n0"})
			n.bootstrap(context.Background(), PendingDecree{Name: "genesis", Decree: genesis})
			if !n.Core().Joined() {
				t.Fatal("genesis not applied")
			}
			at := time.Now().UnixMilli()
			if got, err := n.applyEntry(Entry{Kind: KindBinding, Binding: &sandboxledger.Command{SandboxID: "retained", Host: "acknowledged", AtMS: at}}); err != nil || got != true {
				t.Fatalf("binding: %v %v", got, err)
			}
			policy := n.Core().Policy
			// A legitimate local non-voter change is the last state-affecting log.
			if err := n.r().AddNonvoter("observer/1", raft.ServerAddress(freeAddr(t)+"#observer/1"), 0, time.Second).Error(); err != nil {
				t.Fatal(err)
			}
			configIndex := n.r().LastIndex()
			eventually(t, time.Second, "configuration applied", func() bool { return n.fsm.AppliedIndex() == configIndex })
			var configLog raft.Log
			if err := n.logs.GetLog(configIndex, &configLog); err != nil || configLog.Type != raft.LogConfiguration {
				t.Fatalf("configuration watermark: %v %+v", err, configLog)
			}
			if barrier {
				if err := n.r().Barrier(time.Second).Error(); err != nil {
					t.Fatal(err)
				}
			}
			old := n.r()
			if err := n.stopRaft(old); err != nil {
				t.Fatal(err)
			}
			sd := signDecree(t, key, Decree{Kind: Recover, BootstrapNode: "n0", BaseEpoch: n.Core().Epoch})
			n.recover(context.Background(), PendingDecree{Name: "recover", Decree: sd})
			if n.r() == old || n.Core().Epoch != 2 {
				t.Fatal("recovery did not replace generation and apply decree")
			}
			if got, ok := cfg.Ledger.Lookup("retained"); !ok || got != "acknowledged" {
				t.Fatalf("acknowledged state lost: %q %v", got, ok)
			}
			if n.Core().Policy != policy || n.fsm.AppliedIndex() < configIndex {
				t.Fatal("policy or state watermark regressed")
			}
			n.snaps.mu.RLock()
			body := bytes.Clone(n.snaps.body)
			meta := n.snaps.meta
			n.snaps.mu.RUnlock()
			sn, err := decodeSnapshot(bytes.NewReader(body), Format, false)
			if err != nil {
				t.Fatal(err)
			}
			if sn.Index != configIndex {
				t.Fatalf("recovery body %d, configuration %d", sn.Index, configIndex)
			}
			if barrier && meta.Index <= sn.Index {
				t.Fatal("barrier fixture did not retain separate Raft metadata index")
			}
			if !barrier && meta.Index != sn.Index {
				t.Fatal("configuration-only metadata differs")
			}
			if _, err := n.readBarrier(n.r(), time.Second); err != nil {
				t.Fatalf("recovered quorum: %v", err)
			}
		})
	}
}
