package cdsha

import (
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"reflect"
	"testing"
	"time"
)

func TestRecoveryReplayPreservesPolicy(t *testing.T) {
	for _, ttl := range []time.Duration{24 * time.Hour, 7 * time.Hour} {
		t.Run(ttl.String(), func(t *testing.T) {
			al, err := allowlist.OpenInMemory()
			if err != nil {
				t.Fatal(err)
			}
			defer al.Close()
			replayAL, err := allowlist.OpenInMemory()
			if err != nil {
				t.Fatal(err)
			}
			defer replayAL.Close()
			led := sandboxledger.New(ttl, 2)
			sec := secrets.NewMemoryStore(3, 1, 4)
			n := &Node{cfg: Config{ClusterID: testCluster, Ledger: led, Secrets: sec}}
			live := NewFSM(PreGenesis(testCluster, nil), &al, sec, led)
			live.core.Policy = live.LocalPolicy()
			n.fsm = live
			scratch := n.recoveryFSM(&replayAL)
			if scratch.readable != live.readable {
				t.Fatal("recovery changed readable format")
			}
			scratch.core.Policy = live.Core().Policy
			at := int64(1700000000000)
			entries := []Entry{
				{Kind: KindBinding, Binding: &sandboxledger.Command{SandboxID: "s", Host: "original", AtMS: at}},
				{Kind: KindBinding, Binding: &sandboxledger.Command{SandboxID: "s", Host: "other", AtMS: at + 2*time.Hour.Milliseconds()}},
				{Kind: KindBinding, Binding: &sandboxledger.Command{SandboxID: "s2", Host: "original", AtMS: at}},
				{Kind: KindBinding, Binding: &sandboxledger.Command{SandboxID: "s3", Host: "original", AtMS: at}},
				{Kind: KindSecret, Secret: &secrets.Command{Op: secrets.OpPutIfAbsent, Path: "/1", Value: []byte("v"), Origin: secrets.OriginWorkload, Name: "w"}},
				{Kind: KindSecret, Secret: &secrets.Command{Op: secrets.OpPutIfAbsent, Path: "/2", Value: []byte("v"), Origin: secrets.OriginWorkload, Name: "w"}},
				{Kind: KindSecret, Secret: &secrets.Command{Op: secrets.OpPut, Path: "/big", Value: []byte("large")}},
				{Kind: KindSecret, Secret: &secrets.Command{Op: secrets.OpPut, Path: "/3", Value: []byte("v")}},
				{Kind: KindSecret, Secret: &secrets.Command{Op: secrets.OpPut, Path: "/4", Value: []byte("v")}},
				{Kind: KindSecret, Secret: &secrets.Command{Op: secrets.OpPut, Path: "/5", Value: []byte("v")}},
			}
			for i, e := range entries {
				a, b := applyAt(live, uint64(i+1), e), applyAt(scratch, uint64(i+1), e)
				if !reflect.DeepEqual(a, b) {
					t.Fatalf("command %d: live=%+v replay=%+v", i, a, b)
				}
			}
			if got := led.Dump()[0].ExpiresMS; got != at+ttl.Milliseconds() {
				t.Fatalf("expiry %d", got)
			}
			if err := restoreCopy(t, scratch, live); err != nil {
				t.Fatal(err)
			}
			if got := led.Dump(); len(got) != 2 {
				t.Fatalf("recovery bindings %+v", got)
			}
		})
	}
}
