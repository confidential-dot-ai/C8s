package cdsha

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// BenchmarkStateDigest measures, at allowlist states of about 1, 100 and
// 190 MiB: the checkpoint Apply (what every replica does on the FSM
// goroutine, O(1)), the snapshot capture Raft already did before (Dump, on
// the FSM goroutine), and the added full recompute Persist runs off it.
//
//	go test -run XXX -bench BenchmarkStateDigest -benchtime 5x -timeout 30m .
func BenchmarkStateDigest(b *testing.B) {
	for _, mib := range []int{1, 100, 190} {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		al, err := allowlist.OpenInMemory()
		if err != nil {
			b.Fatal(err)
		}
		f := newBenchFSM(&al, pub)
		// A document of about 1 MiB (7000 workloads), then one changed
		// workload per write: each write journals another 1 MiB document.
		ws := map[string]pkgallowlist.Workload{}
		for i := range 7000 {
			ws[fmt.Sprintf("w%05d", i)] = benchWL(i)
		}
		idx := uint64(1)
		applyAt(f, idx, Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpSeed, Workloads: ws}})
		for i := 0; ; i++ {
			live, _ := al.LiveBytes()
			if live >= int64(mib)<<20 {
				b.Logf("state: %d MiB live, %d writes", live>>20, i)
				break
			}
			idx++
			w := benchWL(10000 + i)
			applyAt(f, idx, Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpPutWorkload, Name: fmt.Sprintf("w%05d", i%7000), Workload: &w}})
		}
		b.Run(fmt.Sprintf("MiB=%d/checkpoint-apply", mib), func(b *testing.B) {
			for b.Loop() {
				idx++
				applyAt(f, idx, Entry{Kind: KindCheckpoint})
			}
		})
		var image []byte
		b.Run(fmt.Sprintf("MiB=%d/snapshot-capture", mib), func(b *testing.B) {
			for b.Loop() {
				s, err := f.Snapshot()
				if err != nil {
					b.Fatal(err)
				}
				image = s.(*fsmSnapshot).sn.Allowlist
			}
		})
		b.Run(fmt.Sprintf("MiB=%d/persist-recompute", mib), func(b *testing.B) {
			for b.Loop() {
				if _, err := allowlist.ImageDigest(image); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("MiB=%d/persist-total", mib), func(b *testing.B) {
			s, err := f.Snapshot()
			if err != nil {
				b.Fatal(err)
			}
			for b.Loop() {
				var buf bytes.Buffer
				if err := s.Persist(&memSink{Buffer: &buf}); err != nil {
					b.Fatal(err)
				}
			}
		})
		al.Close()
	}
}

func newBenchFSM(al *allowlist.Store, pub []byte) *FSM {
	f := NewFSM(PreGenesis(testCluster, pub), al, secrets.NewMemoryStore(8, 4, 64), sandboxledger.New(time.Hour, 8))
	f.core.Policy = f.LocalPolicy()
	return f
}

func benchWL(i int) pkgallowlist.Workload {
	d, _ := types.ParseDigest(fmt.Sprintf("sha256:%064x", i+1))
	return pkgallowlist.Workload{Containers: []pkgallowlist.Container{{Digest: d}}}
}
