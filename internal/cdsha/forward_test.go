package cdsha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
)

// refusingStore refuses every PutEntry after the first allow ones.
type refusingStore struct {
	Store
	allow, puts atomic.Int64
}

func (r *refusingStore) PutEntry(ctx context.Context, h cdschain.Hash, data []byte) error {
	if r.puts.Add(1) > r.allow.Load() {
		return errors.New("403: exceeded quota")
	}
	return r.Store.PutEntry(ctx, h, data)
}

func (s *set) chainOf(slot int) []cdschain.Entry {
	n := s.node(slot)
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]cdschain.Entry(nil), n.chain...)
}

// A re-seed of a Kubernetes store that still holds most entries creates
// only the missing ones and the head: admission charges every create, a
// refused one too, against any quota.
func TestKubeReseedCreatesOnlyMissingEntries(t *testing.T) {
	ctx := context.Background()
	s := newSet(t, 1)
	s.bootstrap()
	for range 4 {
		s.write(0)
	}
	client := fake.NewClientset()
	var creates atomic.Int64
	client.PrependReactor("create", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		creates.Add(1)
		return false, nil, nil
	})
	kube := &Kube{ConfigMaps: client.CoreV1().ConfigMaps("c8s-cds"), Cluster: "lane"}
	chain := s.chainOf(0)
	for _, e := range chain[:len(chain)-2] {
		data, _ := e.Encode()
		if err := kube.PutEntry(ctx, e.Hash(), data); err != nil {
			t.Fatal(err)
		}
		if err := kube.PutEntry(ctx, e.Hash(), data); err != nil {
			t.Fatal(err)
		}
	}
	if got := creates.Load(); got != int64(len(chain)-2) {
		t.Fatalf("%d creates for %d entries, each put twice", got, len(chain)-2)
	}
	creates.Store(0)
	s.node(0).setStore(kube)
	want, _ := json.Marshal(s.node(0).State().Head)
	s.waitFor("the store written forward", func() bool { raw, _ := kube.GetHead(ctx); return bytes.Equal(raw, want) })
	if got := creates.Load(); got != 3 {
		t.Fatalf("%d creates, want the 2 missing entries and the head", got)
	}
}

// A store that refuses writes is written forward again only after a
// backoff, not on every read, and once it takes writes the replica catches
// it up.
func TestWriteForwardBacksOff(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	s.write(0)
	st := &refusingStore{Store: NewMemory()}
	s.node(0).setStore(st)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, _ = s.serves(0)
		time.Sleep(T / 10)
	}
	// Without a backoff: one attempt per gossip tick (T/2) and per read.
	if got := st.puts.Load(); got > 6 {
		t.Fatalf("%d puts refused in 2 s", got)
	}
	st.allow.Store(1 << 30)
	s.waitFor("the store written forward", func() bool { raw, _ := st.GetHead(context.Background()); return raw != nil })
}

// A write-forward cut short keeps what it wrote: the store's head moves
// after every full batch, to an entry whose whole chain the store holds.
func TestForwardKeepsFullBatches(t *testing.T) {
	ctx := context.Background()
	entries := make([]cdschain.Entry, 2*forwardBatch+forwardBatch/2)
	for i := range entries {
		entries[i] = cdschain.Entry{Body: []byte(strconv.Itoa(i))}
	}
	last := len(entries) - 1
	head := cdschain.Head{V: cdschain.Version, Cluster: "lane", Seq: uint64(last), Hash: entries[last].Hash()}
	st := &refusingStore{Store: NewMemory()}
	st.allow.Store(int64(last))
	if _, err := forward(ctx, st, nil, entries, head); err == nil {
		t.Fatal("negative control: a refused put went unnoticed")
	}
	raw, _ := st.GetHead(ctx)
	var got cdschain.Head
	if err := json.Unmarshal(raw, &got); err != nil || got.Seq != 2*forwardBatch-1 || got.Hash != entries[got.Seq].Hash() {
		t.Fatalf("store head %s after %d of %d puts, want seq %d", raw, last, len(entries), 2*forwardBatch-1)
	}
	st.allow.Store(1 << 30)
	if raw, err := forward(ctx, st, raw, entries[got.Seq+1:], head); err != nil {
		t.Fatalf("the rest: %v", err)
	} else if want, _ := json.Marshal(head); !bytes.Equal(raw, want) {
		t.Fatalf("store head %s, want %s", raw, want)
	}
}
