package cdsha

import (
	"io"
	"sync"
	"testing"

	"github.com/hashicorp/raft"
)

// A snapshot is visible only once complete, and readers never see it grow.
func TestSnapStorePublishesOnClose(t *testing.T) {
	s := &snapStore{}
	k, err := s.Create(1, 10, 1, raft.Configuration{}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = k.Write([]byte("half"))
	if l, _ := s.List(); len(l) != 0 {
		t.Fatal("a snapshot being written is listed")
	}
	if _, _, err := s.Open(k.ID()); err == nil {
		t.Fatal("a snapshot being written opened")
	}
	_, _ = k.Write([]byte("-done"))
	if err := k.Close(); err != nil {
		t.Fatal(err)
	}
	m, rc, err := s.Open(k.ID())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	if string(b) != "half-done" || m.Size != 9 || m.Index != 10 {
		t.Fatalf("got %q size %d index %d", b, m.Size, m.Index)
	}
	// An older snapshot finishing later does not replace a newer one; a
	// cancelled one is never published; writing a new one while the old
	// is read is safe (run with -race).
	old, _ := s.Create(1, 5, 1, raft.Configuration{}, 1, nil)
	_, _ = old.Write([]byte("old"))
	_ = old.Close()
	cancelled, _ := s.Create(1, 20, 1, raft.Configuration{}, 1, nil)
	_ = cancelled.Cancel()
	_ = cancelled.Close()
	if l, _ := s.List(); len(l) != 1 || l[0].Index != 10 {
		t.Fatalf("latest %+v", l)
	}
	if _, err := s.Create(2, 1, 1, raft.Configuration{}, 1, nil); err == nil {
		t.Fatal("version 2 accepted")
	}
	var wg sync.WaitGroup
	next, _ := s.Create(1, 30, 1, raft.Configuration{}, 1, nil)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_, _ = next.Write([]byte("xxxxxxxxxxxxxxxx"))
		}
		_ = next.Close()
	}()
	for i := 0; i < 100; i++ {
		if l, _ := s.List(); len(l) == 1 {
			if _, rc, err := s.Open(l[0].ID); err == nil {
				_, _ = io.ReadAll(rc)
			}
		}
	}
	wg.Wait()
}
