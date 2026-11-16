package cdsha

import (
	"bytes"
	"io"
	"sync"
	"testing"

	"github.com/hashicorp/raft"
)

// A leader sends a follower only a snapshot that is whole: the store
// publishes one when its sink closes, not when it is created.
func TestASnapshotIsHandedOnOnlyOnceItIsWhole(t *testing.T) {
	store := &snapStore{}
	sink := create(t, store, 7)
	if _, err := sink.Write([]byte("half")); err != nil {
		t.Fatal(err)
	}

	if held, err := store.List(); err != nil || len(held) != 0 {
		t.Fatalf("the store holds %d snapshots while one is being written: %v", len(held), err)
	}
	if _, _, err := store.Open(sink.ID()); err == nil {
		t.Fatal("a snapshot being written was opened")
	}

	if _, err := sink.Write([]byte(" and half")); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	held, err := store.List()
	if err != nil || len(held) != 1 || held[0].Index != 7 || held[0].Size != 13 {
		t.Fatalf("the store holds %+v: %v", held, err)
	}
	meta, body, err := store.Open(sink.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	read, err := io.ReadAll(body)
	if err != nil || !bytes.Equal(read, []byte("half and half")) {
		t.Fatalf("the snapshot reads %q: %v", read, err)
	}
	if index, size, atMS := store.latest(); index != meta.Index || size != 13 || atMS == 0 {
		t.Fatalf("the newest snapshot is index %d of %d bytes at %d", index, size, atMS)
	}
	// The store holds the sink's own bytes, so the sink takes no more.
	if _, err := sink.Write([]byte("more")); err == nil {
		t.Fatal("a snapshot already handed on took more")
	}
}

// A snapshot whose writer gave up is not the cluster's state.
func TestACancelledSnapshotIsNeverHandedOn(t *testing.T) {
	store := &snapStore{}
	sink := create(t, store, 7)
	if _, err := sink.Write([]byte("half")); err != nil {
		t.Fatal(err)
	}
	if err := sink.Cancel(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if index, _, _ := store.latest(); index != 0 {
		t.Fatalf("the store holds the cancelled snapshot at index %d", index)
	}
}

// The store holds the newest state, not the newest write: an older snapshot
// that finishes last is dropped.
func TestAnOlderSnapshotFinishingLastIsDropped(t *testing.T) {
	store := &snapStore{}
	older := create(t, store, 7)
	newer := create(t, store, 9)
	if err := newer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := older.Close(); err != nil {
		t.Fatal(err)
	}
	if index, _, _ := store.latest(); index != 9 {
		t.Fatalf("the store holds index %d, and the newest snapshot is 9", index)
	}
}

// A snapshot version this replica does not write is refused where it is
// asked for, not where it would be read.
func TestASnapshotVersionThisReplicaDoesNotWriteIsRefused(t *testing.T) {
	store := &snapStore{}
	if _, err := store.Create(raft.SnapshotVersionMax+1, 1, 1, raft.Configuration{}, 1, nil); err == nil {
		t.Fatal("created")
	}
}

// Raft closes a sink from the goroutine that takes the snapshot while the
// state machine may still be writing into it, so the store takes a body of
// the length its metadata names.
func TestACloseRacingAWriteTakesAWholeSnapshot(t *testing.T) {
	store := &snapStore{}
	sink := create(t, store, 7)
	var writers sync.WaitGroup
	writers.Add(2)
	go func() {
		defer writers.Done()
		_, _ = sink.Write([]byte("state"))
	}()
	go func() {
		defer writers.Done()
		if err := sink.Close(); err != nil {
			t.Error(err)
		}
	}()
	writers.Wait()

	meta, body, err := store.Open(sink.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	read, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(read)) != meta.Size {
		t.Fatalf("the snapshot carries %d bytes, and its metadata names %d", len(read), meta.Size)
	}
}

func create(t *testing.T, store *snapStore, index uint64) raft.SnapshotSink {
	t.Helper()
	sink, err := store.Create(raft.SnapshotVersionMax, index, 2, raft.Configuration{}, index, nil)
	if err != nil {
		t.Fatal(err)
	}
	return sink
}
