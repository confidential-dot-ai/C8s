package cdsha

import (
	"errors"
	"testing"

	"github.com/hashicorp/raft"
)

// The log lives in the replica's memory until a snapshot lets Raft compact
// it, so a replica counts what its log holds.
func TestTheLogCountsWhatItHolds(t *testing.T) {
	log := newMemLog()
	if entries, bytes := log.usage(); entries != 0 || bytes != 0 {
		t.Fatalf("an empty log holds %d entries of %d bytes", entries, bytes)
	}

	if err := log.StoreLogs([]*raft.Log{
		{Index: 1, Data: []byte("one")},
		{Index: 2, Data: []byte("two"), Extensions: []byte("!")},
	}); err != nil {
		t.Fatal(err)
	}
	if entries, bytes := log.usage(); entries != 2 || bytes != 7 {
		t.Fatalf("the log holds %d entries of %d bytes, want 2 of 7", entries, bytes)
	}

	// A follower replacing a conflicting suffix stores an index again.
	if err := log.StoreLog(&raft.Log{
		Index: 2,
		Data:  []byte("replacement"),
	}); err != nil {
		t.Fatal(err)
	}
	if entries, bytes := log.usage(); entries != 2 || bytes != 14 {
		t.Fatalf("the log holds %d entries of %d bytes, want 2 of 14", entries, bytes)
	}

	if err := log.DeleteRange(1, 2); err != nil {
		t.Fatal(err)
	}
	if entries, bytes := log.usage(); entries != 0 || bytes != 0 {
		t.Fatalf("a compacted log holds %d entries of %d bytes", entries, bytes)
	}
}

// Raft asks the log where it starts and ends: the front goes once a snapshot
// covers it, and the tail goes where a follower replaces it.
func TestTheLogSaysWhereItStartsAndEnds(t *testing.T) {
	log := newMemLog()
	if first, _ := log.FirstIndex(); first != 0 {
		t.Fatalf("an empty log starts at %d", first)
	}
	for index := uint64(1); index <= 3; index++ {
		if err := log.StoreLog(&raft.Log{
			Index: index,
			Data:  []byte("entry"),
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := log.DeleteRange(1, 1); err != nil {
		t.Fatal(err)
	}
	if err := log.GetLog(1, &raft.Log{}); !errors.Is(err, raft.ErrLogNotFound) {
		t.Fatalf("reading a compacted entry = %v, want ErrLogNotFound", err)
	}
	first, _ := log.FirstIndex()
	last, _ := log.LastIndex()
	if first != 2 || last != 3 {
		t.Fatalf("the log holds %d to %d, want 2 to 3", first, last)
	}

	if err := log.DeleteRange(3, 3); err != nil {
		t.Fatal(err)
	}
	first, _ = log.FirstIndex()
	last, _ = log.LastIndex()
	if first != 2 || last != 2 {
		t.Fatalf("the log holds %d to %d, want 2 to 2", first, last)
	}
}

// Raft reads the term and the vote at its start, and tells a store that
// never held them from one that is failing.
func TestTheStableStoreAnswersAKeyItNeverHeld(t *testing.T) {
	log := newMemLog()
	term := []byte("CurrentTerm")
	if _, err := log.Get(term); err == nil || err.Error() != "not found" {
		t.Fatalf("a key never set = %v, want \"not found\"", err)
	}
	if held, err := log.GetUint64(term); err != nil || held != 0 {
		t.Fatalf("a term never set = %d: %v", held, err)
	}
	if err := log.SetUint64(term, 7); err != nil {
		t.Fatal(err)
	}
	if held, err := log.GetUint64(term); err != nil || held != 7 {
		t.Fatalf("the stored term = %d: %v", held, err)
	}
	if err := log.Set(term, []byte("seven")); err != nil {
		t.Fatal(err)
	}
	if held, err := log.Get(term); err != nil || string(held) != "seven" {
		t.Fatalf("the stored value = %q: %v", held, err)
	}
}
