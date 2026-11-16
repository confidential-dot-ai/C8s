package cdsha

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// snapStore keeps the newest snapshot in the replica's memory and takes one
// only once its sink closes, so a leader never sends a follower a snapshot
// that is still being written.
type snapStore struct {
	mu     sync.RWMutex
	newest *heldSnapshot
}

// heldSnapshot is a snapshot the store holds: what Raft knows about it, its
// stream, and when it was taken.
type heldSnapshot struct {
	meta raft.SnapshotMeta
	body []byte
	at   time.Time
}

var _ raft.SnapshotStore = (*snapStore)(nil)

// latest is the index, size and time (Unix ms) of the snapshot the store
// holds, and zeroes while it holds none.
func (s *snapStore) latest() (index uint64, size, atMS int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.newest == nil {
		return 0, 0, 0
	}
	return s.newest.meta.Index, int64(len(s.newest.body)), s.newest.at.UnixMilli()
}

func (s *snapStore) Create(version raft.SnapshotVersion, index, term uint64, configuration raft.Configuration,
	configurationIndex uint64, _ raft.Transport) (raft.SnapshotSink, error) {
	if version < raft.SnapshotVersionMin || version > raft.SnapshotVersionMax {
		return nil, fmt.Errorf("cds-ha: snapshot version %d is not one this replica writes", version)
	}
	return &snapSink{
		store: s,
		meta: raft.SnapshotMeta{
			Version:            version,
			ID:                 fmt.Sprintf("%d-%d", term, index),
			Index:              index,
			Term:               term,
			Configuration:      configuration,
			ConfigurationIndex: configurationIndex,
		},
	}, nil
}

func (s *snapStore) List() ([]*raft.SnapshotMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.newest == nil {
		return nil, nil
	}
	meta := s.newest.meta
	return []*raft.SnapshotMeta{&meta}, nil
}

func (s *snapStore) Open(id string) (*raft.SnapshotMeta, io.ReadCloser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.newest == nil || s.newest.meta.ID != id {
		return nil, nil, fmt.Errorf("cds-ha: this replica holds no snapshot %s", id)
	}
	meta := s.newest.meta
	// A snapshot the store holds is never written again.
	return &meta, io.NopCloser(bytes.NewReader(s.newest.body)), nil
}

// snapSink is one snapshot being written. It reaches the store on Close.
type snapSink struct {
	store *snapStore
	// mu guards the sink's fields; meta.ID is fixed at Create and read
	// without it.
	mu   sync.Mutex
	meta raft.SnapshotMeta
	buf  bytes.Buffer
	// done is set by Close or Cancel, after which the sink takes no more.
	done bool
}

func (k *snapSink) ID() string {
	return k.meta.ID
}

func (k *snapSink) Write(p []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.done {
		return 0, errors.New("cds-ha: this snapshot is written; it takes no more")
	}
	return k.buf.Write(p)
}

func (k *snapSink) Cancel() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.done = true
	return nil
}

func (k *snapSink) Close() error {
	if held, written := k.finish(); written {
		k.store.hold(held)
	}
	return nil
}

// finish closes the sink and answers what it took, or false for a sink
// already closed or cancelled.
func (k *snapSink) finish() (*heldSnapshot, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.done {
		return nil, false
	}
	k.done = true
	k.meta.Size = int64(k.buf.Len())
	return &heldSnapshot{
		meta: k.meta,
		body: k.buf.Bytes(),
		at:   time.Now(),
	}, true
}

// hold takes held as the store's snapshot. The store holds the newest state,
// not the newest write, so an older snapshot that finishes last is dropped.
func (s *snapStore) hold(held *heldSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.newest != nil && held.meta.Index < s.newest.meta.Index {
		return
	}
	s.newest = held
}
