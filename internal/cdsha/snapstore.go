package cdsha

import (
	"bytes"
	"fmt"
	"io"
	"sync"

	"github.com/hashicorp/raft"
)

// snapStore keeps the latest Raft snapshot in memory, like
// raft.InmemSnapshotStore, but publishes a snapshot only once its sink is
// closed. The raft one makes a snapshot the latest as soon as it is created,
// so the leader could send a follower one that is still being written (and
// read the buffer while it grows).
type snapStore struct {
	mu     sync.RWMutex
	meta   raft.SnapshotMeta
	body   []byte
	exists bool
}

func (s *snapStore) Create(version raft.SnapshotVersion, index, term uint64, configuration raft.Configuration,
	configurationIndex uint64, _ raft.Transport) (raft.SnapshotSink, error) {
	if version != 1 {
		return nil, fmt.Errorf("unsupported snapshot version %d", version)
	}
	return &snapSink{store: s, meta: raft.SnapshotMeta{Version: version, ID: fmt.Sprintf("%d-%d", term, index),
		Index: index, Term: term, Configuration: configuration, ConfigurationIndex: configurationIndex}}, nil
}

func (s *snapStore) List() ([]*raft.SnapshotMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.exists {
		return nil, nil
	}
	m := s.meta
	return []*raft.SnapshotMeta{&m}, nil
}

func (s *snapStore) Open(id string) (*raft.SnapshotMeta, io.ReadCloser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.exists || s.meta.ID != id {
		return nil, nil, fmt.Errorf("snapshot %s not found", id)
	}
	m := s.meta
	return &m, io.NopCloser(bytes.NewReader(s.body)), nil // body is never written again
}

type snapSink struct {
	store *snapStore
	meta  raft.SnapshotMeta
	buf   bytes.Buffer
	done  bool
}

func (k *snapSink) Write(p []byte) (int, error) { return k.buf.Write(p) }
func (k *snapSink) ID() string                  { return k.meta.ID }
func (k *snapSink) Cancel() error               { k.done = true; return nil }

func (k *snapSink) Close() error {
	if k.done {
		return nil
	}
	k.done = true
	k.meta.Size = int64(k.buf.Len())
	k.store.mu.Lock()
	defer k.store.mu.Unlock()
	if k.store.exists && k.meta.Index < k.store.meta.Index {
		return nil // an older snapshot finished last: keep the newer one
	}
	k.store.meta, k.store.body, k.store.exists = k.meta, k.buf.Bytes(), true
	return nil
}
