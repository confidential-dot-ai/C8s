package cdsha

import (
	"errors"
	"sync"

	"github.com/hashicorp/raft"
)

// memLog is the replica's Raft log and stable store. Both live in the
// process's memory, which is where a CDS HA cluster keeps everything, and
// the log holds every entry until a snapshot lets Raft compact it, so it
// counts the entry bytes it holds under the same lock.
type memLog struct {
	mu      sync.Mutex
	entries map[uint64]*raft.Log
	// first and last are the oldest and newest index held, 0 for none.
	first uint64
	last  uint64
	// data is the entry payloads held, which is most of the log's memory.
	data   int64
	values map[string][]byte
	counts map[string]uint64
}

var (
	_ raft.LogStore    = (*memLog)(nil)
	_ raft.StableStore = (*memLog)(nil)
)

func newMemLog() *memLog {
	return &memLog{
		entries: make(map[uint64]*raft.Log),
		values:  make(map[string][]byte),
		counts:  make(map[string]uint64),
	}
}

func (m *memLog) FirstIndex() (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.first, nil
}

func (m *memLog) LastIndex() (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last, nil
}

func (m *memLog) GetLog(index uint64, out *raft.Log) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	held, ok := m.entries[index]
	if !ok {
		return raft.ErrLogNotFound
	}
	*out = *held
	return nil
}

func (m *memLog) StoreLog(entry *raft.Log) error {
	return m.StoreLogs([]*raft.Log{entry})
}

func (m *memLog) StoreLogs(entries []*raft.Log) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, entry := range entries {
		// A follower replacing a conflicting suffix stores an index again.
		if replaced, ok := m.entries[entry.Index]; ok {
			m.data -= entryData(replaced)
		}
		held := *entry
		m.entries[entry.Index] = &held
		m.data += entryData(entry)
		if m.first == 0 || entry.Index < m.first {
			m.first = entry.Index
		}
		if entry.Index > m.last {
			m.last = entry.Index
		}
	}
	return nil
}

// DeleteRange drops the entries from first to last inclusive: the front of
// the log once a snapshot covers it, or the tail a follower replaces.
func (m *memLog) DeleteRange(first, last uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for index := first; index <= last; index++ {
		held, ok := m.entries[index]
		if !ok {
			continue
		}
		m.data -= entryData(held)
		delete(m.entries, index)
	}
	if first <= m.first {
		m.first = last + 1
	}
	if last >= m.last {
		m.last = first - 1
	}
	if m.first > m.last {
		m.first = 0
		m.last = 0
	}
	return nil
}

// dropAll drops every entry held: the log of a replica that carried its
// cluster on alone, whose state is in the snapshot that replaced it
// (recover.go).
func (m *memLog) dropAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = make(map[uint64]*raft.Log)
	m.first = 0
	m.last = 0
	m.data = 0
}

// usage is the entries the log holds and the bytes of their payloads.
func (m *memLog) usage() (entries uint64, data int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return uint64(len(m.entries)), m.data
}

// entryData is the payload of one entry: what the log's memory is spent on.
func entryData(entry *raft.Log) int64 {
	return int64(len(entry.Data) + len(entry.Extensions))
}

func (m *memLog) Set(key, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[string(key)] = value
	return nil
}

// errKeyNotFound is a key the stable store never took. Raft matches its text
// to tell a first start from a failing store.
var errKeyNotFound = errors.New("not found")

func (m *memLog) Get(key []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.values[string(key)]
	if !ok {
		return nil, errKeyNotFound
	}
	return value, nil
}

func (m *memLog) SetUint64(key []byte, value uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts[string(key)] = value
	return nil
}

// GetUint64 answers 0 for a key the store never took: the term and vote Raft
// reads at its start.
func (m *memLog) GetUint64(key []byte) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[string(key)], nil
}
