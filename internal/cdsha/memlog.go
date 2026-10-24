package cdsha

import (
	"sync"

	"github.com/hashicorp/raft"
)

// memLog is the replica's in-memory Raft log (raft.InmemStore) with a
// running count of the bytes its entries hold, for Status: the log lives
// in the Go heap until a snapshot compacts it.
type memLog struct {
	*raft.InmemStore
	mu    sync.Mutex
	bytes int64
}

func newMemLog() *memLog { return &memLog{InmemStore: raft.NewInmemStore()} }

func logEntryBytes(l *raft.Log) int64 { return int64(len(l.Data) + len(l.Extensions)) }

func (m *memLog) StoreLog(l *raft.Log) error { return m.StoreLogs([]*raft.Log{l}) }

func (m *memLog) StoreLogs(logs []*raft.Log) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range logs {
		// An index stored again (a follower truncating a conflicting
		// suffix) replaces the entry there.
		var old raft.Log
		if m.InmemStore.GetLog(l.Index, &old) == nil {
			m.bytes -= logEntryBytes(&old)
		}
	}
	if err := m.InmemStore.StoreLogs(logs); err != nil {
		return err
	}
	for _, l := range logs {
		m.bytes += logEntryBytes(l)
	}
	return nil
}

func (m *memLog) DeleteRange(min, max uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var freed int64
	for i := min; i <= max && i >= min; i++ {
		var l raft.Log
		if m.InmemStore.GetLog(i, &l) == nil {
			freed += logEntryBytes(&l)
		}
	}
	if err := m.InmemStore.DeleteRange(min, max); err != nil {
		return err
	}
	m.bytes -= freed
	return nil
}

// usage is the entries the log holds and their bytes.
func (m *memLog) usage() (entries uint64, bytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	first, _ := m.InmemStore.FirstIndex()
	last, _ := m.InmemStore.LastIndex()
	if last >= first && last > 0 {
		entries = last - first + 1
	}
	return entries, m.bytes
}
