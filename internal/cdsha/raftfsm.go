package cdsha

import (
	"io"

	"github.com/hashicorp/raft"
)

// raftFSM is the replicated state machine as Raft drives it: Raft owns the
// log and the order entries apply in, the state machine what an entry does.
type raftFSM struct {
	*FSM
}

var _ raft.FSM = raftFSM{}

// Apply answers the entry's result, the stop a replica recorded on it
// included.
func (a raftFSM) Apply(entry *raft.Log) any {
	return a.FSM.Apply(entry.Index, entry.Data)
}

// Snapshot captures the state between two entries; Raft encodes it
// afterwards, off the goroutine that applies the log.
func (a raftFSM) Snapshot() (raft.FSMSnapshot, error) {
	state, err := a.FSM.Snapshot()
	if err != nil {
		return nil, err
	}
	return raftSnapshot{state: state}, nil
}

// Restore replaces this replica's whole state with the snapshot a peer sent.
func (a raftFSM) Restore(snapshot io.ReadCloser) error {
	defer snapshot.Close()
	return a.Install(snapshot)
}

type raftSnapshot struct {
	state *Snapshot
}

func (s raftSnapshot) Persist(sink raft.SnapshotSink) error {
	if err := s.state.Encode(sink); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

func (raftSnapshot) Release() {
}
