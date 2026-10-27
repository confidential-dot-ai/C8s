package cdsha

import "github.com/hashicorp/raft"

// recoveryLogStore is only for RecoverCluster, never NewRaft or normal reads.
// Pinned Raft v1.8.0 reads each tail entry once, in ascending order, after
// restoring its base snapshot and immediately before applying each command.
// Its replay omits ConfigurationStore callbacks. Restore those callbacks here
// so the scratch command/configuration watermark matches normal runFSM.
// Re-audit this side-effectful read contract when upgrading Raft.
type recoveryLogStore struct {
	raft.LogStore
	scratch *FSM
}

func (s recoveryLogStore) GetLog(index uint64, entry *raft.Log) error {
	if err := s.LogStore.GetLog(index, entry); err != nil {
		return err
	}
	if entry.Type == raft.LogConfiguration {
		// Match normal runFSM decoding, including its corrupt-storage panic behavior.
		s.scratch.StoreConfiguration(entry.Index, raft.DecodeConfiguration(entry.Data))
	}
	return nil
}
