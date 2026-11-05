package allowlist

import (
	"database/sql"
	"errors"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// BootstrapNoOp checks whether a seed or journal-start command would change
// nothing. It does not apply a command or change the database. An HA caller
// must first establish a fresh read barrier; arbitrary mutations never qualify.
func (s *Store) BootstrapNoOp(cmd Command) (bool, error) {
	if cmd.AtMS <= 0 || (cmd.Op != OpSeed && cmd.Op != OpStartJournal) {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	stored, err := loadWorkloads(tx)
	if err != nil {
		return false, err
	}
	if cmd.Op == OpSeed {
		if len(replacedBySeed(stored, cmd.Workloads)) != 0 {
			return false, nil
		}
		for name := range cmd.Workloads {
			if _, exists := stored[name]; !exists {
				return false, nil
			}
		}
	} else if err := verifyJournalTx(tx); err != nil {
		return false, err
	}
	// Even an unchanged seed may need to publish a missing journal head.
	body, err := (&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: stored}).Canonical()
	if err != nil {
		return false, err
	}
	var head string
	err = tx.QueryRow("SELECT digest FROM journal_event ORDER BY position DESC LIMIT 1").Scan(&head)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil && head == objectDigest(body), err
}
