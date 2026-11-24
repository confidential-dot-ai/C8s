package allowlist

import (
	"database/sql"
	"fmt"
	"maps"
	"slices"

	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

// The host privilege the allowlist declared, in one row the transaction that
// changes the document writes, so it lasts as long as the store.
const hostPrivilegeSQL = `
CREATE TABLE IF NOT EXISTS host_privilege (
	id                   INTEGER PRIMARY KEY CHECK (id = 1),
	declared_by_seed     INTEGER NOT NULL,
	first_operator_grant TEXT
);
INSERT INTO host_privilege (id, declared_by_seed)
	SELECT 1, 0 WHERE NOT EXISTS (SELECT 1 FROM host_privilege);
`

// HostPrivilege is what GET /allowlist/history reports beside the entries.
type HostPrivilege struct {
	// DeclaredBySeed is whether the measured launch seed declares host
	// privilege; only seeding sets it.
	DeclaredBySeed bool `json:"declaredBySeed"`
	// FirstOperatorGrant is the document of the operator write that first served
	// a declaration the document it replaced did not, null until one has.
	FirstOperatorGrant *HostPrivilegeGrant `json:"firstOperatorGrant"`
}

// HostPrivilegeGrant names that document the way the history names it.
type HostPrivilegeGrant struct {
	Digest string `json:"digest"`
}

// hostPrivilege reads the record. Callers must hold s.mu.
func (s *Store) hostPrivilege() (HostPrivilege, error) {
	var record HostPrivilege
	var grant sql.NullString
	if err := s.db.QueryRow(
		"SELECT declared_by_seed, first_operator_grant FROM host_privilege",
	).Scan(&record.DeclaredBySeed, &grant); err != nil {
		return HostPrivilege{}, fmt.Errorf("read the allowlist host privilege: %w", err)
	}
	if grant.Valid {
		record.FirstOperatorGrant = &HostPrivilegeGrant{Digest: grant.String}
	}
	return record, nil
}

// seedDeclaresHostPrivilegeTx records a measured launch seed that declares host
// privilege. A seed grants nothing: it is part of the measured launch.
func seedDeclaresHostPrivilegeTx(tx *sql.Tx, seed map[string]pkgallowlist.Workload) error {
	for _, w := range seed {
		if w.DeclaresHostPrivilege() {
			_, err := tx.Exec("UPDATE host_privilege SET declared_by_seed = 1")
			return err
		}
	}
	return nil
}

// hostPrivilegeLatch is what commitTx needs to record a grant: the declarations
// the write serves and the ones it replaces. The zero value grants nothing.
type hostPrivilegeLatch struct {
	declared []string
	replaced map[string]bool
}

// hostPrivilegeLatchTx reads the latch of the document about to replace the
// store's contents; call it before replaceContentsTx.
func hostPrivilegeLatchTx(tx *sql.Tx, al *pkgallowlist.Allowlist) (hostPrivilegeLatch, error) {
	declared, err := hostPrivilegeKeys(al.Workloads, al.Components)
	if err != nil {
		return hostPrivilegeLatch{}, err
	}
	workloads, err := loadWorkloads(tx)
	if err != nil {
		return hostPrivilegeLatch{}, err
	}
	components, err := loadComponents(tx)
	if err != nil {
		return hostPrivilegeLatch{}, err
	}
	replaced, err := hostPrivilegeKeys(workloads, components)
	if err != nil {
		return hostPrivilegeLatch{}, err
	}
	latch := hostPrivilegeLatch{declared: declared, replaced: map[string]bool{}}
	for _, key := range replaced {
		latch.replaced[key] = true
	}
	return latch, nil
}

// hostPrivilegeKeys are the declaration keys of every entry of a document that
// declares host privilege. A component set's entries count as the workloads
// section's do: a set introducing a host port or a host bind is the write that
// granted it.
func hostPrivilegeKeys(workloads map[string]pkgallowlist.Workload, components map[string]pkgallowlist.ComponentSet) ([]string, error) {
	entries := slices.Collect(maps.Values(workloads))
	for _, set := range components {
		entries = append(entries, slices.Collect(maps.Values(set.Entries))...)
	}
	var keys []string
	for _, w := range entries {
		if !w.DeclaresHostPrivilege() {
			continue
		}
		key, err := declarationKey(w)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// declarationKey is an entry as the latch compares it: its canonical JSON, with
// an empty container list spelled like an absent one.
func declarationKey(w pkgallowlist.Workload) (string, error) {
	if len(w.InitContainers) == 0 {
		w.InitContainers = nil
	}
	if len(w.Containers) == 0 {
		w.Containers = nil
	}
	return entryJSON(w)
}

// recordTx names digest as the write that granted host privilege. The UPDATE
// passes over a row that already names one, so the first grant stands.
func (l hostPrivilegeLatch) recordTx(tx *sql.Tx, digest string) error {
	if !l.grants() {
		return nil
	}
	_, err := tx.Exec(
		"UPDATE host_privilege SET first_operator_grant = ? WHERE first_operator_grant IS NULL",
		digest,
	)
	return err
}

// grants reports whether the write serves a declaration none of the entries it
// replaces serves identically; the key is an entry, not its name.
func (l hostPrivilegeLatch) grants() bool {
	return slices.ContainsFunc(l.declared, func(entry string) bool {
		return !l.replaced[entry]
	})
}
