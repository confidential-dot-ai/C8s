package allowlist

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// Replicator carries a store mutation to every CDS replica (CDS HA). It
// returns once the command is committed and applied by this replica, with
// the result Apply produced. Without one, the store is a singleton and every
// write method runs locally.
type Replicator interface {
	Replicate(cmd Command) (Result, error)
}

// SetReplicator makes every later mutation a replicated command. Set it
// before serving.
func (s *Store) SetReplicator(r Replicator) { s.repl = r }

// Op names one store mutation.
type Op string

// The store mutations.
const (
	OpSeed           Op = "seed"
	OpPutWorkload    Op = "put_workload"
	OpDeleteWorkload Op = "delete_workload"
	OpReplaceAll     Op = "replace_all"
	OpSignPolicy     Op = "sign_policy"
	OpConsumeToken   Op = "consume_token"
	OpReplaceRoutes  Op = "replace_routes"
	OpStartJournal   Op = "start_journal"
	// OpPruneHistory keeps the newest Keep entries of the history. A
	// replica of a release without it would answer an error and keep its
	// history, so the leader proposes it only in a format every member reads
	// (cdsha.Format 2).
	OpPruneHistory Op = "prune_history"
)

// Command is one replicated mutation. Everything a replica needs to apply it
// identically is in it, including the time it is journaled at.
type Command struct {
	Op        Op                               `json:"op"`
	AtMS      int64                            `json:"at_ms"`
	Name      string                           `json:"name,omitempty"`
	Workload  *pkgallowlist.Workload           `json:"workload,omitempty"`
	Workloads map[string]pkgallowlist.Workload `json:"workloads,omitempty"`
	Allowlist *pkgallowlist.Allowlist          `json:"allowlist,omitempty"`
	Body      []byte                           `json:"body,omitempty"`
	Token     string                           `json:"token,omitempty"`
	Routes    *routes.Envelope                 `json:"routes,omitempty"`
	IfMatch   string                           `json:"if_match,omitempty"`
	Keep      int                              `json:"keep,omitempty"`
}

// Result is what applying a command returned. Err keeps the sentinel a
// caller tests with errors.Is across the replication boundary.
type Result struct {
	Found   bool   `json:"found,omitempty"`
	Added   int    `json:"added,omitempty"`
	Retired int    `json:"retired,omitempty"`
	ErrKind string `json:"err_kind,omitempty"`
	Err     string `json:"err,omitempty"`
}

var sentinels = map[string]error{
	"invalid_workload":     ErrInvalidWorkload,
	"token_reused":         operatorauth.ErrTokenReused,
	"revision_not_greater": ErrRevisionNotGreater,
	"digest_mismatch":      ErrDigestMismatch,
}

func resultErr(err error) Result {
	if err == nil {
		return Result{}
	}
	for kind, s := range sentinels {
		if errors.Is(err, s) {
			return Result{ErrKind: kind, Err: err.Error()}
		}
	}
	return Result{ErrKind: "other", Err: err.Error()}
}

// Error rebuilds the error Apply returned, wrapping its sentinel.
func (r Result) Error() error {
	switch {
	case r.ErrKind == "":
		return nil
	case sentinels[r.ErrKind] != nil:
		if r.Err == sentinels[r.ErrKind].Error() {
			return sentinels[r.ErrKind]
		}
		return fmt.Errorf("%w (%s)", sentinels[r.ErrKind], r.Err)
	default:
		return errors.New(r.Err)
	}
}

// ApplyOptions are the behaviors a replicated group turns on only once every
// member has them, so replicas of two releases apply a command alike.
type ApplyOptions struct {
	// TokenExpiry records each spent token's iat and exp and prunes the
	// records of long-expired ones (see consumeToken); cdsha.Format 2.
	TokenExpiry bool
}

// Apply runs one replicated command against the local database with every
// behavior of this release on (see ApplyWith).
func (s *Store) Apply(cmd Command) Result {
	return s.ApplyWith(cmd, ApplyOptions{TokenExpiry: true})
}

// ApplyWith runs one replicated command against the local database. Replicas
// apply the same commands in the same order, with the same options, so they
// hold the same store.
func (s *Store) ApplyWith(cmd Command, opts ApplyOptions) Result {
	s.at.Store(cmd.AtMS)
	defer s.at.Store(0)
	switch cmd.Op {
	case OpSeed:
		added, retired, err := s.seedWorkloads(cmd.Workloads)
		r := resultErr(err)
		r.Added, r.Retired = added, retired
		return r
	case OpPutWorkload:
		if cmd.Workload == nil {
			return resultErr(errors.New("put_workload without a workload"))
		}
		return resultErr(s.putWorkload(cmd.Name, *cmd.Workload))
	case OpDeleteWorkload:
		found, err := s.deleteWorkload(cmd.Name)
		r := resultErr(err)
		r.Found = found
		return r
	case OpReplaceAll:
		return resultErr(s.replaceAll(cmd.Allowlist))
	case OpSignPolicy:
		return resultErr(s.signPolicy(cmd.Body, cmd.Token))
	case OpConsumeToken:
		return resultErr(s.consumeToken(cmd.Token, opts.TokenExpiry))
	case OpReplaceRoutes:
		if cmd.Routes == nil {
			return resultErr(errors.New("replace_routes without a manifest"))
		}
		return resultErr(s.replaceRoutes(*cmd.Routes, cmd.IfMatch))
	case OpStartJournal:
		return resultErr(s.startJournal())
	case OpPruneHistory:
		dropped, err := s.pruneHistory(cmd.Keep)
		r := resultErr(err)
		r.Retired = dropped
		return r
	}
	return resultErr(fmt.Errorf("unknown allowlist command %q", cmd.Op))
}

func (s *Store) replicate(cmd Command) (Result, error) {
	cmd.AtMS = time.Now().UnixMilli()
	res, err := s.repl.Replicate(cmd)
	if err != nil {
		return Result{}, err
	}
	return res, res.Error()
}

// SeedWorkloads adds every workload entry whose name is not already present
// and retires each stored entry the seed replaces (see seedWorkloads).
func (s *Store) SeedWorkloads(workloads map[string]pkgallowlist.Workload) (added, retired int, err error) {
	if s.repl == nil {
		return s.seedWorkloads(workloads)
	}
	if len(workloads) == 0 {
		return 0, 0, nil
	}
	res, err := s.replicate(Command{Op: OpSeed, Workloads: workloads})
	return res.Added, res.Retired, err
}

// PutWorkload upserts one named workload entry (see putWorkload).
func (s *Store) PutWorkload(name string, w pkgallowlist.Workload) error {
	if s.repl == nil {
		return s.putWorkload(name, w)
	}
	_, err := s.replicate(Command{Op: OpPutWorkload, Name: name, Workload: &w})
	return err
}

// DeleteWorkload removes one named entry (see deleteWorkload).
func (s *Store) DeleteWorkload(name string) (bool, error) {
	if s.repl == nil {
		return s.deleteWorkload(name)
	}
	res, err := s.replicate(Command{Op: OpDeleteWorkload, Name: name})
	return res.Found, err
}

// ReplaceAll swaps the entire allowlist (see replaceAll).
func (s *Store) ReplaceAll(al *pkgallowlist.Allowlist) error {
	if s.repl == nil || al == nil {
		return s.replaceAll(al)
	}
	_, err := s.replicate(Command{Op: OpReplaceAll, Allowlist: al})
	return err
}

// SignPolicy stores the operator token of a whole-document write (see
// signPolicy).
func (s *Store) SignPolicy(body []byte, token string) error {
	if s.repl == nil {
		return s.signPolicy(body, token)
	}
	_, err := s.replicate(Command{Op: OpSignPolicy, Body: body, Token: token})
	return err
}

// ConsumeToken spends a write token once (see consumeToken). Replicated, a
// token spent at any replica is spent at all of them.
func (s *Store) ConsumeToken(token string) error {
	if s.repl == nil {
		return s.consumeToken(token, true)
	}
	_, err := s.replicate(Command{Op: OpConsumeToken, Token: token})
	return err
}

// ReplaceRoutes stores a signed route manifest (see replaceRoutes).
func (s *Store) ReplaceRoutes(env routes.Envelope, ifMatch string) error {
	if s.repl == nil {
		return s.replaceRoutes(env, ifMatch)
	}
	// Refuse what routes.Parse refuses before it reaches the log.
	if _, err := routes.Parse(env.Manifest); err != nil {
		return err
	}
	_, err := s.replicate(Command{Op: OpReplaceRoutes, Routes: &env, IfMatch: ifMatch})
	return err
}

// StartJournal verifies the history and journals the current document if it
// is not the head (see startJournal).
func (s *Store) StartJournal() error {
	if s.repl == nil {
		return s.startJournal()
	}
	_, err := s.replicate(Command{Op: OpStartJournal})
	return err
}

var columnRE = regexp.MustCompile(`^[a-z_]{1,64}$`)

// snapshotTables are every table a snapshot carries, in restore order.
var snapshotTables = []string{
	"allowlist_version", "workload_entry", "workload_entry_digest", "route_manifest",
	"journal_object", "journal_event", "journal_signature", "used_token",
}

// Snapshot is the whole database as rows, for a replica that joins or
// recovers. Columns are kept by name; a row that lacks a column restores
// with the column's default.
type Snapshot map[string][]map[string]any

// StripTokenExpiry drops the used_token columns a release before
// ApplyOptions.TokenExpiry cannot restore. A group that has not turned
// TokenExpiry on holds only 0s in them, which is what restoring without
// them writes.
func (sn Snapshot) StripTokenExpiry() {
	for _, row := range sn["used_token"] {
		for _, c := range usedTokenColumns {
			delete(row, c)
		}
	}
}

// Dump returns every row of every table.
func (s *Store) Dump() (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Snapshot{}
	for _, t := range snapshotTables {
		rows, err := s.db.Query("SELECT * FROM " + t) //nolint:gosec // fixed table names
		if err != nil {
			return nil, err
		}
		cols, err := rows.Columns()
		if err != nil {
			rows.Close()
			return nil, err
		}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				return nil, err
			}
			row := map[string]any{}
			for i, c := range cols {
				row[c] = vals[i]
			}
			out[t] = append(out[t], row)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// MarshalJSON keeps BLOB columns distinct from TEXT ones across the wire.
func (sn Snapshot) MarshalJSON() ([]byte, error) {
	type cell struct {
		B []byte `json:"b,omitempty"`
		V any    `json:"v,omitempty"`
	}
	out := map[string][]map[string]cell{}
	for t, rows := range sn {
		for _, row := range rows {
			r := map[string]cell{}
			for c, v := range row {
				if b, ok := v.([]byte); ok {
					r[c] = cell{B: b}
				} else {
					r[c] = cell{V: v}
				}
			}
			out[t] = append(out[t], r)
		}
	}
	return json.Marshal(out)
}

// UnmarshalJSON is the inverse of MarshalJSON. Integers come back as int64.
func (sn *Snapshot) UnmarshalJSON(b []byte) error {
	type cell struct {
		B []byte          `json:"b,omitempty"`
		V json.RawMessage `json:"v,omitempty"`
	}
	var in map[string][]map[string]cell
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	out := Snapshot{}
	for t, rows := range in {
		for _, row := range rows {
			r := map[string]any{}
			for c, v := range row {
				switch {
				case v.B != nil:
					r[c] = v.B
				case len(v.V) == 0:
					r[c] = nil
				default:
					var n json.Number
					if json.Unmarshal(v.V, &n) == nil {
						i, err := n.Int64()
						if err != nil {
							return fmt.Errorf("snapshot %s.%s: %w", t, c, err)
						}
						r[c] = i
						continue
					}
					var str string
					if err := json.Unmarshal(v.V, &str); err != nil {
						return fmt.Errorf("snapshot %s.%s: %w", t, c, err)
					}
					r[c] = str
				}
			}
			out[t] = append(out[t], r)
		}
	}
	*sn = out
	return nil
}

// Restore replaces the whole database with a snapshot, in one transaction.
func (s *Store) Restore(sn Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range snapshotTables {
		if _, err := tx.Exec("DELETE FROM " + t); err != nil { //nolint:gosec // fixed table names
			return err
		}
		for _, row := range sn[t] {
			cols := make([]string, 0, len(row))
			for c := range row {
				if !columnRE.MatchString(c) {
					return fmt.Errorf("restore %s: bad column name %q", t, c)
				}
				cols = append(cols, c)
			}
			slices.Sort(cols)
			args := make([]any, len(cols))
			for i, c := range cols {
				args[i] = row[c]
			}
			q := "INSERT INTO " + t + " (" + strings.Join(cols, ", ") + ") VALUES (" + strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ") + ")"
			if _, err := tx.Exec(q, args...); err != nil { //nolint:gosec // fixed table names; column names checked against columnRE
				return fmt.Errorf("restore %s: %w", t, err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.gen++
	return nil
}
