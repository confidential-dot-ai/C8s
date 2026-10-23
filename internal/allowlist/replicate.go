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
	// OpPruneHistory keeps the newest Keep entries of the history.
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

// with records err in r for the trip back across the log.
func (r Result) with(err error) Result {
	if err == nil {
		return r
	}
	r.ErrKind, r.Err = "other", err.Error()
	for kind, s := range sentinels {
		if errors.Is(err, s) {
			r.ErrKind = kind
		}
	}
	return r
}

// Error rebuilds the error Apply returned: its message, and its sentinel
// for errors.Is.
func (r Result) Error() error {
	if r.ErrKind == "" {
		return nil
	}
	return wireErr{r.Err, sentinels[r.ErrKind]}
}

// wireErr is an error that crossed the log: the text, and the sentinel.
type wireErr struct {
	msg string
	is  error
}

func (e wireErr) Error() string { return e.msg }
func (e wireErr) Unwrap() error { return e.is }

// Apply runs one replicated command against the local database. Replicas
// apply the same commands in the same order, so they hold the same store.
func (s *Store) Apply(cmd Command) Result {
	r, err := s.apply(cmd)
	return r.with(err)
}

func (s *Store) apply(cmd Command) (r Result, err error) {
	s.at.Store(cmd.AtMS)
	defer s.at.Store(0)
	switch cmd.Op {
	case OpSeed:
		r.Added, r.Retired, err = s.seedWorkloads(cmd.Workloads)
	case OpPutWorkload:
		if cmd.Workload == nil {
			return r, errors.New("put_workload without a workload")
		}
		err = s.putWorkload(cmd.Name, *cmd.Workload)
	case OpDeleteWorkload:
		r.Found, err = s.deleteWorkload(cmd.Name)
	case OpReplaceAll:
		err = s.replaceAll(cmd.Allowlist)
	case OpSignPolicy:
		err = s.signPolicy(cmd.Body, cmd.Token)
	case OpConsumeToken:
		err = s.consumeToken(cmd.Token)
	case OpReplaceRoutes:
		if cmd.Routes == nil {
			return r, errors.New("replace_routes without a manifest")
		}
		err = s.replaceRoutes(*cmd.Routes, cmd.IfMatch)
	case OpStartJournal:
		err = s.startJournal()
	case OpPruneHistory:
		r.Retired, err = s.PruneHistory(cmd.Keep)
	default:
		err = fmt.Errorf("unknown allowlist command %q", cmd.Op)
	}
	return r, err
}

// write runs cmd here, or through the log when the store is replicated.
func (s *Store) write(cmd Command) (Result, error) {
	if s.repl == nil {
		return s.apply(cmd)
	}
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
	if len(workloads) == 0 {
		return 0, 0, nil
	}
	res, err := s.write(Command{Op: OpSeed, Workloads: workloads})
	return res.Added, res.Retired, err
}

// PutWorkload upserts one named workload entry (see putWorkload).
func (s *Store) PutWorkload(name string, w pkgallowlist.Workload) error {
	_, err := s.write(Command{Op: OpPutWorkload, Name: name, Workload: &w})
	return err
}

// DeleteWorkload removes one named entry (see deleteWorkload).
func (s *Store) DeleteWorkload(name string) (bool, error) {
	res, err := s.write(Command{Op: OpDeleteWorkload, Name: name})
	return res.Found, err
}

// ReplaceAll swaps the entire allowlist (see replaceAll).
func (s *Store) ReplaceAll(al *pkgallowlist.Allowlist) error {
	_, err := s.write(Command{Op: OpReplaceAll, Allowlist: al})
	return err
}

// SignPolicy stores the operator token of a whole-document write (see
// signPolicy).
func (s *Store) SignPolicy(body []byte, token string) error {
	_, err := s.write(Command{Op: OpSignPolicy, Body: body, Token: token})
	return err
}

// ConsumeToken spends a write token once (see consumeToken). Replicated, a
// token spent at any replica is spent at all of them.
func (s *Store) ConsumeToken(token string) error {
	_, err := s.write(Command{Op: OpConsumeToken, Token: token})
	return err
}

// ReplaceRoutes stores a signed route manifest (see replaceRoutes).
func (s *Store) ReplaceRoutes(env routes.Envelope, ifMatch string) error {
	_, err := s.write(Command{Op: OpReplaceRoutes, Routes: &env, IfMatch: ifMatch})
	return err
}

// StartJournal verifies the history and journals the current document if it
// is not the head (see startJournal).
func (s *Store) StartJournal() error {
	_, err := s.write(Command{Op: OpStartJournal})
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
