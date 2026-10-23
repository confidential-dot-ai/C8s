package allowlist

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

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
	if localStoreFault(err) {
		r.ErrKind = storageKind
		return r
	}
	for kind, s := range sentinels {
		if errors.Is(err, s) {
			r.ErrKind = kind
		}
	}
	return r
}

// storageKind marks a Result whose command failed in this replica's own
// database, not on its content.
const storageKind = "storage"

// LocalStoreFault reports that applying the command failed in this
// replica's database (disk full, I/O error, corruption, ...). Every replica
// applies the same commands, but each has its own disk: such a failure is
// not an answer the others share, and a replica that keeps going after one
// no longer holds the replicated state.
func (r Result) LocalStoreFault() bool { return r.ErrKind == storageKind }

// localStoreFault reports a SQLite failure of the database itself. Results a
// command produces identically everywhere (a constraint it violates, a value
// over a fixed limit) are not faults of the store.
func localStoreFault(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code() & 0xff {
	case sqlite3.SQLITE_CONSTRAINT, sqlite3.SQLITE_TOOBIG, sqlite3.SQLITE_MISMATCH, sqlite3.SQLITE_RANGE:
		return false
	}
	return true
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
		r.Retired, err = s.pruneHistory(cmd.Keep)
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

// imageConn is the modernc.org/sqlite connection API a database image needs.
type imageConn interface {
	Serialize() ([]byte, error)
	Deserialize([]byte) error
	NewBackup(dstURI string) (*sqlite.Backup, error)
}

// memdbSeq names the in-memory databases of this process (see memdbURI).
var memdbSeq atomic.Uint64

// memdbURI names a new in-memory database. Unlike ":memory:", every
// connection that opens the name shares it, until the last one closes.
func memdbURI(use string) string {
	return fmt.Sprintf("file:/c8s-allowlist-%s-%d?vfs=memdb", use, memdbSeq.Add(1))
}

// Dump returns the whole database as a SQLite database image, for a replica
// that joins or recovers. VACUUM INTO leaves out free pages (and the deleted
// rows they still hold) and keeps rowids. Two replicas with the same rows may
// still produce different bytes: compare stores by content, not by image.
func (s *Store) Dump() ([]byte, error) {
	ctx := context.Background()
	uri := memdbURI("dump")
	dst, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, err
	}
	defer dst.Close()
	conn, err := dst.Conn(ctx) // keeps the database alive until it is read
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	s.mu.Lock()
	_, err = s.db.Exec("VACUUM INTO ?", uri)
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("dump allowlist: %w", err)
	}
	var image []byte
	err = conn.Raw(func(dc any) error {
		image, err = dc.(imageConn).Serialize()
		return err
	})
	return image, err
}

// Restore replaces the whole database with an image from Dump. The image is
// checked and migrated on a scratch connection first, then copied in with
// the SQLite backup API in one step, so a bad image leaves the store as it
// was.
func (s *Store) Restore(image []byte) error {
	ctx := context.Background()
	scratch, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return err
	}
	defer scratch.Close()
	conn, err := scratch.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Raw(func(dc any) error { return dc.(imageConn).Deserialize(image) }); err != nil {
		return fmt.Errorf("restore allowlist: %w", err)
	}
	var check string
	if err := conn.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil || check != "ok" {
		return fmt.Errorf("restore allowlist: not a sound database image (%s): %v", check, err)
	}
	if err := initDB(ctx, conn); err != nil {
		return fmt.Errorf("restore allowlist: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err = conn.Raw(func(dc any) error {
		b, err := dc.(imageConn).NewBackup(s.uri)
		if err != nil {
			return err
		}
		if _, err := b.Step(-1); err != nil {
			_ = b.Finish()
			return err
		}
		return b.Finish()
	})
	if err != nil {
		return fmt.Errorf("restore allowlist: %w", err)
	}
	s.gen++
	return nil
}
