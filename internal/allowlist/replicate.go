package allowlist

import (
	"errors"
	"fmt"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/internal/replicate"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Committer takes one allowlist mutation: a single CDS applies it, a CDS HA
// replica commits it to the cluster's log first.
type Committer = replicate.Committer[Command, Result]

// Handle is the allowlist as its writers hold it. It is the only way to
// write, so no write path asks which kind of CDS it serves.
type Handle struct {
	store  *Store
	commit Committer
}

// Local is a handle whose mutations apply to the store's own database.
func (s *Store) Local() *Handle {
	return &Handle{
		store:  s,
		commit: replicate.Local[Command, Result](s),
	}
}

// CommittedBy is a handle whose mutations c commits to a CDS HA cluster
// before any replica applies them.
func (s *Store) CommittedBy(c Committer) *Handle {
	return &Handle{
		store:  s,
		commit: c,
	}
}

func (h *Handle) LoadAll() (*pkgallowlist.Allowlist, string, error) {
	return h.store.LoadAll()
}

func (h *Handle) Version() (string, error) {
	return h.store.Version()
}

func (h *Handle) History() ([]HistoryEntry, error) {
	return h.store.History()
}

func (h *Handle) Object(digest string) ([]byte, bool, error) {
	return h.store.Object(digest)
}

func (h *Handle) Signature(digest string) (string, bool, error) {
	return h.store.Signature(digest)
}

func (h *Handle) LoadRoutes() (routes.Envelope, error) {
	return h.store.LoadRoutes()
}

func (h *Handle) Contains(digest types.Digest) (bool, error) {
	return h.store.Contains(digest)
}

func (h *Handle) Generation() uint64 {
	return h.store.Generation()
}

// ErrUnavailable wraps a store that may take the next write: a CDS HA replica
// with no leader or no quorum, or a failing local disk.
var ErrUnavailable = errors.New("allowlist: store unavailable; retry")

// ErrCapacity wraps a write refused because the replicated state is near what
// a snapshot can hold. It clears when the state shrinks.
var ErrCapacity = errors.New("allowlist: replicated state at capacity")

// ErrStoreFull wraps a write the store's volume had no room for. It clears
// when the history is pruned.
var ErrStoreFull = errors.New("allowlist: store is full")

type Op string

const (
	OpSeed          Op = "seed"
	OpReplaceAll    Op = "replace_all"
	OpConsumeToken  Op = "consume_token"
	OpReplaceRoutes Op = "replace_routes"
	OpStartJournal  Op = "start_journal"
	OpPruneHistory  Op = "prune_history"
)

// Command carries everything a replica needs to apply one mutation
// identically, the time it is journaled at included.
type Command struct {
	Op   Op    `json:"op"`
	AtMS int64 `json:"at_ms"`
	// Workloads is the seed (OpSeed).
	Workloads map[string]pkgallowlist.Workload `json:"workloads,omitempty"`
	// Allowlist and Write are the document to serve and what the operator's
	// write carries beside it (OpReplaceAll).
	Allowlist *pkgallowlist.Allowlist `json:"allowlist,omitempty"`
	Write     OperatorWrite           `json:"write"`
	// Token is the operator write token to spend (OpConsumeToken).
	Token string `json:"token,omitempty"`
	// Routes is the signed route manifest to store and RouteDigest the digest
	// of the manifest it replaces (OpReplaceRoutes).
	Routes      *routes.Envelope `json:"routes,omitempty"`
	RouteDigest string           `json:"route_digest,omitempty"`
	// Keep is how many of the newest history entries survive
	// (OpPruneHistory).
	Keep int `json:"keep,omitempty"`
}

type Result struct {
	Added   int `json:"added,omitempty"`
	Retired int `json:"retired,omitempty"`
	httputil.Status
}

// sentinels carries a refusal across the cluster's log, so a caller matches
// the same error at every replica as in a single CDS.
var sentinels = map[string]error{
	"token_reused":         operatorauth.ErrTokenReused,
	"revision_not_greater": ErrRevisionNotGreater,
	"digest_mismatch":      ErrDigestMismatch,
	"version_mismatch":     ErrVersionMismatch,
	fullKind:               ErrStoreFull,
}

const (
	storageKind = "storage"
	fullKind    = "storage_full"
)

// LocalStoreFault reports that applying the command failed in this replica's
// own database (no room left, I/O error, corruption): not an answer the other
// replicas share, and a replica that keeps going after one has lost the
// replicated state.
func (r Result) LocalStoreFault() bool {
	return r.Kind == storageKind || r.Kind == fullKind
}

// IsLocalStoreFault reports a SQLite failure of this replica's own database
// (see Result.LocalStoreFault).
func IsLocalStoreFault(err error) bool {
	_, ok := localStoreFaultKind(err)
	return ok
}

func localStoreFaultKind(err error) (string, bool) {
	code, ok := sqliteCode(err)
	if !ok || refusedByItsContent(code) {
		return "", false
	}
	if code == sqlite3.SQLITE_FULL {
		return fullKind, true
	}
	return storageKind, true
}

// refusedByItsContent reports a SQLite code a command produces at every
// replica alike: a constraint it violates, a value over a fixed limit.
func refusedByItsContent(code int) bool {
	switch code {
	case sqlite3.SQLITE_CONSTRAINT,
		sqlite3.SQLITE_TOOBIG,
		sqlite3.SQLITE_MISMATCH,
		sqlite3.SQLITE_RANGE:
		return true
	}
	return false
}

// sqliteCode is the primary result code of a SQLite error, without the
// extended detail its high bits carry.
func sqliteCode(err error) (int, bool) {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return 0, false
	}
	return se.Code() & 0xff, true
}

// Apply runs one command against the local database. Replicas apply the same
// commands in the same order, so they hold the same store.
func (s *Store) Apply(cmd Command) Result {
	r, err := s.apply(cmd)
	r.Status = statusOf(err)
	return r
}

// statusOf records err for the trip back to the writer.
func statusOf(err error) httputil.Status {
	if kind, ok := localStoreFaultKind(err); ok {
		return httputil.Status{
			Kind:    kind,
			Message: err.Error(),
		}
	}
	return httputil.StatusOf(err, sentinels)
}

func (s *Store) apply(cmd Command) (r Result, err error) {
	if cmd.AtMS <= 0 {
		return r, fmt.Errorf("allowlist command %q carries no time", cmd.Op)
	}
	at := time.UnixMilli(cmd.AtMS)
	switch cmd.Op {
	case OpSeed:
		r.Added, r.Retired, err = s.seedWorkloads(cmd.Workloads, at)
	case OpReplaceAll:
		err = s.replaceAll(cmd.Allowlist, cmd.Write, at)
	case OpConsumeToken:
		err = s.consumeToken(cmd.Token)
	case OpReplaceRoutes:
		if cmd.Routes == nil {
			return r, errors.New("replace_routes without a manifest")
		}
		err = s.replaceRoutes(*cmd.Routes, cmd.RouteDigest)
	case OpStartJournal:
		err = s.startJournal(at)
	case OpPruneHistory:
		err = s.pruneHistory(cmd.Keep)
	default:
		err = fmt.Errorf("unknown allowlist command %q", cmd.Op)
	}
	return r, err
}

// write stamps cmd with the writer's clock, so every store that applies it
// journals the same time.
func (h *Handle) write(cmd Command) (Result, error) {
	cmd.AtMS = time.Now().UnixMilli()
	res, err := h.commit.Commit(cmd)
	if err != nil {
		return Result{}, err
	}
	return res, res.Err(sentinels)
}

// SeedWorkloads seeds the measured configuration's entries (see
// seedWorkloads).
func (h *Handle) SeedWorkloads(workloads map[string]pkgallowlist.Workload) (added, retired int, err error) {
	res, err := h.write(Command{
		Op:        OpSeed,
		Workloads: workloads,
	})
	return res.Added, res.Retired, err
}

// ReplaceAll swaps the whole document for al (see replaceAll). One command,
// so every replica checks the version the write names against the one it
// holds, and none holds the document without its signature.
func (h *Handle) ReplaceAll(al *pkgallowlist.Allowlist, write OperatorWrite) error {
	_, err := h.write(Command{
		Op:        OpReplaceAll,
		Allowlist: al,
		Write:     write,
	})
	return err
}

// ConsumeToken spends an operator write token once (see consumeToken): spent
// at any replica, it is spent at all of them.
func (h *Handle) ConsumeToken(token string) error {
	_, err := h.write(Command{
		Op:    OpConsumeToken,
		Token: token,
	})
	return err
}

// ReplaceRoutes stores a signed route manifest (see replaceRoutes).
func (h *Handle) ReplaceRoutes(env routes.Envelope, ifMatch string) error {
	_, err := h.write(Command{
		Op:          OpReplaceRoutes,
		Routes:      &env,
		RouteDigest: ifMatch,
	})
	return err
}

// StartJournal verifies the history and journals the served document when it
// is not already the head (see startJournal).
func (h *Handle) StartJournal() error {
	_, err := h.write(Command{Op: OpStartJournal})
	return err
}
