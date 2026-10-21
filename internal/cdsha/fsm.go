package cdsha

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// EntryKind names what a log entry changes.
type EntryKind string

// The log entry kinds.
const (
	KindAllowlist EntryKind = "allowlist"
	KindSecret    EntryKind = "secret"
	KindBinding   EntryKind = "binding"
	KindDecree    EntryKind = "decree"
	KindRestore   EntryKind = "restore"
)

// Entry is one Raft log entry. Exactly one payload is set.
type Entry struct {
	Kind EntryKind `json:"kind"`
	// Format is the oldest format that can apply the entry (0 is 1).
	Format    uint32                 `json:"format,omitempty"`
	SetFormat uint32                 `json:"set_format,omitempty"` // KindFormat
	Allowlist *allowlist.Command     `json:"allowlist,omitempty"`
	Secret    *secrets.Command       `json:"secret,omitempty"`
	Binding   *sandboxledger.Command `json:"binding,omitempty"`
	Decree    *DecreeEntry           `json:"decree,omitempty"`
	Restore   *RestoreEntry          `json:"restore,omitempty"`
}

// RestoreEntry restores a backup into a replica that holds no cluster. It is
// the first entry of a restored cluster, so every replica that joins applies
// the same state.
type RestoreEntry struct {
	Decree   SignedDecree `json:"decree"`
	AtMS     int64        `json:"at_ms"`
	Snapshot []byte       `json:"snapshot"`
}

// DecreeEntry applies one operator decree. The leader stamps the time and,
// for Genesis and RotateKey, the new mesh CA, so every replica applies the
// same result; each replica still checks the operator's signature itself.
type DecreeEntry struct {
	Decree   SignedDecree `json:"decree"`
	AtMS     int64        `json:"at_ms"`
	Pins     []string     `json:"pins,omitempty"`      // Genesis: the bootstrap replica's baked pins
	RootCert []byte       `json:"root_cert,omitempty"` // Genesis, RotateKey
	Key      []byte       `json:"key,omitempty"`       // PKCS#8; Genesis, RotateKey
}

// DecreeResult is what applying a decree returned.
type DecreeResult struct {
	Epoch uint64 `json:"epoch"`
	Err   string `json:"err,omitempty"`
}

// FSM is the replicated state: Core and the mesh CA, the allowlist, the
// secrets and the sandbox ledger. Raft applies entries one at a time.
type FSM struct {
	mu   sync.RWMutex
	core Core
	ca   *issuer.CA

	allowlist *allowlist.Store
	secrets   *secrets.MemoryStore
	ledger    *sandboxledger.Ledger

	applied atomic.Uint64
	// readable is the newest format this replica reads; stuck is set once it
	// met an entry it could not apply, and keeps it from serving.
	readable uint32
	stuck    atomic.Pointer[string]
}

// NewFSM builds the state machine over the replica's local stores. pre is
// the pre-Genesis state from the replica's launch configuration.
func NewFSM(pre Core, al *allowlist.Store, sec *secrets.MemoryStore, led *sandboxledger.Ledger) *FSM {
	return &FSM{core: pre, allowlist: al, secrets: sec, ledger: led, readable: Format}
}

// Stuck is why this replica stopped applying the log, or "".
func (f *FSM) Stuck() string {
	if p := f.stuck.Load(); p != nil {
		return *p
	}
	return ""
}

// Core returns a copy of the agreed cluster state.
func (f *FSM) Core() Core {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.core.clone()
}

// CA returns the mesh CA, or nil before Genesis.
func (f *FSM) CA() *issuer.CA {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.ca
}

// AppliedIndex is the last log index this replica applied.
func (f *FSM) AppliedIndex() uint64 { return f.applied.Load() }

// Apply implements raft.FSM.
func (f *FSM) Apply(l *raft.Log) any {
	defer f.applied.Store(l.Index)
	if l.Type != raft.LogCommand {
		return nil
	}
	var e Entry
	if err := json.Unmarshal(l.Data, &e); err != nil {
		return f.stop(fmt.Errorf("decode log entry %d: %w", l.Index, err))
	}
	if formatOr1(e.Format) > f.readable {
		return f.stop(fmt.Errorf("%w: entry %d needs format %d, this replica reads up to %d", ErrNewerFormat, l.Index, e.Format, f.readable))
	}
	res := f.apply(e)
	if err, ok := res.(error); ok && errors.Is(err, errMalformed) {
		return f.stop(fmt.Errorf("log entry %d: %w", l.Index, err))
	}
	return res
}

// errMalformed is an entry this replica does not understand.
var errMalformed = errors.New("malformed log entry")

// stop records that this replica can no longer follow the log. Raft treats
// Apply's result as the entry's answer and moves on, so a replica that
// skipped an entry would serve state the rest of the group does not have.
// It stops serving instead, and is replaced by one that reads the log.
func (f *FSM) stop(err error) error {
	msg := err.Error()
	f.stuck.CompareAndSwap(nil, &msg)
	return err
}

func (f *FSM) apply(e Entry) any {
	switch {
	case e.Kind == KindFormat && e.SetFormat != 0:
		if err := f.applyFormat(e.SetFormat); err != nil {
			return f.stop(err)
		}
		return nil
	case e.Kind == KindAllowlist && e.Allowlist != nil:
		return f.allowlist.Apply(*e.Allowlist)
	case e.Kind == KindSecret && e.Secret != nil:
		return f.secrets.Apply(*e.Secret)
	case e.Kind == KindBinding && e.Binding != nil:
		return f.ledger.Apply(*e.Binding)
	case e.Kind == KindDecree && e.Decree != nil:
		return f.applyDecree(*e.Decree)
	case e.Kind == KindRestore && e.Restore != nil:
		return f.applyRestore(*e.Restore)
	}
	return fmt.Errorf("%w of kind %q", errMalformed, e.Kind)
}

func (f *FSM) applyDecree(de DecreeEntry) DecreeResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	next, ca, err := nextCore(f.core, de)
	if err != nil {
		return DecreeResult{Epoch: f.core.Epoch, Err: err.Error()}
	}
	f.core = next
	if ca != nil {
		f.ca = ca
	}
	return DecreeResult{Epoch: next.Epoch}
}

// applyRestore loads an operator backup, checked against the decree that
// names it, into a replica that holds no cluster.
func (f *FSM) applyRestore(re RestoreEntry) DecreeResult {
	cur := f.Core()
	fail := func(err error) DecreeResult { return DecreeResult{Epoch: cur.Epoch, Err: err.Error()} }
	if re.Decree.Decree.Kind != Restore {
		return fail(errors.New("restore entry without a Restore decree"))
	}
	if err := CheckDecree(re.Decree, cur, time.UnixMilli(re.AtMS)); err != nil {
		return fail(err)
	}
	if SnapshotSHA256(re.Snapshot) != re.Decree.Decree.SnapshotSHA256 {
		return fail(errors.New("snapshot differs from the one the decree names"))
	}
	sn, err := decodeSnapshot(bytes.NewReader(re.Snapshot), f.readable)
	if err != nil {
		return fail(err)
	}
	switch {
	case sn.Core.ClusterID != cur.ClusterID:
		return fail(fmt.Errorf("snapshot is of cluster %q", sn.Core.ClusterID))
	case !bytes.Equal(sn.Core.OperatorPubKey, cur.OperatorPubKey):
		return fail(errors.New("snapshot names another operator key"))
	case !sn.Core.Joined():
		return fail(errors.New("snapshot holds no mesh CA"))
	}
	sn.Core.Epoch++
	sn.Core.AppliedDecrees = append(sn.Core.AppliedDecrees, re.Decree.Decree.IntentID)
	if err := f.restore(sn); err != nil {
		return fail(err)
	}
	return DecreeResult{Epoch: sn.Core.Epoch}
}

// nextCore is the state after decree entry de, or why de does not apply.
func nextCore(cur Core, de DecreeEntry) (Core, *issuer.CA, error) {
	if err := CheckDecree(de.Decree, cur, time.UnixMilli(de.AtMS)); err != nil {
		return Core{}, nil, err
	}
	d := de.Decree.Decree
	next := cur.clone()
	var ca *issuer.CA
	if d.Kind == Genesis || d.Kind == RotateKey {
		var err error
		if ca, err = caFromDER(de.RootCert, de.Key); err != nil {
			return Core{}, nil, err
		}
		next.RootCert = slices.Clone(de.RootCert)
	}
	switch d.Kind {
	case Genesis:
		pins := normalizePins(de.Pins)
		if len(pins) == 0 {
			return Core{}, nil, errors.New("genesis without the bootstrap replica's pins")
		}
		next.Measurements = pins
		next.GenesisAtMS = de.AtMS
	case UpdateMeasurements, RotateKey:
		if len(d.Measurements) > 0 {
			next.Measurements = slices.Clone(d.Measurements)
		}
	}
	next.Epoch++
	next.AppliedDecrees = append(next.AppliedDecrees, d.IntentID)
	return next, ca, nil
}

// snapshot is the whole replicated state.
type snapshot struct {
	// Index is the log index the snapshot was taken at (0 in snapshots and
	// backups from before it was recorded).
	Index uint64 `json:"index,omitempty"`
	// Format is the encoding of the snapshot (0 is 1).
	Format    uint32                  `json:"format,omitempty"`
	Core      Core                    `json:"core"`
	Key       []byte                  `json:"key,omitempty"`
	Allowlist allowlist.Snapshot      `json:"allowlist"`
	Secrets   []secrets.SnapshotEntry `json:"secrets"`
	Bindings  []sandboxledger.Binding `json:"bindings"`
}

// StoreConfiguration implements raft.ConfigurationStore. The state machine
// keeps no membership of its own; seeing configuration entries is what lets
// its applied index pass them, without which Raft refuses to snapshot (so
// backups stall) after a membership change until the next write.
func (f *FSM) StoreConfiguration(index uint64, _ raft.Configuration) {
	f.applied.Store(index)
}

var _ raft.ConfigurationStore = (*FSM)(nil)

// Snapshot implements raft.FSM. Raft calls it between applies, so the
// state captured here is one point of the log. Encoding happens in Persist,
// as a stream, so the state is held once, not once per encoding stage.
func (f *FSM) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	sn := snapshot{Index: f.applied.Load(), Core: f.core.clone()}
	sn.Format = sn.Core.format() // what every member reads, not what this one could write
	if f.ca != nil {
		key, err := x509.MarshalPKCS8PrivateKey(f.ca.Key)
		if err != nil {
			f.mu.RUnlock()
			return nil, err
		}
		sn.Key = key
	}
	f.mu.RUnlock()
	al, err := f.allowlist.Dump()
	if err != nil {
		return nil, err
	}
	sn.Allowlist, sn.Secrets, sn.Bindings = al, f.secrets.Dump(), f.ledger.Dump()
	return &fsmSnapshot{sn: sn}, nil
}

// Restore implements raft.FSM: a joining replica takes the leader's state.
func (f *FSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	sn, err := decodeSnapshot(rc, f.readable)
	if err != nil {
		return err
	}
	// Raft installs a snapshot the leader sends without comparing it with
	// what this replica already applied. A delayed one (from a replication
	// stream that outlived the member's removal and re-addition) would roll
	// a serving replica back; the error keeps the state, and the leader
	// sends the log instead.
	if applied := f.applied.Load(); sn.Index != 0 && sn.Index < applied {
		return fmt.Errorf("%w: snapshot at index %d, applied %d", ErrStaleSnapshot, sn.Index, applied)
	}
	if err := f.restore(sn); err != nil {
		return err
	}
	if sn.Index != 0 {
		f.applied.Store(sn.Index)
	}
	return nil
}

// ErrStaleSnapshot refuses a snapshot older than the state already applied.
var ErrStaleSnapshot = errors.New("cds-ha: refusing a snapshot older than the applied state")

// A snapshot is gzip over JSON lines: a header line with everything but the
// allowlist tables, then one line per allowlist row (a one-row
// allowlist.Snapshot, which keeps BLOB columns apart). The allowlist history
// keeps a whole document per version, so it is most of the state; lines keep
// encoding and decoding to one row at a time. A snapshot that does not start
// with the gzip magic is the earlier single JSON object (older backups).
func encodeSnapshot(w io.Writer, sn snapshot) error {
	zw, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(zw)
	head := sn
	head.Allowlist = nil
	if err := enc.Encode(head); err != nil {
		return err
	}
	tables := slices.Sorted(maps.Keys(sn.Allowlist))
	for _, t := range tables {
		for _, row := range sn.Allowlist[t] {
			if err := enc.Encode(allowlist.Snapshot{t: {row}}); err != nil {
				return err
			}
		}
	}
	return zw.Close()
}

func decodeSnapshot(r io.Reader, readable uint32) (snapshot, error) {
	sn, err := decodeSnapshotAny(r)
	if err == nil && (formatOr1(sn.Format) > readable || sn.Core.format() > readable) {
		return snapshot{}, fmt.Errorf("%w: snapshot format %d, cluster format %d, this replica reads up to %d",
			ErrNewerFormat, formatOr1(sn.Format), sn.Core.format(), readable)
	}
	return sn, err
}

func decodeSnapshotAny(r io.Reader) (snapshot, error) {
	var sn snapshot
	br := bufio.NewReader(r)
	if magic, _ := br.Peek(2); len(magic) < 2 || magic[0] != 0x1f || magic[1] != 0x8b {
		if err := json.NewDecoder(br).Decode(&sn); err != nil {
			return snapshot{}, fmt.Errorf("decode snapshot: %w", err)
		}
		return sn, nil
	}
	zr, err := gzip.NewReader(br)
	if err != nil {
		return snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	dec := json.NewDecoder(zr)
	if err := dec.Decode(&sn); err != nil {
		return snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	sn.Allowlist = allowlist.Snapshot{}
	for {
		var rows allowlist.Snapshot
		err := dec.Decode(&rows)
		if errors.Is(err, io.EOF) {
			return sn, nil
		}
		if err != nil {
			return snapshot{}, fmt.Errorf("decode snapshot: %w", err)
		}
		for t, rs := range rows {
			sn.Allowlist[t] = append(sn.Allowlist[t], rs...)
		}
	}
}

func (f *FSM) restore(sn snapshot) error {
	var ca *issuer.CA
	if sn.Core.Joined() {
		var err error
		if ca, err = caFromDER(sn.Core.RootCert, sn.Key); err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
	}
	if err := f.allowlist.Restore(sn.Allowlist); err != nil {
		return fmt.Errorf("snapshot allowlist: %w", err)
	}
	f.secrets.Restore(sn.Secrets)
	f.ledger.Restore(sn.Bindings)
	f.mu.Lock()
	f.core, f.ca = sn.Core, ca
	f.mu.Unlock()
	return nil
}

type fsmSnapshot struct{ sn snapshot }

func (s *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	if err := encodeSnapshot(sink, s.sn); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s *fsmSnapshot) Release() { s.sn = snapshot{} }
