package cdsha

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
	"github.com/klauspost/compress/zstd"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// Core is the cluster state every replica agrees on through the Raft log:
// the operator's authority, the replica pin set, and the mesh CA. Nothing
// here is ever written outside the attested replicas, so it needs no
// signature of its own; the log is its history.
type Core struct {
	// Policy is fixed by Genesis and retained by snapshots and recovery.
	Policy         FSMPolicy `json:"policy"`
	ClusterID      string    `json:"cluster_id"`
	Epoch          uint64    `json:"epoch"` // decrees applied
	RootCert       []byte    `json:"root_cert,omitempty"`
	Measurements   []string  `json:"measurements,omitempty"` // replica pin set, sorted lowercase hex
	OperatorPubKey []byte    `json:"operator_pubkey"`        // PKIX DER; nil means decrees are rejected
	AppliedDecrees []string  `json:"applied_decrees,omitempty"`
	// GenesisAtMS is when the cluster was born. Single-use operator tokens
	// issued before it are refused: no replica can know whether they were
	// spent in an earlier life of the cluster.
	GenesisAtMS int64 `json:"genesis_at_ms,omitempty"`
	// Format is the encoding every replica writes (see Format). 0 is baseFormat.
	Format uint32 `json:"format,omitempty"`
	// Seats is the voter seat count set by a SetVoters decree; 0 keeps the
	// launch configuration's.
	Seats int `json:"seats,omitempty"`
	// PinsDecree is the signed decree that set Measurements, when it named
	// their images: what clients outside the group pin CDS to (/ha/pins).
	PinsDecree *SignedDecree `json:"pins_decree,omitempty"`
}

// Joined reports whether the cluster has a mesh CA (Genesis applied).
func (c Core) Joined() bool { return len(c.RootCert) > 0 }

// Pins reports whether measurement is in the replica pin set.
func (c Core) Pins(measurement string) bool { return slices.Contains(c.Measurements, measurement) }

func (c Core) clone() Core {
	c.RootCert = slices.Clone(c.RootCert)
	c.Measurements = slices.Clone(c.Measurements)
	c.OperatorPubKey = slices.Clone(c.OperatorPubKey)
	c.AppliedDecrees = slices.Clone(c.AppliedDecrees)
	return c
}

// caFromDER rebuilds the mesh CA from its certificate and PKCS#8 key, and
// checks the two belong together.
func caFromDER(certDER, keyDER []byte) (*issuer.CA, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("mesh CA certificate: %w", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("mesh CA key: %w", err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("mesh CA key is not ECDSA")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("mesh CA key does not match its certificate")
	}
	return &issuer.CA{Cert: cert, Key: key}, nil
}

// EntryKind names what a log entry changes.
type EntryKind string

// The log entry kinds.
const (
	KindAllowlist EntryKind = "allowlist"
	KindSecret    EntryKind = "secret"
	KindBinding   EntryKind = "binding"
	KindDecree    EntryKind = "decree"
	KindRestore   EntryKind = "restore"
	// KindRenewCA replaces the mesh CA certificate with one renewed under the
	// same key.
	KindRenewCA EntryKind = "renew_ca"
)

// Entry is one Raft log entry. Exactly one payload is set.
type Entry struct {
	Kind EntryKind `json:"kind"`
	// Format is the oldest format that can apply the entry (0 is baseFormat).
	Format    uint32                 `json:"format,omitempty"`
	SetFormat uint32                 `json:"set_format,omitempty"` // KindFormat
	Allowlist *allowlist.Command     `json:"allowlist,omitempty"`
	Secret    *secrets.Command       `json:"secret,omitempty"`
	Binding   *sandboxledger.Command `json:"binding,omitempty"`
	Decree    *DecreeEntry           `json:"decree,omitempty"`
	Restore   *RestoreEntry          `json:"restore,omitempty"`
	RenewCA   *RenewCAEntry          `json:"renew_ca,omitempty"`
}

// RenewCAEntry carries a mesh CA certificate the leader renewed under the
// cluster's key. Every replica checks it (issuer.RenewalOf) before adopting
// it, so the group serves one certificate and running workloads keep their
// trust anchor: the key, subject and key identifier do not change.
type RenewCAEntry struct {
	RootCert []byte `json:"root_cert"`
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
	Policy   FSMPolicy    `json:"policy"` // Genesis only
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
	// decrees is the record of applied decrees (newest last, at most
	// maxDecreeRecord): the audit trail an operator
	// or user reads over the attested channel (GET /ha/decrees), where the
	// decree objects in Kubernetes are only the host's word.
	decrees []DecreeRecord

	// readable is the newest format this replica reads; stuck is set once it
	// met an entry it could not apply, and keeps it from serving.
	readable uint32
	stuck    atomic.Pointer[string]
	stuckAt  atomic.Int64 // unix nanoseconds when stuck was set

	// applyDelay is a test seam (set only from tests, zero otherwise): it
	// slows every command apply, as a slow local disk does.
	applyDelay atomic.Int64

	// base caches the header size of core and decrees for the admission
	// cap (snapshotEstimate); f.mu guards it.
	base headerBase
	// measure is the last snapshot this replica encoded, for the admission
	// cap's compressed estimate.
	measure atomic.Pointer[sizeMeasure]
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

// stuckFor is how long ago the replica got stuck, or 0 if it is not.
func (f *FSM) stuckFor() time.Duration {
	if at := f.stuckAt.Load(); at != 0 {
		return time.Since(time.Unix(0, at))
	}
	return 0
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
	if d := f.applyDelay.Load(); d > 0 {
		time.Sleep(time.Duration(d))
	}
	var e Entry
	if err := json.Unmarshal(l.Data, &e); err != nil {
		return f.stop(fmt.Errorf("decode log entry %d: %w", l.Index, err))
	}
	if cmp.Or(e.Format, baseFormat) > f.readable {
		return f.stop(fmt.Errorf("%w: entry %d needs format %d, this replica reads up to %d", ErrNewerFormat, l.Index, e.Format, f.readable))
	}
	res := f.apply(e)
	if err, ok := res.(error); ok && errors.Is(err, errMalformed) {
		return f.stop(fmt.Errorf("log entry %d: %w", l.Index, err))
	}
	// The entry is committed, and replicas whose disks took it hold it. One
	// that could not write it here must not mark it applied and serve on.
	if r, ok := res.(allowlist.Result); ok && r.LocalStoreFault() {
		return f.stop(fmt.Errorf("log entry %d: local allowlist store: %w", l.Index, r.Error()))
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
	if f.stuck.CompareAndSwap(nil, &msg) {
		f.stuckAt.Store(time.Now().UnixNano())
		slog.Error("cds-ha: this replica can no longer follow the log; it stops serving and exits to rejoin", "reason", msg)
	}
	return err
}

func (f *FSM) apply(e Entry) any {
	// Only Genesis and backup restore may establish the initial policy.
	// They validate their incoming policy before replacing any state.
	cur := f.Core()
	initial := !cur.Joined() && cur.Policy == (FSMPolicy{})
	establishing := initial && ((e.Kind == KindDecree && e.Decree != nil && e.Decree.Decree.Decree.Kind == Genesis) || (e.Kind == KindRestore && e.Restore != nil))
	if !establishing {
		if err := f.ValidatePolicy(cur.Policy); err != nil {
			return f.stop(err)
		}
	}
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
	case e.Kind == KindRenewCA && e.RenewCA != nil:
		return f.applyRenewCA(*e.RenewCA)
	}
	return fmt.Errorf("%w of kind %q", errMalformed, e.Kind)
}

func (f *FSM) applyDecree(de DecreeEntry) DecreeResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	if de.Decree.Decree.Kind == Genesis {
		if err := f.ValidatePolicy(de.Policy); err != nil {
			err = f.stop(err)
			return DecreeResult{Epoch: f.core.Epoch, Err: err.Error()}
		}
	}
	next, ca, err := nextCore(f.core, de)
	if err != nil {
		return DecreeResult{Epoch: f.core.Epoch, Err: err.Error()}
	}
	f.record(de.Decree, de.AtMS, next.Epoch)
	f.core = next
	if ca != nil {
		f.ca = ca
	}
	return DecreeResult{Epoch: next.Epoch}
}

// DecreeRecord is one applied decree: what the operator signed, when the
// leader applied it, and the epoch it produced.
type DecreeRecord struct {
	Decree SignedDecree `json:"decree"`
	AtMS   int64        `json:"at_ms"`
	Epoch  uint64       `json:"epoch"`
}

// maxDecreeRecord bounds the record; older decrees fall off the front.
const maxDecreeRecord = 256

// record appends to the decree record (f.mu held).
func (f *FSM) record(sd SignedDecree, atMS int64, epoch uint64) {
	f.decrees = append(f.decrees, DecreeRecord{Decree: sd, AtMS: atMS, Epoch: epoch})
	if over := len(f.decrees) - maxDecreeRecord; over > 0 {
		f.decrees = slices.Clone(f.decrees[over:])
	}
}

// Decrees is a copy of the decree record, oldest first.
func (f *FSM) Decrees() []DecreeRecord {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return slices.Clone(f.decrees)
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
	sn, err := decodeSnapshot(bytes.NewReader(re.Snapshot), f.readable, false)
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
	if sn.Core.Epoch == ^uint64(0) {
		return fail(errors.New("snapshot epoch overflows on restore"))
	}
	sn.Core.Epoch++
	sn.Core.AppliedDecrees = append(sn.Core.AppliedDecrees, re.Decree.Decree.IntentID)
	if err := f.restore(sn); err != nil {
		return fail(err)
	}
	f.mu.Lock()
	f.record(re.Decree, re.AtMS, sn.Core.Epoch)
	f.mu.Unlock()
	return DecreeResult{Epoch: sn.Core.Epoch}
}

// nextCore is the state after decree entry de, or why de does not apply.
func nextCore(cur Core, de DecreeEntry) (Core, *issuer.CA, error) {
	if err := CheckDecree(de.Decree, cur, time.UnixMilli(de.AtMS)); err != nil {
		return Core{}, nil, err
	}
	if cur.Epoch == ^uint64(0) {
		return Core{}, nil, errors.New("epoch overflows on decree")
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
		if err := de.Policy.Validate(); err != nil {
			return Core{}, nil, err
		}
		next.Policy = de.Policy
		next.Format = Format
		pins := normalizePins(de.Pins)
		if len(pins) == 0 {
			return Core{}, nil, errors.New("genesis without the bootstrap replica's pins")
		}
		next.Measurements = pins
		next.GenesisAtMS = de.AtMS
	case SetVoters:
		next.Seats = d.Voters
	case UpdateMeasurements, RotateKey:
		if len(d.Measurements) > 0 {
			next.Measurements = slices.Clone(d.Measurements)
			// A set without images leaves clients outside the group on
			// the last one they were told; they cannot pin a bare hash.
			next.PinsDecree = nil
			if len(d.Images) > 0 {
				sd := de.Decree
				next.PinsDecree = &sd
			}
		}
	}
	next.Epoch++
	next.AppliedDecrees = append(next.AppliedDecrees, d.IntentID)
	return next, ca, nil
}

// snapshot is the whole replicated state.
type snapshot struct {
	// Index is the log index the snapshot was taken at.
	Index uint64 `json:"index,omitempty"`
	// Format is the encoding of the snapshot (0 is baseFormat).
	Format uint32 `json:"format,omitempty"`
	// Decrees is the decree record.
	Decrees []DecreeRecord `json:"decrees,omitempty"`
	Core    Core           `json:"core"`
	Key     []byte         `json:"key,omitempty"`
	// Allowlist is the allowlist database image (allowlist.Store.Dump). It
	// follows the header line as raw bytes, not inside it.
	Allowlist []byte                  `json:"-"`
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
	if reason := f.Stuck(); reason != "" {
		return nil, fmt.Errorf("cds-ha: cannot snapshot stopped FSM: %s", reason)
	}

	f.mu.RLock()
	sn := snapshot{Index: f.applied.Load(), Core: f.core.clone(), Decrees: slices.Clone(f.decrees)}
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
	// Raft calls Snapshot between applies, so the estimate is of this state.
	decoded := int64(-1)
	if header, image, err := f.snapshotEstimate(); err == nil {
		decoded = header + image
	}
	return &fsmSnapshot{sn: sn, fsm: f, decoded: decoded}, nil
}

// Restore implements raft.FSM: a joining replica takes the leader's state.
func (f *FSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	sn, err := decodeSnapshot(rc, f.readable, false)
	if err != nil {
		return err
	}
	// Raft installs a snapshot the leader sends without comparing it with
	// what this replica already applied. A delayed one (from a replication
	// stream that outlived the member's removal and re-addition) would roll
	// a serving replica back; the error keeps the state, and the leader
	// sends the log instead.
	if applied := f.applied.Load(); sn.Index < applied {
		return fmt.Errorf("%w: snapshot at index %d, applied %d", ErrStaleSnapshot, sn.Index, applied)
	}
	if err := f.restore(sn); err != nil {
		return err
	}
	f.applied.Store(sn.Index)
	return nil
}

// ErrStaleSnapshot refuses a snapshot older than the state already applied.
var ErrStaleSnapshot = errors.New("cds-ha: refusing a snapshot older than the applied state")

// A snapshot is zstd-compressed: a JSON header line with everything but the
// allowlist, then the allowlist database image as raw bytes. The allowlist
// history keeps a whole document per version, so it is most of the state;
// the zstd window reaches back past the previous version, so each near-copy
// of a document is stored as a reference.
func encodeSnapshot(w io.Writer, sn snapshot) error {
	header, err := json.Marshal(sn)
	if err != nil {
		return err
	}
	if len(header)+1 > maxSnapshotHeader || len(sn.Allowlist) > maxSnapshotImage {
		return errSnapshotTooLarge
	}
	zw, err := zstd.NewWriter(&snapshotLimitWriter{w: w, remaining: MaxSnapshotBytes}, zstd.WithWindowSize(snapshotWindow), zstd.WithEncoderConcurrency(1))
	if err != nil {
		return err
	}
	defer zw.Close()
	if _, err := zw.Write(append(header, '\n')); err != nil {
		return err
	}
	if _, err := zw.Write(sn.Allowlist); err != nil {
		return err
	}
	return zw.Close()
}

// errSnapshotTooLarge is a state too large to snapshot (see admitTotalBytes).
var errSnapshotTooLarge = errors.New("snapshot exceeds supported decoded size")

// snapshotWindow is the zstd window of a snapshot: enough to reach
// the previous version of allowlist documents of several MiB, small enough
// to keep encoder and decoder memory modest.
const snapshotWindow = 16 << 20

// Operational limits bound allocations before JSON/SQLite validation. Creation
// uses the same limits as restore. SQLite restore may hold several image copies.
const maxSnapshotHeader = 16 << 20
const maxSnapshotImage = 256 << 20

// MaxSnapshotBytes bounds compressed snapshots, including backups and transport.
const MaxSnapshotBytes = 128 << 20

// decodeSnapshot reads a snapshot in a format from baseFormat to readable.
// With headOnly it stops after the header line, without the allowlist.
func decodeSnapshot(r io.Reader, readable uint32, headOnly bool) (snapshot, error) {
	compressed := &io.LimitedReader{R: r, N: MaxSnapshotBytes + 1}
	d, err := zstd.NewReader(compressed, zstd.WithDecoderMaxWindow(snapshotWindow), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	defer d.Close()
	sn, err := decodeSnapshotBody(d, readable, headOnly, maxSnapshotHeader, maxSnapshotImage)
	if compressed.N <= 0 {
		return snapshot{}, errors.New("snapshot exceeds compressed size limit")
	}
	return sn, err
}

func decodeSnapshotBody(r io.Reader, readable uint32, headOnly bool, headerLimit, imageLimit int64) (snapshot, error) {
	// Read the newline-delimited header through a limit before unmarshalling;
	// json.Decoder alone can allocate arbitrarily before returning a value.
	br := bufio.NewReader(io.LimitReader(r, headerLimit+1))
	header, err := br.ReadBytes('\n')
	if err != nil || int64(len(header)) > headerLimit {
		return snapshot{}, errors.New("decode snapshot: missing or oversized header")
	}
	var sn snapshot
	if err := json.Unmarshal(header, &sn); err != nil {
		return snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	switch v, c := cmp.Or(sn.Format, baseFormat), sn.Core.format(); {
	case v > readable || c > readable:
		return snapshot{}, fmt.Errorf("%w: snapshot format %d, cluster format %d, this replica reads up to %d", ErrNewerFormat, v, c, readable)
	case v < baseFormat || c < baseFormat:
		return snapshot{}, fmt.Errorf("cds-ha: snapshot format %d, cluster format %d: older than this release reads (%d)", v, c, baseFormat)
	}
	if headOnly {
		return sn, nil
	}
	// Recover bytes prefetched through the header limit, then the original stream.
	rest := io.MultiReader(br, r)
	if sn.Allowlist, err = io.ReadAll(io.LimitReader(rest, imageLimit+1)); err != nil {
		return snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	if int64(len(sn.Allowlist)) > imageLimit {
		return snapshot{}, errors.New("decode snapshot: oversized allowlist image")
	}
	return sn, nil
}

func (f *FSM) restore(sn snapshot) error {
	// Check before touching any store. In particular, never derive a missing
	// snapshot policy from this process's launch configuration.
	if err := f.ValidatePolicy(sn.Core.Policy); err != nil {
		return err
	}
	cur := f.Core()
	if cur.Policy != (FSMPolicy{}) && cur.Policy != sn.Core.Policy {
		return fmt.Errorf("%w: snapshot changes established policy", ErrPolicy)
	}
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
	f.core, f.ca, f.decrees = sn.Core, ca, sn.Decrees
	f.mu.Unlock()
	return nil
}

type fsmSnapshot struct {
	sn snapshot
	// fsm and decoded (its estimate of this state, or -1) record the
	// compressed size once encoded, for the admission cap.
	fsm     *FSM
	decoded int64
}

func (s *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	cw := &countWriter{w: sink}
	if err := encodeSnapshot(cw, s.sn); err != nil {
		_ = sink.Cancel()
		return err
	}
	if s.fsm != nil && s.decoded >= 0 {
		s.fsm.measure.Store(&sizeMeasure{decoded: s.decoded, compressed: cw.n})
	}
	return sink.Close()
}

func (s *fsmSnapshot) Release() { s.sn = snapshot{} }

// applyRenewCA adopts a renewed mesh CA certificate, or returns why not. The
// checks read only the entry and the replicated state, so every replica
// decides alike.
func (f *FSM) applyRenewCA(re RenewCAEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ca == nil {
		return errors.New("cds-ha: no mesh CA to renew")
	}
	cert, err := x509.ParseCertificate(re.RootCert)
	if err != nil {
		return fmt.Errorf("renewed mesh CA certificate: %w", err)
	}
	if err := issuer.RenewalOf(f.ca.Cert, cert); err != nil {
		return err
	}
	f.core.RootCert = slices.Clone(re.RootCert)
	f.ca = &issuer.CA{Cert: cert, Key: f.ca.Key}
	return nil
}

type snapshotLimitWriter struct {
	w         io.Writer
	remaining int
}

func (w *snapshotLimitWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, errors.New("snapshot exceeds compressed size limit")
	}
	n, err := w.w.Write(p)
	w.remaining -= n
	return n, err
}
