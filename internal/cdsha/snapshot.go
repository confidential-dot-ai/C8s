// A snapshot is the whole replicated state at one log index: what a replica
// that joins takes from a peer, and what lets a leader compact its log. It
// travels as one zstd stream, a JSON header line and then the allowlist
// database image as raw bytes. The allowlist history keeps a whole document
// per version, so it is most of the state, and the window reaches back past
// the previous version, so each near-copy of a document costs a reference.
//
// Nothing in a snapshot is signed: whoever sends it chose every byte. A
// replica installs one only after it has checked the cluster it names, the
// launch file it was taken under, its own policy, the digest of its database
// image, and the state this replica already applied.

package cdsha

import (
	"bufio"
	"cmp"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// snapshot is a snapshot's header and the database image that follows it.
type snapshot struct {
	// Index is the log index the state was captured at. The cluster's agreed
	// encoding, in ClusterState, is the snapshot's own.
	Index        uint64       `json:"index"`
	ClusterState ClusterState `json:"core"`
	// Decrees is the record of applied decrees, oldest first.
	Decrees []DecreeRecord `json:"decrees,omitempty"`
	// MeshCAKey is the mesh CA's private key in PKCS#8.
	MeshCAKey   []byte                  `json:"mesh_ca_key,omitempty"`
	Secrets     []secrets.SnapshotEntry `json:"secrets,omitempty"`
	Bindings    []sandboxledger.Binding `json:"bindings,omitempty"`
	ImageSHA256 string                  `json:"image_sha256"`
	// Image is the allowlist database image, which follows the header line.
	Image []byte `json:"-"`
	// Chain is where the chain of the replica that captured the state stood
	// at Index (digest.go).
	Chain   Point   `json:"chain"`
	Digests Digests `json:"digests"`
}

// Snapshot is the replicated state captured at one log index. Capturing it
// and encoding it are two steps: the state is captured between two log
// entries, and encoded afterwards, off the goroutine that applies the log.
type Snapshot struct {
	sn snapshot
}

// Index is the log index the state was captured at.
func (s *Snapshot) Index() uint64 {
	return s.sn.Index
}

// Snapshot captures the whole replicated state at the applied index. The
// state must stand still while it is captured, so a capture an entry applied
// during is refused.
func (f *FSM) Snapshot() (*Snapshot, error) {
	if reason := f.Stuck(); reason != "" {
		return nil, fmt.Errorf("cds-ha: this replica stopped applying the log, so what it holds is no snapshot of the cluster: %s", reason)
	}
	sn, err := f.state()
	if err != nil {
		return nil, err
	}
	sn.Chain = f.dig.latest()
	image, err := f.allowlist.Dump()
	if err != nil {
		return nil, err
	}
	sn.Image = image
	sn.ImageSHA256 = imageDigest(image)
	if sn.Digests, err = f.capturedDigests(sn); err != nil {
		return nil, err
	}
	// Every part of the capture is read above, so one check covers them all.
	if err := f.stillAt(sn.Index); err != nil {
		return nil, err
	}
	return &Snapshot{sn: sn}, nil
}

type storeContent struct {
	allowlist digest
	secrets   digest
	bindings  digest
}

// Read from the content the capture carries. Stores that hold other content
// than they applied stop this replica, so state that changed under it reaches
// no replica that joins.
func (f *FSM) capturedDigests(sn snapshot) (Digests, error) {
	scanned, kept, err := f.allowlist.ScanDigest()
	if err != nil {
		return Digests{}, err
	}
	captured := storeContent{
		allowlist: digest(scanned),
		secrets:   digest(secrets.DigestOf(sn.Secrets)),
		bindings:  digest(sandboxledger.DigestOf(sn.Bindings)),
	}
	applied := storeContent{
		allowlist: digest(kept),
		secrets:   digest(f.secrets.Digest()),
		bindings:  digest(f.ledger.Digest()),
	}
	if captured != applied {
		return Digests{}, f.stopLocal(fmt.Errorf("the stores of this replica hold other content at log index %d than they applied: they hold %+v, and they applied %+v", sn.Index, captured, applied))
	}
	core, err := coreDigest(sn.ClusterState, sn.MeshCAKey, sn.Decrees)
	if err != nil {
		return Digests{}, err
	}
	return digestsOf(core, captured.allowlist, captured.secrets, captured.bindings), nil
}

// stillAt refuses a capture the log moved under: the header is read before
// the database image, so a snapshot of two indexes would hand a replica a
// state no log index produced. An entry applied, or still applying, between
// the two moves the applied index or leaves the state machine inside Apply.
func (f *FSM) stillAt(index uint64) error {
	if f.applied.Load() != index || f.ApplyingFor() != 0 {
		return fmt.Errorf("cds-ha: the log moved while this replica captured its state at index %d", index)
	}
	return nil
}

// state is what a snapshot carries beside the database image: the core, the
// decree record, the mesh CA key and the stores this process holds in
// memory. It takes each store's lock under f.mu, the order every reader of
// two of them uses.
func (f *FSM) state() (snapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	sn := snapshot{
		Index:        f.applied.Load(),
		ClusterState: f.core.clone(),
		Decrees:      slices.Clone(f.decrees),
		Secrets:      f.secrets.Dump(),
		Bindings:     f.ledger.Dump(),
	}
	if f.ca == nil {
		return sn, nil
	}
	key, err := x509.MarshalPKCS8PrivateKey(f.ca.Key)
	if err != nil {
		return snapshot{}, err
	}
	sn.MeshCAKey = key
	return sn, nil
}

// Encode writes the snapshot as one zstd stream.
func (s *Snapshot) Encode(w io.Writer) error {
	return encodeSnapshot(w, s.sn, stateBounds())
}

// encodeSnapshot writes sn, refusing a state no replica could read back.
func encodeSnapshot(w io.Writer, sn snapshot, b bounds) error {
	line, err := headerLine(sn)
	if err != nil {
		return err
	}
	switch {
	case int64(len(line)) > b.header:
		return fmt.Errorf("%w: its header is %d bytes, and a replica reads up to %d", ErrStateTooLarge, len(line), b.header)
	case int64(len(sn.Image)) > b.image:
		return fmt.Errorf("%w: its allowlist database image is %d bytes, and a replica reads up to %d", ErrStateTooLarge, len(sn.Image), b.image)
	}
	zw, err := zstd.NewWriter(w, zstd.WithWindowSize(snapshotWindow), zstd.WithEncoderConcurrency(1))
	if err != nil {
		return err
	}
	return cmp.Or(writeParts(zw, line, sn.Image), zw.Close())
}

// headerLine is the newline-terminated header of a snapshot of sn, which is
// also what the size of a replica's state is read from.
func headerLine(sn snapshot) ([]byte, error) {
	header, err := json.Marshal(sn)
	if err != nil {
		return nil, err
	}
	return append(header, '\n'), nil
}

func writeParts(w io.Writer, line, image []byte) error {
	if _, err := w.Write(line); err != nil {
		return err
	}
	_, err := w.Write(image)
	return err
}

// snapshotWindow is the zstd window a snapshot is written and read with:
// enough to reach the previous version of an allowlist document of several
// MiB, small enough to keep encoder and decoder memory modest.
const snapshotWindow = 16 << 20

// Install replaces this replica's state with the snapshot in r: what a
// replica that joins takes from the peer that sends it.
func (f *FSM) Install(r io.Reader) error {
	sn, err := decodeSnapshot(r, f.readable, stateBounds())
	if err != nil {
		return err
	}
	// A snapshot the sender's own state has overtaken, or caught up with,
	// would roll this replica back or replace its state with itself; refused,
	// the sender carries it on with the log instead.
	if applied := f.applied.Load(); sn.Index <= applied {
		return fmt.Errorf("%w: the snapshot is at index %d, and this replica applied %d", ErrStaleSnapshot, sn.Index, applied)
	}
	start := time.Now()
	if err := f.install(sn); err != nil {
		// A state this replica's own database cannot take leaves it behind
		// for good: it stops as it does on an entry its store refused, and
		// exits to rejoin.
		if allowlist.IsLocalStoreFault(err) {
			return f.stopLocal(fmt.Errorf("install the snapshot at index %d: this replica's allowlist store: %w", sn.Index, err))
		}
		return err
	}
	slog.Info("cds-ha: this replica installed a snapshot of the cluster's state", "index", sn.Index, "took", time.Since(start).Round(time.Millisecond))
	return nil
}

// install replaces every store, and the state around them, under one lock,
// so no reader meets a replica holding half of one state and half of
// another. The parts that can fail come first, so a replica that cannot take
// the snapshot keeps the state it had.
func (f *FSM) install(sn snapshot) error {
	if err := f.checkSnapshot(sn); err != nil {
		return err
	}
	ca, err := snapshotCA(sn)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.allowlist.Restore(sn.Image, [32]byte(sn.Digests.Allowlist)); err != nil {
		return fmt.Errorf("install the allowlist database image: %w", err)
	}
	f.secrets.Restore(sn.Secrets)
	f.ledger.Restore(sn.Bindings)
	f.core = sn.ClusterState
	f.ca = ca
	f.decrees = sn.Decrees
	f.applied.Store(sn.Index)
	// This replica reports the chain of the replica that captured the state.
	f.dig.installed(sn.Chain)
	return nil
}

// checkSnapshot requires a snapshot of this replica's own cluster, taken
// under the launch file it boots and the limits its stores hold, carrying no
// more than those limits allow. Only an operator decree moves a cluster
// across launch files.
func (f *FSM) checkSnapshot(sn snapshot) error {
	if err := f.checkPolicy(sn.ClusterState.Policy); err != nil {
		return err
	}
	switch {
	case sn.Index == 0:
		return errors.New("the snapshot is of a replica that applied no entry")
	case sn.ClusterState.ClusterID != f.launch.ClusterID:
		return fmt.Errorf("the snapshot is of cluster %q, and this replica boots %q", sn.ClusterState.ClusterID, f.launch.ClusterID)
	case sn.ClusterState.ConfigSHA256 != f.launch.ConfigSHA256:
		return fmt.Errorf("the snapshot is of launch file %s, and this replica boots %s", sn.ClusterState.ConfigSHA256, f.launch.ConfigSHA256)
	}
	if err := checkSnapshotDigests(sn); err != nil {
		return err
	}
	return withinPolicy(sn, sn.ClusterState.Policy)
}

// Refuses a snapshot whose secrets, bindings or state digest are not what its
// header names, before any store takes it. The database image is checked as
// it is installed, where its rows are read anyway.
func checkSnapshotDigests(sn snapshot) error {
	switch {
	case sn.Chain.Chain == (digest{}):
		return fmt.Errorf("%w: it names no chain of the entries it holds", ErrSnapshotDigest)
	case sn.Chain.Index != sn.Index:
		return fmt.Errorf("%w: its chain stands at log index %d, and the state it carries at %d", ErrSnapshotDigest, sn.Chain.Index, sn.Index)
	}
	core, err := coreDigest(sn.ClusterState, sn.MeshCAKey, sn.Decrees)
	if err != nil {
		return err
	}
	held := digestsOf(
		core,
		sn.Digests.Allowlist,
		digest(secrets.DigestOf(sn.Secrets)),
		digest(sandboxledger.DigestOf(sn.Bindings)),
	)
	switch {
	case held.Secrets != sn.Digests.Secrets:
		return fmt.Errorf("%w: its secrets are %s, and its header names %s", ErrSnapshotDigest, held.Secrets, sn.Digests.Secrets)
	case held.Bindings != sn.Digests.Bindings:
		return fmt.Errorf("%w: its sandbox bindings are %s, and its header names %s", ErrSnapshotDigest, held.Bindings, sn.Digests.Bindings)
	case held.State != sn.Digests.State:
		return fmt.Errorf("%w: the state it carries is %s, and its header names %s", ErrSnapshotDigest, held.State, sn.Digests.State)
	}
	return nil
}

// withinPolicy refuses a snapshot carrying more than the cluster's limits
// allow, before any store takes it: the stores install what they are handed,
// and a replica must hold no more than a replica of this cluster may.
func withinPolicy(sn snapshot, p Policy) error {
	switch {
	case len(sn.Secrets) > p.SecretsMaxPaths:
		return fmt.Errorf("the snapshot carries %d secret paths, and the cluster allows %d", len(sn.Secrets), p.SecretsMaxPaths)
	case len(sn.Bindings) > p.LedgerMax:
		return fmt.Errorf("the snapshot carries %d sandbox bindings, and the cluster allows %d", len(sn.Bindings), p.LedgerMax)
	}
	for _, e := range sn.Secrets {
		if len(e.Value) > p.SecretsMaxValue {
			return fmt.Errorf("the snapshot carries a secret of %d bytes, and the cluster allows %d", len(e.Value), p.SecretsMaxValue)
		}
	}
	return nil
}

// snapshotCA is the mesh CA a snapshot carries, or nil for a cluster that
// holds none yet.
func snapshotCA(sn snapshot) (*issuer.CA, error) {
	if !sn.ClusterState.Joined() {
		return nil, nil
	}
	ca, err := meshCA(sn.ClusterState.MeshCACert, sn.MeshCAKey)
	if err != nil {
		return nil, fmt.Errorf("the snapshot's mesh CA: %w", err)
	}
	return ca, nil
}

// ErrStaleSnapshot refuses a snapshot older than the state already applied.
var ErrStaleSnapshot = errors.New("cds-ha: refusing a snapshot older than the applied state")

// ErrSnapshotDigest is a snapshot whose content is not what its header names.
var ErrSnapshotDigest = errors.New("cds-ha: the snapshot does not match the digest it carries")

// decodeSnapshot reads a snapshot in a format from baseFormat to readable,
// and checks its database image against the digest its header carries before
// any of it reaches a store.
func decodeSnapshot(r io.Reader, readable uint32, b bounds) (snapshot, error) {
	// One byte over the bound, so a reader left with none read too much.
	stream := &io.LimitedReader{
		R: r,
		N: b.stream + 1,
	}
	zr, err := zstd.NewReader(stream, zstd.WithDecoderMaxWindow(snapshotWindow), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return snapshot{}, fmt.Errorf("decode the snapshot: %w", err)
	}
	defer zr.Close()
	sn, err := decodeSnapshotBody(zr, readable, b)
	if overBound := stream.N == 0; overBound {
		return snapshot{}, fmt.Errorf("%w: its stream is longer than %d bytes", ErrStateTooLarge, b.stream)
	}
	if err != nil {
		return snapshot{}, err
	}
	if digest := imageDigest(sn.Image); digest != sn.ImageSHA256 {
		return snapshot{}, fmt.Errorf("%w: its allowlist database image is %s, and its header names %s", ErrSnapshotDigest, digest, sn.ImageSHA256)
	}
	return sn, nil
}

func decodeSnapshotBody(r io.Reader, readable uint32, b bounds) (snapshot, error) {
	line, rest, err := readHeaderLine(r, b.header)
	if err != nil {
		return snapshot{}, err
	}
	var sn snapshot
	if err := decodeStrict(line, &sn); err != nil {
		return snapshot{}, fmt.Errorf("decode the snapshot: %w", err)
	}
	if err := checkSnapshotFormat(sn, readable); err != nil {
		return snapshot{}, err
	}
	if sn.Image, err = readImage(rest, b.image); err != nil {
		return snapshot{}, err
	}
	return sn, nil
}

// readHeaderLine reads the header through a limit, before it is
// unmarshalled: a JSON decoder allocates by what it is handed before it
// returns anything. It answers the line and a reader of everything after it,
// since reading a line reads ahead.
func readHeaderLine(r io.Reader, limit int64) (line []byte, rest io.Reader, err error) {
	br := bufio.NewReader(io.LimitReader(r, limit+1))
	line, err = br.ReadBytes('\n')
	switch {
	case int64(len(line)) > limit:
		return nil, nil, fmt.Errorf("%w: its header is longer than %d bytes", ErrStateTooLarge, limit)
	case err != nil:
		return nil, nil, fmt.Errorf("decode the snapshot: it carries no header: %w", err)
	}
	return line, io.MultiReader(br, r), nil
}

// readImage reads the allowlist database image through its own limit.
func readImage(r io.Reader, limit int64) ([]byte, error) {
	image, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("decode the snapshot: %w", err)
	}
	if int64(len(image)) > limit {
		return nil, fmt.Errorf("%w: its allowlist database image is longer than %d bytes", ErrStateTooLarge, limit)
	}
	return image, nil
}

// checkSnapshotFormat refuses a snapshot of a cluster whose encoding this
// replica does not read: installing it would leave the replica serving state
// it read differently than the replicas that know the encoding.
func checkSnapshotFormat(sn snapshot, readable uint32) error {
	if format := sn.ClusterState.format(); format > readable {
		return fmt.Errorf("%w: the snapshot is of a cluster at format %d, and this replica reads up to %d", ErrNewerFormat, format, readable)
	}
	return nil
}

// imageDigest is the hex SHA-256 of a database image.
func imageDigest(image []byte) string {
	sum := sha256.Sum256(image)
	return hex.EncodeToString(sum[:])
}
