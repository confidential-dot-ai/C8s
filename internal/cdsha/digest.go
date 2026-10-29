package cdsha

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// Divergence detection. Every replica keeps two digests of what it applied:
//
//   - the chain, a rolling SHA-256 over every command it applied (index,
//     term, data). Two replicas whose chains differ at an index applied
//     different entries up to it (hashicorp/raft #695);
//   - the state digest: Core, the mesh CA key and the decree record, with
//     the multiset hashes the allowlist, secrets and ledger keep of their
//     content as each write changes it. It is recorded at checkpoints, empty
//     entries the leader proposes (KindCheckpoint), so every replica records
//     it at the same index; reading it costs O(1) in the size of the state.
//
// The leader compares the replicas' digests (divergence.go), and a snapshot
// carries them: Persist recomputes them from what it encodes, and Restore
// from what it decodes, so state that changed under a replica (memory or
// disk corruption) is neither shipped nor installed.

// KindCheckpoint asks every replica to record its state digest.
const KindCheckpoint EntryKind = "checkpoint"

// Point is a replica's digest at a log index: its chain, and at a
// checkpoint its state digest.
type Point struct {
	Index uint64 `json:"index"`
	Chain string `json:"chain"`
	State string `json:"state,omitempty"`
}

// Digests are the state digest and its parts, as a snapshot carries them.
type Digests struct {
	State     string `json:"state"`
	Allowlist string `json:"allowlist"`
	Secrets   string `json:"secrets"`
	Ledger    string `json:"ledger"`
}

// ErrSnapshotDigest refuses a snapshot whose content is not what its
// digests name.
var ErrSnapshotDigest = errors.New("cds-ha: snapshot content does not match its digest")

// ErrDiverged is a replica whose state differs from the majority's.
var ErrDiverged = errors.New("cds-ha: diverged from the majority")

const (
	chainRing      = 1024
	checkpointRing = 8
)

// digestLog is a replica's chain and recent points (FSM.dig).
type digestLog struct {
	mu sync.Mutex
	// base is the first index the chain vouches for: 0, or the snapshot
	// this replica was restored from.
	base  uint64
	chain [32]byte
	// points are the chain after each of the last chainRing commands, oldest
	// first; checkpoints the last checkpointRing state digests.
	points      []Point
	checkpoints []Point
}

// next is the chain after the command l. Apply records it (record) once it
// has applied l, so a report never shows a checkpoint's chain without its
// state digest.
func (d *digestLog) next(l *raft.Log) Point {
	h := sha256.New()
	d.mu.Lock()
	h.Write(d.chain[:])
	d.mu.Unlock()
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], l.Index)
	binary.BigEndian.PutUint64(b[8:], l.Term)
	h.Write(b[:])
	h.Write(l.Data)
	return Point{Index: l.Index, Chain: hex.EncodeToString(h.Sum(nil))}
}

// record makes p, from next, the chain; with State set it is a checkpoint.
func (d *digestLog) record(p Point) {
	c, _ := hex.DecodeString(p.Chain)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.chain = [32]byte(c)
	if len(d.points) == chainRing {
		d.points = append(d.points[:0], d.points[1:]...)
	}
	d.points = append(d.points, Point{Index: p.Index, Chain: p.Chain})
	if p.State != "" {
		if len(d.checkpoints) == checkpointRing {
			d.checkpoints = append(d.checkpoints[:0], d.checkpoints[1:]...)
		}
		d.checkpoints = append(d.checkpoints, p)
	}
}

// reset starts the chain at p, a snapshot's point.
func (d *digestLog) reset(p Point) error {
	c, err := hex.DecodeString(p.Chain)
	if err != nil || len(c) != sha256.Size {
		return fmt.Errorf("%w: chain %q", ErrSnapshotDigest, p.Chain)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.base, d.chain = p.Index, [32]byte(c)
	d.points, d.checkpoints = []Point{{Index: p.Index, Chain: p.Chain}}, nil
	return nil
}

// latest is the chain after the last command applied.
func (d *digestLog) latest() Point {
	d.mu.Lock()
	defer d.mu.Unlock()
	if n := len(d.points); n > 0 {
		return d.points[n-1]
	}
	return Point{Index: d.base, Chain: hex.EncodeToString(d.chain[:])}
}

// report is what a follower tells the leader (divergence.go).
func (d *digestLog) report() *DigestReport {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := &DigestReport{Base: d.base, Checkpoints: slices.Clone(d.checkpoints)}
	if n := len(d.points); n > 0 {
		r.Latest = d.points[n-1]
	} else {
		r.Latest = Point{Index: d.base, Chain: hex.EncodeToString(d.chain[:])}
	}
	return r
}

// chainAt is this replica's chain at index i: found, or known to be no
// command (no is true: i is within what the ring covers, but no command
// was applied there).
func (d *digestLog) chainAt(i uint64) (chain string, found, no bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	k, ok := slices.BinarySearchFunc(d.points, i, func(p Point, i uint64) int {
		switch {
		case p.Index < i:
			return -1
		case p.Index > i:
			return 1
		}
		return 0
	})
	if ok {
		return d.points[k].Chain, true, false
	}
	return "", false, len(d.points) > 0 && d.points[0].Index < i
}

func (d *digestLog) checkpointsCopy() []Point {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.checkpoints)
}

// coreDigest hashes Core, the mesh CA key and the decree record.
func coreDigest(core Core, key []byte, decrees []DecreeRecord) ([32]byte, error) {
	h := sha256.New()
	h.Write([]byte("c8s-cds-ha-state-v1\n"))
	for _, v := range []any{core, decrees} {
		j, err := json.Marshal(v)
		if err != nil {
			return [32]byte{}, err
		}
		_ = binary.Write(h, binary.BigEndian, uint64(len(j)))
		h.Write(j)
	}
	_ = binary.Write(h, binary.BigEndian, uint64(len(key)))
	h.Write(key)
	return [32]byte(h.Sum(nil)), nil
}

// stateDigest combines the parts into the state digest.
func stateDigest(core, allowlist, secrets, ledger [32]byte) [32]byte {
	h := sha256.New()
	for _, p := range [][32]byte{core, allowlist, secrets, ledger} {
		h.Write(p[:])
	}
	return [32]byte(h.Sum(nil))
}

func hexOf(b [32]byte) string { return hex.EncodeToString(b[:]) }

// liveDigests is the state digest of what this replica holds now. Call it
// on the FSM goroutine (Apply, Snapshot), where no entry is applied
// concurrently.
func (f *FSM) liveDigests(allowlist [32]byte) (Digests, error) {
	f.mu.RLock()
	core, decrees := f.core.clone(), slices.Clone(f.decrees)
	var key []byte
	if f.ca != nil {
		var err error
		if key, err = x509.MarshalPKCS8PrivateKey(f.ca.Key); err != nil {
			f.mu.RUnlock()
			return Digests{}, err
		}
	}
	f.mu.RUnlock()
	c, err := coreDigest(core, key, decrees)
	if err != nil {
		return Digests{}, err
	}
	sec, led := f.secrets.Digest(), f.ledger.Digest()
	return Digests{State: hexOf(stateDigest(c, allowlist, sec, led)), Allowlist: hexOf(allowlist), Secrets: hexOf(sec), Ledger: hexOf(led)}, nil
}

// contentDigests computes the digests of sn from its content: the
// allowlist image's rows, the secrets and bindings, the header.
func contentDigests(sn snapshot, allowlistImage func([]byte) ([32]byte, error)) (Digests, error) {
	al, err := allowlistImage(sn.Allowlist)
	if err != nil {
		return Digests{}, err
	}
	c, err := coreDigest(sn.Core, sn.Key, sn.Decrees)
	if err != nil {
		return Digests{}, err
	}
	sec, led := secrets.DigestOf(sn.Secrets), sandboxledger.DigestOf(sn.Bindings)
	return Digests{State: hexOf(stateDigest(c, al, sec, led)), Allowlist: hexOf(al), Secrets: hexOf(sec), Ledger: hexOf(led)}, nil
}
