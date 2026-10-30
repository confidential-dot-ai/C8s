// Divergence detection. Every replica keeps two digests of what it applied:
//
//   - the chain, a rolling hash over every log entry it applied, each index
//     and its bytes. Replicas whose chains differ at an index applied
//     different entries up to it;
//   - the state digest, which names ClusterState, the mesh CA key, the decree record
//     and the content of the three stores. Replicas record it at
//     checkpoints, entries the leader proposes, so every replica records it
//     at the same index.
//
// The leader compares what the replicas report (divergence.go). A snapshot
// carries both and is taken and installed only where the content matches
// them.

package cdsha

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"slices"
	"sync"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

// Hex in JSON, so what a replica reports reads as what an operator compares.
type digest [32]byte

func (d digest) String() string {
	return hex.EncodeToString(d[:])
}

func (d digest) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

func (d *digest) UnmarshalText(text []byte) error {
	raw, err := hex.DecodeString(string(text))
	if err != nil || len(raw) != len(d) {
		return fmt.Errorf("cds-ha: %q is no SHA-256 digest", text)
	}
	*d = digest(raw)
	return nil
}

// Point is where a replica's chain stood after one log entry. State is set
// only where that entry was a checkpoint.
type Point struct {
	Index uint64 `json:"index"`
	Chain digest `json:"chain"`
	State digest `json:"state,omitzero"`
}

// Digests are the digest of a whole state and the content digests it is made
// of.
type Digests struct {
	State     digest `json:"state"`
	Allowlist digest `json:"allowlist"`
	Secrets   digest `json:"secrets"`
	Bindings  digest `json:"bindings"`
}

// How far back a replica answers for its chain and for its state digests.
const (
	chainPoints      = 1024
	checkpointPoints = 8
)

// What a replica has applied, as it reports it.
type digestLog struct {
	mu sync.Mutex
	// The point a snapshot carried, or the empty chain at index 0.
	base Point
	// Oldest first.
	points       []Point
	checkpointed []Point
}

// took records the entry at index as applied, state being the digest of the
// state the replica held there, which only a checkpoint carries. A report
// showing a checkpoint's chain without its state digest would count as a
// replica that recorded none, so the caller records both at once.
func (d *digestLog) took(index uint64, entry []byte, state digest) {
	d.mu.Lock()
	defer d.mu.Unlock()
	chain := chainOver(d.newest().Chain, index, entry)
	d.points = appendPoint(
		d.points,
		Point{
			Index: index,
			Chain: chain,
		},
		chainPoints,
	)
	if state == (digest{}) {
		return
	}
	d.checkpointed = appendPoint(
		d.checkpointed,
		Point{
			Index: index,
			Chain: chain,
			State: state,
		},
		checkpointPoints,
	)
}

func chainOver(chain digest, index uint64, entry []byte) digest {
	h := sha256.New()
	h.Write(chain[:])
	h.Write(binary.BigEndian.AppendUint64(nil, index))
	h.Write(entry)
	return digest(h.Sum(nil))
}

// Drops the oldest half at the bound, so one point costs no copy of them all.
func appendPoint(points []Point, p Point, bound int) []Point {
	if len(points) >= bound {
		points = append(points[:0], points[bound/2:]...)
	}
	return append(points, p)
}

// The chain a snapshot carries covers everything the snapshot holds.
func (d *digestLog) installed(p Point) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.base = Point{
		Index: p.Index,
		Chain: p.Chain,
	}
	d.points = nil
	d.checkpointed = nil
}

func (d *digestLog) latest() Point {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.newest()
}

// d.mu held.
func (d *digestLog) newest() Point {
	if last := len(d.points) - 1; last >= 0 {
		return d.points[last]
	}
	return d.base
}

// The zero point where this replica recorded none.
func (d *digestLog) lastCheckpoint() Point {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.checkpointed) == 0 {
		return Point{}
	}
	return d.checkpointed[len(d.checkpointed)-1]
}

// Oldest first.
func (d *digestLog) checkpoints() []Point {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.checkpointed)
}

func (d *digestLog) report() *DigestReport {
	d.mu.Lock()
	defer d.mu.Unlock()
	return &DigestReport{
		Base:        d.base.Index,
		Latest:      d.newest(),
		Checkpoints: slices.Clone(d.checkpointed),
	}
}

// A point older than the chain reaches back is no disagreement.
func (d *digestLog) disagreesWith(p Point) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.points) == 0 || p.Index < d.points[0].Index {
		return false
	}
	for _, held := range slices.Backward(d.points) {
		if held.Index == p.Index {
			return held.Chain != p.Chain
		}
	}
	return true
}

// Separates the state digest from every other hash of the same bytes.
const coreDigestDomain = "c8s-cds-ha-state-v1"

// The state around the stores: ClusterState, which carries the mesh CA certificate,
// then the mesh CA key and the decree record.
func coreDigest(core ClusterState, meshCAKey []byte, decrees []DecreeRecord) (digest, error) {
	h := sha256.New()
	h.Write(appendBoundField(nil, []byte(coreDigestDomain)))
	if err := writeBoundDocument(h, core); err != nil {
		return digest{}, err
	}
	h.Write(appendBoundField(nil, meshCAKey))
	if err := writeBoundDocument(h, decrees); err != nil {
		return digest{}, err
	}
	return digest(h.Sum(nil)), nil
}

// ClusterState and the decree record carry no map and no value of one replica's own,
// so every replica encodes this JSON alike.
func writeBoundDocument(h hash.Hash, part any) error {
	document, err := json.Marshal(part)
	if err != nil {
		return err
	}
	h.Write(appendBoundField(nil, document))
	return nil
}

func digestsOf(core, allowlist, secrets, bindings digest) Digests {
	h := sha256.New()
	for _, part := range []digest{core, allowlist, secrets, bindings} {
		h.Write(part[:])
	}
	return Digests{
		State:     digest(h.Sum(nil)),
		Allowlist: allowlist,
		Secrets:   secrets,
		Bindings:  bindings,
	}
}

// Only the goroutine that applies the log reads these, so no entry changes a
// store while they are read.
func (f *FSM) digestsNow() (Digests, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	key, err := meshCAKeyOf(f.ca)
	if err != nil {
		return Digests{}, err
	}
	core, err := coreDigest(f.core, key, f.decrees)
	if err != nil {
		return Digests{}, err
	}
	return digestsOf(
		core,
		digest(f.allowlist.Digest()),
		digest(f.secrets.Digest()),
		digest(f.ledger.Digest()),
	), nil
}

// None where this replica cannot read the state it holds.
func (f *FSM) digestAtCheckpoint() digest {
	digests, err := f.digestsNow()
	if err != nil {
		_ = f.stopLocal(fmt.Errorf("read the digest of the state this replica holds: %w", err))
		return digest{}
	}
	return digests.State
}

// PKCS#8, and none for a cluster that holds no mesh CA yet.
func meshCAKeyOf(ca *issuer.CA) ([]byte, error) {
	if ca == nil {
		return nil, nil
	}
	_, key, err := caEntryBytes(ca)
	return key, err
}
