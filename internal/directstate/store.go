// Package directstate is the experimental encrypted current-state backend.
// Metadata transactions are the commit authority; immutable ciphertext objects
// carry large values. There is no application log, replay, leader or checkpoint.
package directstate

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/requestgate"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
)

const (
	IdentityRecord = "identity"
	InlineBytes    = 32 << 10
	MaxValueBytes  = 8 << 20
	Shards         = 16
	ShardCapacity  = 8
	MaxAttempts    = 16
	CacheSlots     = 64
	CacheWays      = 4
	MaxCachedBytes = 256 << 10
	MaxReadBytes   = 16 << 20
)

type Metadata interface {
	Read(context.Context, []string) ([]metadatapilot.Record, error)
	Commit(context.Context, metadatapilot.Transaction) error
}

// Store has immutable crypto/transport state and bounded actor admission per
// key shard. Operations own their plaintext and speculative changes. No shared
// application map, process-wide lock, writer lease or mutable replica cache.
type Store struct {
	ctx                                      context.Context
	cancel                                   context.CancelFunc
	metadata                                 Metadata
	objects                                  objectwal.Store
	prefix, scope                            string
	indexKey                                 []byte
	aead                                     cipher.AEAD
	gates                                    [Shards]*requestgate.Gate
	readers                                  *requestgate.Gate
	cache                                    [CacheSlots / CacheWays]atomic.Pointer[cacheSet]
	reads, commits, conflicts, unknown, puts atomic.Uint64
}

type cachedObject struct {
	hash string
	data []byte
}

type cacheSet struct{ objects [CacheWays]*cachedObject }

type Stats struct {
	Reads            uint64 `json:"reads"`
	Commits          uint64 `json:"commits"`
	Conflicts        uint64 `json:"conflicts"`
	Unknown          uint64 `json:"unknown"`
	ObjectPuts       uint64 `json:"object_puts"`
	Admitted, Active int
	Rejected         uint64 `json:"rejected"`
}

func New(parent context.Context, metadata Metadata, objects objectwal.Store, key []byte, prefix, scope string) (*Store, error) {
	if metadata == nil || objects == nil || len(key) != 32 || scope == "" || prefix == "" || strings.Trim(prefix, "/") != prefix || strings.Contains(prefix, "..") {
		return nil, errors.New("direct state: metadata, objects, 32-byte key and bound namespace required")
	}
	contextBytes, _ := json.Marshal([]string{"cds-direct-state-v1", prefix, scope})
	index, err := hkdf.Key(sha256.New, key, contextBytes, "index", 32)
	if err != nil {
		return nil, err
	}
	enc, err := hkdf.Key(sha256.New, key, contextBytes, "encryption", 32)
	if err != nil {
		return nil, err
	}
	defer clear(enc)
	block, err := aes.NewCipher(enc)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Store{ctx: ctx, cancel: cancel, metadata: metadata, objects: objects, prefix: prefix, scope: scope, indexKey: index, aead: aead}
	for i := range s.gates {
		s.gates[i], _ = requestgate.New(ctx, 1, ShardCapacity)
	}
	s.readers, _ = requestgate.New(ctx, 16, 64)
	return s, nil
}

func (s *Store) Close() {
	s.cancel()
	s.readers.Close()
	for _, g := range s.gates {
		g.Close()
	}
	// The cipher's expanded key is not wipeable through Go's AEAD interface.
	// It dies with this process; do not claim guaranteed Go heap zeroization.
}

func (s *Store) Stats() Stats {
	r := Stats{Reads: s.reads.Load(), Commits: s.commits.Load(), Conflicts: s.conflicts.Load(), Unknown: s.unknown.Load(), ObjectPuts: s.puts.Load()}
	for _, g := range s.gates {
		a := g.Stats()
		r.Admitted += a.Admitted
		r.Active += a.Active
		r.Rejected += a.Rejected
	}
	a := s.readers.Stats()
	r.Admitted += a.Admitted
	r.Active += a.Active
	r.Rejected += a.Rejected
	return r
}

func (s *Store) name(key string) string {
	h := hmac.New(sha256.New, s.indexKey)
	_, _ = h.Write([]byte(key))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Store) aad(key, version string) []byte {
	b, _ := json.Marshal([]string{"cds-direct-state-v1", s.prefix, s.scope, key, version})
	return b
}

type envelope struct {
	Format int    `json:"format"`
	Inline []byte `json:"inline,omitempty"`
	Object string `json:"object,omitempty"`
	Bytes  int    `json:"bytes,omitempty"`
}

// View owns a consistent set of current records. Clear releases plaintext
// promptly. An empty value is legal and distinct from an absent key.
type View struct {
	values   map[string][]byte
	versions map[string]string
}

func (v *View) Get(key string) ([]byte, bool) { b, ok := v.values[key]; return b, ok }
func (v *View) Version(key string) string     { return v.versions[key] }
func (v *View) Clear() {
	for _, b := range v.values {
		clear(b)
	}
}

type needRecord string

func (n needRecord) Error() string { return "direct state: transition needs another record" }

// Require expands an optimistic read set before any commit. Get is for keys
// the caller already declared; use Require for a holder named by another row.
func (v *View) Require(key string) ([]byte, bool, error) {
	if _, read := v.versions[key]; !read {
		return nil, false, needRecord(key)
	}
	b, ok := v.Get(key)
	return b, ok, nil
}

func (s *Store) read(ctx context.Context, keys []string) (*View, error) {
	if len(keys) == 0 || len(keys) > metadatapilot.MaxTransactionKeys {
		return nil, errors.New("direct state: invalid read set")
	}
	names := make([]string, len(keys))
	seen := map[string]bool{}
	for i, key := range keys {
		if key == "" || len(key) > 8192 || seen[key] {
			return nil, errors.New("direct state: invalid or repeated key")
		}
		seen[key], names[i] = true, s.name(key)
	}
	rows, err := s.metadata.Read(ctx, names)
	if err != nil {
		return nil, err
	}
	s.reads.Add(1)
	if len(rows) != len(keys) {
		return nil, objectwal.ErrCorrupt
	}
	v := &View{values: map[string][]byte{}, versions: map[string]string{}}
	good := false
	defer func() {
		if !good {
			v.Clear()
		}
	}()
	readBytes := 0
	for i, r := range rows {
		if r.Key != names[i] {
			return nil, objectwal.ErrCorrupt
		}
		v.versions[keys[i]] = r.Version
		if r.Version == "" {
			if len(r.Value) != 0 {
				return nil, objectwal.ErrCorrupt
			}
			continue
		}
		var e envelope
		d := json.NewDecoder(bytes.NewReader(r.Value))
		d.DisallowUnknownFields()
		if err := d.Decode(&e); err != nil || strictjson.Validate(r.Value) != nil || e.Format != 1 || (e.Object == "") == (len(e.Inline) == 0) {
			return nil, objectwal.ErrCorrupt
		}
		ciphertext := e.Inline
		readBytes += len(e.Inline) + e.Bytes
		if readBytes < 0 || readBytes > MaxReadBytes {
			return nil, errors.New("direct state: read byte budget exceeded")
		}
		if e.Object != "" {
			digest, err := hex.DecodeString(e.Object)
			if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != e.Object || e.Bytes <= 0 || e.Bytes > MaxValueBytes+s.aead.Overhead() {
				return nil, objectwal.ErrCorrupt
			}
			ciphertext, err = s.object(ctx, e.Object, e.Bytes)
			if err != nil {
				return nil, err
			}
		} else if len(ciphertext) > InlineBytes+s.aead.Overhead() || e.Bytes != 0 {
			return nil, objectwal.ErrCorrupt
		}
		plain, err := s.aead.Open(nil, nil, ciphertext, s.aad(r.Key, r.Version))
		if err != nil {
			return nil, objectwal.ErrCorrupt
		}
		v.values[keys[i]] = plain
	}
	good = true
	return v, nil
}

func (s *Store) enter(ctx context.Context, lane string) (context.Context, func(), error) {
	h := sha256.Sum256([]byte(lane))
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	release, err := s.gates[int(h[0])%Shards].Acquire(ctx)
	if err != nil {
		stop()
		cancel()
		return nil, nil, err
	}
	return ctx, func() { release(); stop(); cancel() }, nil
}

func (s *Store) Read(ctx context.Context, keys ...string) (*View, error) {
	if len(keys) == 0 {
		return nil, errors.New("direct state: empty read set")
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	defer func() { stop(); cancel() }()
	release, err := s.readers.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return s.read(ctx, keys)
}

// Only hash-verified immutable CIPHERTEXT is cached. Every operation still
// reads current metadata. Fixed atomic slots bound the cache to 16 MiB, and
// collisions evict entries without a lock, lease, background loop or GC.
func (s *Store) object(ctx context.Context, hash string, size int) ([]byte, error) {
	digest, err := hex.DecodeString(hash)
	if err != nil || len(digest) != 32 {
		return nil, objectwal.ErrCorrupt
	}
	slot := &s.cache[int(digest[0])%len(s.cache)]
	if set := slot.Load(); set != nil {
		for _, c := range set.objects {
			if c != nil && c.hash == hash && len(c.data) == size {
				return c.data, nil
			}
		}
	}
	o, err := s.objects.Get(ctx, s.prefix+"/current/"+hash)
	if err != nil {
		return nil, err
	}
	actual := sha256.Sum256(o.Data)
	if len(o.Data) != size || !bytes.Equal(actual[:], digest) {
		return nil, objectwal.ErrCorrupt
	}
	s.remember(hash, o.Data)
	return o.Data, nil
}

func (s *Store) remember(hash string, ciphertext []byte) {
	if len(ciphertext) > MaxCachedBytes {
		return
	}
	digest, err := hex.DecodeString(hash)
	if err != nil || len(digest) != 32 {
		return
	}
	slot := &s.cache[int(digest[0])%len(s.cache)]
	entry := &cachedObject{hash: hash, data: bytes.Clone(ciphertext)}
	// Immutable four-way sets avoid repeated identity/policy collisions without
	// locks or a cache-maintenance actor. Contention may skip caching; it never
	// delays an authoritative transaction or permits a stale metadata read.
	for range 8 {
		old := slot.Load()
		next := &cacheSet{}
		if old != nil {
			for _, c := range old.objects {
				if c != nil && c.hash == hash {
					return
				}
			}
			copy(next.objects[1:], old.objects[:CacheWays-1])
		}
		next.objects[0] = entry
		if slot.CompareAndSwap(old, next) {
			return
		}
	}
}

// Update reevaluates a pure transition only after a DEFINITE transaction
// conflict. The callback must not expose a result, mutate a shared cache, or
// perform external effects. Its proposed values are cleared after encryption.
// lane selects a bounded key shard, so one hot policy cannot occupy all workers.
// No-op transitions still perform a fresh metadata read.
func (s *Store) Update(ctx context.Context, lane string, keys []string, change func(*View) (map[string][]byte, any, error)) (any, error) {
	keys = slices.Clone(keys)
	ctx, release, err := s.enter(ctx, lane)
	if err != nil {
		return nil, err
	}
	defer release()
	for attempt := 0; attempt < MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		v, err := s.read(ctx, keys)
		if err != nil {
			return nil, err
		}
		writes, answer, err := change(v)
		if err != nil {
			v.Clear()
			clearWrites(writes)
			var missing needRecord
			if errors.As(err, &missing) && len(keys) < metadatapilot.MaxTransactionKeys && !slices.Contains(keys, string(missing)) {
				keys = append(keys, string(missing))
				continue
			}
			return nil, err
		}
		txn, err := s.prepare(ctx, v, writes)
		v.Clear()
		clearWrites(writes)
		if err != nil {
			return nil, err
		}
		if len(txn.Writes) == 0 {
			return answer, nil
		}
		err = s.metadata.Commit(ctx, txn)
		if err == nil {
			s.commits.Add(1)
			return answer, nil
		}
		if !errors.Is(err, objectwal.ErrConflict) {
			if errors.Is(err, objectwal.ErrInDoubt) {
				s.unknown.Add(1)
			}
			return nil, err
		}
		s.conflicts.Add(1)
		timer := time.NewTimer(time.Duration(1+rand.IntN(1<<min(attempt+1, 6))) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, objectwal.ErrBackpressure
}

func clearWrites(writes map[string][]byte) {
	for _, b := range writes {
		clear(b)
	}
}

func (s *Store) prepare(ctx context.Context, v *View, writes map[string][]byte) (metadatapilot.Transaction, error) {
	t := metadatapilot.Transaction{}
	bytes := 0
	for key, value := range writes {
		if _, read := v.versions[key]; !read || len(value) > MaxValueBytes {
			return t, errors.New("direct state: write outside read set or value bound")
		}
		bytes += len(value)
		if bytes > MaxReadBytes {
			return t, errors.New("direct state: write byte budget exceeded")
		}
	}
	keys := make([]string, 0, len(v.versions))
	for key := range v.versions {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		t.Checks = append(t.Checks, metadatapilot.Check{Key: s.name(key), Version: v.Version(key)})
	}
	for key, value := range writes {
		if _, read := v.versions[key]; !read || len(value) > MaxValueBytes {
			return t, errors.New("direct state: write outside read set or value bound")
		}
		version, err := metadatapilot.NextVersion(v.Version(key))
		if err != nil {
			return t, err
		}
		r := metadatapilot.Record{Key: s.name(key), Version: version}
		ciphertext := s.aead.Seal(nil, nil, value, s.aad(r.Key, r.Version))
		e := envelope{Format: 1}
		if len(value) <= InlineBytes {
			e.Inline = ciphertext
		} else {
			h := sha256.Sum256(ciphertext)
			e.Object, e.Bytes = hex.EncodeToString(h[:]), len(ciphertext)
			if _, err := s.objects.Put(ctx, s.prefix+"/current/"+e.Object, ciphertext, ""); err != nil {
				return t, fmt.Errorf("direct state: immutable upload: %w", err)
			}
			s.puts.Add(1)
			// Cache only validated reads. Speculative uploads otherwise evict
			// useful objects and give a winning policy writer a persistent
			// head start over competitors fetching the same current object.
		}
		r.Value, err = json.Marshal(e)
		if err != nil {
			return t, err
		}
		t.Writes = append(t.Writes, r)
	}
	return t, nil
}
