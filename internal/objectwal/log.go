package objectwal

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"
)

const maxEntryBytes = 4 << 20

type ref struct {
	Key   string `json:"key"`
	Hash  string `json:"sha256"`
	Index uint64 `json:"index"`
}

type head struct {
	Version  int    `json:"version"`
	Revision uint64 `json:"revision"`
	Tail     ref    `json:"tail"`
	Snapshot ref    `json:"snapshot,omitempty"`
}

type record struct {
	ID       string `json:"id"`
	Index    uint64 `json:"index"`
	Previous ref    `json:"previous"`
	Payload  []byte `json:"payload"`
}

type Stats struct {
	Applied   uint64 `json:"applied"`
	Revision  uint64 `json:"revision"`
	Snapshot  uint64 `json:"snapshot"`
	Gets      uint64 `json:"gets"`
	Puts      uint64 `json:"puts"`
	Conflicts uint64 `json:"conflicts"`
	Ambiguous uint64 `json:"ambiguous"`
	Replayed  uint64 `json:"replayed"`
	Stopped   bool   `json:"stopped"`
}

type Log struct {
	mu      sync.Mutex
	store   Store
	machine Machine
	aead    cipher.AEAD
	prefix  string
	scope   string
	head    head
	etag    string
	applied ref
	stats   Stats
	stopped error
}

// New opens no objects and changes no state. scope binds ciphertext to the
// cluster and measured configuration; prefix is an exclusive, nonempty object
// namespace. The 256-bit key is provisioned into TEE memory, never a launch file.
func New(store Store, machine Machine, key []byte, prefix, scope string) (*Log, error) {
	if store == nil || machine == nil || len(key) != 32 || scope == "" ||
		prefix == "" || strings.Trim(prefix, "/") != prefix || strings.Contains(prefix, "..") {
		return nil, errors.New("object WAL: store, machine, 32-byte key, scope and clean prefix are required")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return &Log{store: store, machine: machine, aead: aead, prefix: prefix, scope: scope}, nil
}

func (l *Log) Stats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats
	s.Applied, s.Revision, s.Snapshot = l.applied.Index, l.head.Revision, l.head.Snapshot.Index
	s.Stopped = l.stopped != nil
	return s
}

// Sync establishes a fresh read watermark and applies through it. Polling or a
// successful upload is not a substitute for this operation before a fresh read.
func (l *Log) Sync(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _, err := l.sync(ctx, "")
	return err
}

// Append acknowledges only after the head CAS committed and the machine applied
// this request. Its private request ID is reused across every attempt. After an
// ambiguous response we replay the authoritative history before retrying, even
// if another writer has already advanced the head past our record.
func (l *Log) Append(ctx context.Context, payload []byte) (any, error) {
	if len(payload) == 0 || len(payload) > maxEntryBytes {
		return nil, errors.New("object WAL: entry must be between 1 byte and 4 MiB")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	id := randomID()
	uncertain := false
	for {
		answer, found, err := l.sync(ctx, id)
		if err != nil {
			if uncertain {
				return nil, fmt.Errorf("%w: %w", ErrInDoubt, err)
			}
			return nil, err
		}
		if found {
			return answer, nil
		}
		if err := ctx.Err(); err != nil {
			if uncertain {
				return nil, fmt.Errorf("%w: %w", ErrInDoubt, err)
			}
			return nil, err
		}
		if l.head.Revision == math.MaxUint64 || l.applied.Index == math.MaxUint64 {
			return nil, l.stop(errors.New("object WAL: sequence exhausted"))
		}
		r := record{ID: id, Index: l.applied.Index + 1, Previous: l.applied, Payload: payload}
		body, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		written, err := l.immutable(ctx, "wal", r.Index, body)
		if err != nil {
			if uncertain {
				return nil, fmt.Errorf("%w: %w", ErrInDoubt, err)
			}
			return nil, err
		}
		next := l.head
		next.Version, next.Revision, next.Tail = 1, l.head.Revision+1, written
		etag, err := l.publish(ctx, next)
		if err != nil {
			if errors.Is(err, ErrConflict) {
				l.stats.Conflicts++
			} else {
				uncertain = true
				l.stats.Ambiguous++
			}
			// Back off contention and outage retries, bounded by the caller.
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				if uncertain {
					return nil, fmt.Errorf("%w: %w", ErrInDoubt, ctx.Err())
				}
				return nil, ctx.Err()
			case <-timer.C:
			}
			continue
		}
		// The object store has committed. Apply exactly these bytes; subsequent
		// writers may already have published newer records, which Sync will read.
		l.head, l.etag = next, etag
		answer, err = l.apply(written, r)
		return answer, err
	}
}

func (l *Log) sync(ctx context.Context, wanted string) (any, bool, error) {
	if l.stopped != nil {
		return nil, false, l.stopped
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	obj, err := l.get(ctx, l.prefix+"/head")
	if errors.Is(err, ErrNotFound) && l.applied.Index == 0 && l.head.Revision == 0 {
		return nil, false, nil
	}
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			err = l.stop(fmt.Errorf("%w: head disappeared", ErrCorrupt))
		}
		return nil, false, err
	}
	if obj.ETag == "" {
		return nil, false, l.stop(fmt.Errorf("%w: head has no ETag", ErrCorrupt))
	}
	plain, err := l.open(l.prefix+"/head", obj.Data)
	if err != nil {
		return nil, false, l.stop(err)
	}
	var h head
	if err := decode(plain, &h); err != nil {
		return nil, false, l.stop(err)
	}
	if h.Version != 1 || h.Revision == 0 || h.Tail.Index == 0 ||
		h.Revision < l.head.Revision || h.Tail.Index < l.applied.Index ||
		h.Snapshot.Index > h.Tail.Index ||
		(h.Revision == l.head.Revision && h != l.head) {
		return nil, false, l.stop(ErrCorrupt)
	}
	// Only a fresh process installs a snapshot. An existing process replays
	// every missing record, including a pending operation's response. Retained
	// history makes that possible even while other writers publish checkpoints.
	if wanted == "" && l.applied.Index == 0 && h.Snapshot.Index != 0 {
		data, err := l.readRef(ctx, h.Snapshot, "snapshots")
		if err != nil {
			return nil, false, err
		}
		index, err := l.machine.Restore(data)
		if err != nil || index != h.Snapshot.Index {
			return nil, false, l.stop(fmt.Errorf("%w: snapshot restore at %d: %v", ErrCorrupt, index, err))
		}
		// Find the precise WAL reference at the restored index below, then
		// retain it to validate the link from the next record.
		l.applied.Index = index
	}
	var pending []struct {
		ref    ref
		record record
	}
	cursor := h.Tail
	for cursor.Index > l.applied.Index {
		data, err := l.readRef(ctx, cursor, "wal")
		if err != nil {
			return nil, false, err
		}
		var r record
		if err := decode(data, &r); err != nil {
			return nil, false, l.stop(err)
		}
		if r.ID == "" || r.Index != cursor.Index || r.Previous.Index != r.Index-1 ||
			len(r.Payload) == 0 || len(r.Payload) > maxEntryBytes ||
			(r.Previous.Index == 0 && r.Previous != (ref{})) {
			return nil, false, l.stop(ErrCorrupt)
		}
		pending = append(pending, struct {
			ref    ref
			record record
		}{cursor, r})
		cursor = r.Previous
	}
	if l.applied.Key == "" && l.applied.Index != 0 {
		l.applied = cursor
	}
	if cursor != l.applied {
		return nil, false, l.stop(fmt.Errorf("%w: history fork", ErrCorrupt))
	}
	var answer any
	found := false
	for i := len(pending) - 1; i >= 0; i-- {
		item := pending[i]
		res, err := l.apply(item.ref, item.record)
		if err != nil {
			return nil, false, err
		}
		l.stats.Replayed++
		if wanted != "" && item.record.ID == wanted {
			answer, found = res, true
		}
	}
	l.head, l.etag = h, obj.ETag
	return answer, found, nil
}

func (l *Log) apply(at ref, r record) (any, error) {
	if at.Index != l.applied.Index+1 || r.Previous != l.applied {
		return nil, l.stop(ErrCorrupt)
	}
	answer, err := l.machine.Apply(at.Index, r.Payload)
	if err != nil {
		return nil, l.stop(err)
	}
	l.applied = at
	return answer, nil
}

// Checkpoint publishes an encrypted snapshot through the same head CAS. A
// competing append may win; in that case the snapshot is an unreferenced object
// and no log record is removed. This pilot deliberately implements no GC.
func (l *Log) Checkpoint(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, _, err := l.sync(ctx, ""); err != nil {
		return err
	}
	if l.applied.Index == 0 || l.head.Snapshot.Index == l.applied.Index {
		return nil
	}
	if l.head.Revision == math.MaxUint64 {
		return l.stop(ErrCorrupt)
	}
	data, err := l.machine.Capture()
	if err != nil {
		return err
	}
	r, err := l.immutable(ctx, "snapshots", l.applied.Index, data)
	if err != nil {
		return err
	}
	next := l.head
	next.Revision++
	next.Snapshot = r
	etag, err := l.publish(ctx, next)
	if err != nil {
		return err
	}
	l.head, l.etag = next, etag
	return nil
}

func (l *Log) publish(ctx context.Context, h head) (string, error) {
	data, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	key := l.prefix + "/head"
	l.stats.Puts++
	return l.store.Put(ctx, key, l.seal(key, data), l.etag)
}

func (l *Log) immutable(ctx context.Context, kind string, index uint64, data []byte) (ref, error) {
	key := l.prefix + "/" + kind + "/" + randomID()
	body := l.seal(key, data)
	if len(body) > MaxObjectBytes {
		return ref{}, errors.New("object WAL: object exceeds 64 MiB pilot limit")
	}
	l.stats.Puts++
	if _, err := l.store.Put(ctx, key, body, ""); err != nil {
		// An upload may have landed without its response. Only identical bytes
		// at this never-reused random name allow us to proceed to publication.
		existing, readErr := l.get(ctx, key)
		if readErr != nil || !bytes.Equal(body, existing.Data) {
			return ref{}, err
		}
	}
	sum := sha256.Sum256(body)
	return ref{Key: key, Hash: hex.EncodeToString(sum[:]), Index: index}, nil
}

func (l *Log) readRef(ctx context.Context, r ref, kind string) ([]byte, error) {
	if r.Index == 0 || len(r.Hash) != 64 || !strings.HasPrefix(r.Key, l.prefix+"/"+kind+"/") {
		return nil, l.stop(ErrCorrupt)
	}
	obj, err := l.get(ctx, r.Key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(obj.Data)
	if hex.EncodeToString(sum[:]) != r.Hash {
		return nil, l.stop(ErrCorrupt)
	}
	data, err := l.open(r.Key, obj.Data)
	if err != nil {
		return nil, l.stop(err)
	}
	return data, nil
}

func (l *Log) get(ctx context.Context, key string) (Object, error) {
	l.stats.Gets++
	return l.store.Get(ctx, key)
}

func (l *Log) seal(key string, data []byte) []byte {
	return l.aead.Seal(nil, nil, data, []byte("c8s-object-wal-v1\x00"+l.scope+"\x00"+key))
}

func (l *Log) open(key string, data []byte) ([]byte, error) {
	if len(data) > MaxObjectBytes {
		return nil, ErrCorrupt
	}
	plain, err := l.aead.Open(nil, nil, data, []byte("c8s-object-wal-v1\x00"+l.scope+"\x00"+key))
	if err != nil {
		return nil, fmt.Errorf("%w: ciphertext authentication failed", ErrCorrupt)
	}
	return plain, nil
}

func (l *Log) stop(err error) error {
	if l.stopped == nil {
		l.stopped = err
	}
	return l.stopped
}

func randomID() string {
	var id [16]byte
	_, _ = rand.Read(id[:]) // crypto/rand.Read terminates the process on failure.
	return hex.EncodeToString(id[:])
}

func decode(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("%w: invalid JSON", ErrCorrupt)
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrCorrupt
	}
	return nil
}
