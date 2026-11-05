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
	"time"
)

const (
	maxEntryBytes   = 4 << 20
	maxBatchEntries = 128
	maxBatchBytes   = 8 << 20
)

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
	Writer   Owner  `json:"writer,omitempty"`
}

type record struct {
	ID       string  `json:"id,omitempty"` // version-one records
	Index    uint64  `json:"index"`
	Previous ref     `json:"previous"`
	Payload  []byte  `json:"payload,omitempty"` // version-one records
	Entries  []entry `json:"entries,omitempty"`
}

type Entry struct {
	ID      string `json:"id"`
	Payload []byte `json:"payload"`
}

type entry = Entry

type Stats struct {
	Applied            uint64 `json:"applied"`
	Revision           uint64 `json:"revision"`
	Snapshot           uint64 `json:"snapshot"`
	Gets               uint64 `json:"gets"`
	Puts               uint64 `json:"puts"`
	Conflicts          uint64 `json:"conflicts"`
	Ambiguous          uint64 `json:"ambiguous"`
	Replayed           uint64 `json:"replayed"`
	Stopped            bool   `json:"stopped"`
	Batches            uint64 `json:"batches"`
	CommittedCommands  uint64 `json:"committed_commands"`
	LargestBatch       uint64 `json:"largest_batch"`
	Admitted           int64  `json:"admitted"`
	AdmittedBytes      int64  `json:"admitted_bytes"`
	AdmissionLimit     int    `json:"admission_limit"`
	AdmissionByteLimit int64  `json:"admission_byte_limit"`
	Rejected           uint64 `json:"rejected"`
	Writer             Owner  `json:"writer"`
	Forwarded          uint64 `json:"forwarded"`
	Takeovers          uint64 `json:"takeovers"`
}

type logState struct {
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
	options Options
	fresh   time.Time
}

// New opens no objects and changes no state. scope binds ciphertext to the
// cluster and measured configuration; prefix is an exclusive, nonempty object
// namespace. The 256-bit key is provisioned into TEE memory, never a launch file.
func newState(store Store, machine Machine, key []byte, prefix, scope string) (*logState, error) {
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
	return &logState{store: store, machine: machine, aead: aead, prefix: prefix, scope: scope}, nil
}

func (l *logState) Stats() Stats {
	s := l.stats
	s.Applied, s.Revision, s.Snapshot = l.applied.Index, l.head.Revision, l.head.Snapshot.Index
	s.Stopped = l.stopped != nil
	s.Writer = l.head.Writer
	return s
}

// Sync establishes a fresh read watermark and applies through it. Polling or a
// successful upload is not a substitute for this operation before a fresh read.
func (l *logState) Sync(ctx context.Context) error {
	_, err := l.sync(ctx, nil)
	return err
}

// Append acknowledges only after the head CAS committed and the machine applied
// this request. Its private request ID is reused across every attempt. After an
// ambiguous response we replay the authoritative history before retrying, even
// if another writer has already advanced the head past our record.
func (l *logState) appendBatch(ctx context.Context, entries []entry, live func() bool, required *Owner) (map[string]any, error) {
	return l.appendBatchIfCurrent(ctx, entries, live, required, nil)
}

func (l *logState) appendBatchIfCurrent(ctx context.Context, entries []entry, live func() bool, required *Owner, expected *uint64) (map[string]any, error) {
	wanted := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		wanted[e.ID] = struct{}{}
	}
	uncertain := false
	var failedOwner *Owner
	acknowledged := false
	for {
		answers, err := l.sync(ctx, wanted)
		if err != nil {
			if uncertain {
				return nil, fmt.Errorf("%w: %w", ErrInDoubt, err)
			}
			return nil, err
		}
		if len(answers) == len(entries) {
			return answers, nil
		}
		// Resolve a possibly committed request first. A newer index is not a
		// failed precondition when this very request advanced the history.
		if expected != nil && l.applied.Index != *expected {
			return nil, ErrStateChanged
		}
		if required != nil && l.head.Writer != *required {
			return nil, ErrNotWriter
		}
		if len(answers) != 0 {
			return nil, l.stop(fmt.Errorf("%w: partially committed batch", ErrCorrupt))
		}
		if acknowledged {
			return nil, fmt.Errorf("%w: preferred writer acknowledged no committed batch", ErrInDoubt)
		}
		if err := ctx.Err(); err != nil {
			if uncertain {
				return nil, fmt.Errorf("%w: %w", ErrInDoubt, err)
			}
			return nil, err
		}
		if !live() {
			if uncertain {
				return nil, fmt.Errorf("%w: %w", ErrInDoubt, context.Canceled)
			}
			return nil, context.Canceled
		}
		var takeover *Owner
		if writer := l.options.Writer; expected == nil && writer != nil && l.head.Writer.ID != writer.ID {
			owner := l.head.Writer
			if required != nil {
				return nil, ErrNotWriter
			}
			// A replacement at the previous writer's address cannot forward
			// to itself: its actor would wait for work queued to that same
			// actor. Claim the new generation by CAS instead. The address is
			// only a routing hint; the head CAS still fences every writer.
			if owner.ID != "" && owner.Address != writer.Address && (failedOwner == nil || *failedOwner != owner) {
				forwardCtx, cancel := context.WithTimeout(ctx, writer.ForwardTimeout)
				l.stats.Forwarded++
				err := writer.Forward(forwardCtx, owner, ForwardRequest{Owner: owner, After: l.applied.Index, Entries: entries})
				cancel()
				if errors.Is(err, ErrBackpressure) || errors.Is(err, ErrRequestMismatch) {
					return nil, err
				}
				// A transport error can hide a commit. The next Sync searches
				// every record since forwarding began before any replacement write.
				uncertain = true
				if err == nil {
					acknowledged = true
				} else {
					failedOwner = &owner
				}
				continue
			}
			if owner.Epoch == math.MaxUint64 {
				return nil, l.stop(ErrCorrupt)
			}
			// Publish ownership together with this batch. A separate claim
			// lets overlapping replacements repeatedly steal ownership without
			// committing any work. Every successful takeover now advances the
			// application history, under the same CAS fencing condition.
			takeover = &Owner{ID: writer.ID, Address: writer.Address, Epoch: owner.Epoch + 1}
		}
		if l.head.Revision == math.MaxUint64 || l.applied.Index > math.MaxUint64-uint64(len(entries)) {
			return nil, l.stop(errors.New("object WAL: sequence exhausted"))
		}
		r := record{Index: l.applied.Index + uint64(len(entries)), Previous: l.applied, Entries: entries}
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
		next.Version, next.Revision, next.Tail = 2, l.head.Revision+1, written
		if takeover != nil {
			next.Writer = *takeover
		}
		etag, err := l.publish(ctx, next)
		if err != nil {
			if errors.Is(err, ErrConflict) {
				l.stats.Conflicts++
			} else {
				uncertain = true
				l.stats.Ambiguous++
			}
			// Back off contention and outage retries, bounded by the caller.
			if err := retryDelay(ctx); err != nil {
				if uncertain {
					return nil, fmt.Errorf("%w: %w", ErrInDoubt, err)
				}
				return nil, err
			}
			continue
		}
		// The object store has committed. Apply exactly these bytes; subsequent
		// writers may already have published newer records, which Sync will read.
		l.head, l.etag = next, etag
		if takeover != nil {
			l.stats.Takeovers++
		}
		answers, err = l.apply(written, r)
		if err == nil {
			l.committedBatch(len(entries))
		}
		return answers, err
	}
}

func (l *logState) committedBatch(size int) {
	l.stats.Batches++
	l.stats.CommittedCommands += uint64(size)
	l.stats.LargestBatch = max(l.stats.LargestBatch, uint64(size))
}

func retryDelay(ctx context.Context) error {
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (l *logState) sync(ctx context.Context, wanted map[string]struct{}) (map[string]any, error) {
	if l.stopped != nil {
		return nil, l.stopped
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	obj, err := l.get(ctx, l.prefix+"/head")
	if errors.Is(err, ErrNotFound) && l.applied.Index == 0 && l.head.Revision == 0 {
		return nil, nil
	}
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			err = l.stop(fmt.Errorf("%w: head disappeared", ErrCorrupt))
		}
		return nil, err
	}
	if obj.ETag == "" {
		return nil, l.stop(fmt.Errorf("%w: head has no ETag", ErrCorrupt))
	}
	plain, err := l.open(l.prefix+"/head", obj.Data)
	if err != nil {
		return nil, l.stop(err)
	}
	var h head
	if err := decode(plain, &h); err != nil {
		return nil, l.stop(err)
	}
	if (h.Version != 1 && h.Version != 2) || h.Revision == 0 ||
		(h.Tail.Index == 0 && (h.Version != 2 || h.Writer.ID == "" || h.Tail != (ref{}))) ||
		!h.Writer.valid() || h.Writer.Epoch > h.Revision ||
		h.Revision < l.head.Revision || h.Tail.Index < l.applied.Index ||
		h.Snapshot.Index > h.Tail.Index ||
		(h.Revision == l.head.Revision && h != l.head) {
		return nil, l.stop(ErrCorrupt)
	}
	// Only a fresh process installs a snapshot. An existing process replays
	// every missing record, including a pending operation's response. Retained
	// history makes that possible even while other writers publish checkpoints.
	if len(wanted) == 0 && l.applied.Index == 0 && h.Snapshot.Index != 0 {
		data, err := l.readRef(ctx, h.Snapshot, "snapshots")
		if err != nil {
			return nil, err
		}
		index, err := l.machine.Restore(data)
		if err != nil || index != h.Snapshot.Index {
			return nil, l.stop(fmt.Errorf("%w: snapshot restore at %d: %v", ErrCorrupt, index, err))
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
	replayBytes := 0
	for cursor.Index > l.applied.Index {
		data, err := l.readRef(ctx, cursor, "wal")
		if err != nil {
			return nil, err
		}
		replayBytes += len(data)
		if replayBytes > l.options.ReplayBytes || len(pending) >= 4096 {
			return nil, ErrReplayLimit
		}
		var r record
		if err := decode(data, &r); err != nil {
			return nil, l.stop(err)
		}
		if !r.valid() || r.Index != cursor.Index {
			return nil, l.stop(ErrCorrupt)
		}
		pending = append(pending, struct {
			ref    ref
			record record
		}{cursor, r})
		cursor = r.Previous
	}
	if l.applied.Key == "" && l.applied.Index != 0 {
		if cursor.Index != l.applied.Index {
			return nil, l.stop(ErrCorrupt)
		}
		l.applied = cursor
	}
	if cursor != l.applied {
		return nil, l.stop(fmt.Errorf("%w: history fork", ErrCorrupt))
	}
	answers := make(map[string]any, len(wanted))
	for i := len(pending) - 1; i >= 0; i-- {
		item := pending[i]
		res, err := l.apply(item.ref, item.record)
		if err != nil {
			return nil, err
		}
		l.stats.Replayed += uint64(len(res))
		for id, answer := range res {
			if _, ok := wanted[id]; ok {
				answers[id] = answer
			}
		}
	}
	l.head, l.etag = h, obj.ETag
	return answers, nil
}

func (l *logState) apply(at ref, r record) (map[string]any, error) {
	if !r.valid() || at.Index != r.Index || r.Previous != l.applied {
		return nil, l.stop(ErrCorrupt)
	}
	entries := r.entries()
	answers := make(map[string]any, len(entries))
	for i, e := range entries {
		answer, err := l.machine.Apply(r.Previous.Index+uint64(i)+1, e.Payload)
		if err != nil {
			return nil, l.stop(err)
		}
		answers[e.ID] = answer
	}
	l.applied = at
	return answers, nil
}

func (r record) entries() []entry {
	if len(r.Entries) != 0 {
		return r.Entries
	}
	return []entry{{ID: r.ID, Payload: r.Payload}}
}

func (r record) valid() bool {
	if len(r.Entries) > 0 && (r.ID != "" || len(r.Payload) != 0) {
		return false
	}
	entries := r.entries()
	if len(entries) > maxBatchEntries || r.Index <= r.Previous.Index || r.Index-r.Previous.Index != uint64(len(entries)) ||
		(r.Previous.Index == 0 && r.Previous != (ref{})) {
		return false
	}
	seen := make(map[string]struct{}, len(entries))
	bytes := 0
	for _, e := range entries {
		if e.ID == "" || len(e.ID) > 128 || len(e.Payload) == 0 || len(e.Payload) > maxEntryBytes {
			return false
		}
		if _, ok := seen[e.ID]; ok {
			return false
		}
		seen[e.ID] = struct{}{}
		bytes += len(e.Payload)
	}
	return bytes <= maxBatchBytes
}

// Checkpoint publishes an encrypted snapshot through the same head CAS. A
// competing append may win; in that case the snapshot is an unreferenced object
// and no log record is removed. This pilot deliberately implements no GC.
func (l *logState) Checkpoint(ctx context.Context) error {
	if _, err := l.sync(ctx, nil); err != nil {
		return err
	}
	if l.applied.Index == 0 || l.head.Snapshot.Index == l.applied.Index {
		return nil
	}
	if writer := l.options.Writer; writer != nil && l.head.Writer.ID != writer.ID {
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
	next.Version = 2
	next.Revision++
	next.Snapshot = r
	etag, err := l.publish(ctx, next)
	if err != nil {
		return err
	}
	l.head, l.etag = next, etag
	return nil
}

func (l *logState) publish(ctx context.Context, h head) (string, error) {
	data, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	key := l.prefix + "/head"
	l.stats.Puts++
	return l.store.Put(ctx, key, l.seal(key, data), l.etag)
}

func (l *logState) immutable(ctx context.Context, kind string, index uint64, data []byte) (ref, error) {
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

func (l *logState) readRef(ctx context.Context, r ref, kind string) ([]byte, error) {
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

func (l *logState) get(ctx context.Context, key string) (Object, error) {
	l.stats.Gets++
	return l.store.Get(ctx, key)
}

func (l *logState) seal(key string, data []byte) []byte {
	return l.aead.Seal(nil, nil, data, []byte("c8s-object-wal-v1\x00"+l.scope+"\x00"+key))
}

func (l *logState) open(key string, data []byte) ([]byte, error) {
	if len(data) > MaxObjectBytes {
		return nil, ErrCorrupt
	}
	plain, err := l.aead.Open(nil, nil, data, []byte("c8s-object-wal-v1\x00"+l.scope+"\x00"+key))
	if err != nil {
		return nil, fmt.Errorf("%w: ciphertext authentication failed", ErrCorrupt)
	}
	return plain, nil
}

func (l *logState) stop(err error) error {
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
