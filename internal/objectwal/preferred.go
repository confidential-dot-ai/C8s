package objectwal

import (
	"bytes"
	"context"
	"errors"
	"math"
	"time"
)

var (
	ErrNotWriter       = errors.New("object WAL: preferred writer changed")
	ErrRequestMismatch = errors.New("object WAL: invalid or conflicting forwarded request")
)

// Owner is a routing preference and fencing generation in the SAME CAS head
// as the committed tail. A clock or a separate lease object grants no authority.
type Owner struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Epoch   uint64 `json:"epoch"`
}

func (o Owner) valid() bool {
	return o == (Owner{}) || (o.ID != "" && len(o.ID) <= 128 && o.Address != "" && len(o.Address) <= 512 && o.Epoch != 0)
}

type WriterConfig struct {
	ID             string
	Address        string
	ForwardTimeout time.Duration
	// Forward sends exactly one request, with no transparent POST retries.
	// The receiver accepts it only under the supplied Owner generation. A
	// lost response is resolved from the log before the sender can take over.
	Forward func(context.Context, Owner, ForwardRequest) error
}

// ForwardRequest carries a whole local batch. After is the committed index
// the originating actor applied BEFORE its first forwarding attempt. That
// actor cannot apply other work until this batch has resolved, so replay can
// recover its original results even after a snapshot and writer replacement.
type ForwardRequest struct {
	Owner   Owner   `json:"owner"`
	After   uint64  `json:"after"`
	Entries []Entry `json:"entries"`
}

func (r ForwardRequest) valid() bool {
	if r.Owner.ID == "" || !r.Owner.valid() || len(r.Entries) == 0 || len(r.Entries) > maxBatchEntries {
		return false
	}
	return (record{Index: uint64(len(r.Entries)), Entries: r.Entries}).valid()
}

func (l *logState) claim(ctx context.Context) error {
	if l.head.Revision == math.MaxUint64 || l.head.Writer.Epoch == math.MaxUint64 {
		return l.stop(ErrCorrupt)
	}
	next := l.head
	next.Version = 2
	next.Revision++
	next.Writer = Owner{ID: l.options.Writer.ID, Address: l.options.Writer.Address, Epoch: l.head.Writer.Epoch + 1}
	etag, err := l.publish(ctx, next)
	if err != nil {
		return err
	}
	l.head, l.etag = next, etag
	l.stats.Takeovers++
	return nil
}

// acceptForwarded batches messages from other replicas. Duplicates are checked
// against retained committed history, not an unbounded in-memory request map.
// This path NEVER rebases across a writer generation: an obsolete writer must
// reject the request so its origin can resolve the outcome and route again.
func (l *logState) acceptForwarded(ctx context.Context, requests []*request) []error {
	errorsFor := make([]error, len(requests))
	if _, err := l.sync(ctx, nil); err != nil {
		for i := range errorsFor {
			errorsFor[i] = err
		}
		return errorsFor
	}
	owner := l.head.Writer
	var entries []entry
	var pending []int
	seen := map[string]bool{}
	for i, r := range requests {
		f := r.forward
		if l.options.Writer == nil || owner.ID != l.options.Writer.ID || f.Owner != owner {
			errorsFor[i] = ErrNotWriter
			continue
		}
		found, err := l.forwardedCommitted(ctx, *f)
		if err != nil {
			errorsFor[i] = err
			continue
		}
		if found {
			continue
		}
		duplicate := false
		for _, e := range f.Entries {
			if seen[e.ID] {
				duplicate = true
			}
		}
		// A duplicate still waiting in this same batch is refused, not written
		// twice. Its originating actor resolves via Sync just as for a lost reply.
		if duplicate {
			errorsFor[i] = ErrBackpressure
			continue
		}
		for _, e := range f.Entries {
			seen[e.ID] = true
			entries = append(entries, e)
		}
		pending = append(pending, i)
	}
	if len(entries) != 0 {
		_, err := l.appendBatch(ctx, entries, func() bool {
			for _, i := range pending {
				if requests[i].ctx.Err() == nil {
					return true
				}
			}
			return false
		}, &owner)
		for _, i := range pending {
			errorsFor[i] = err
		}
	}
	return errorsFor
}

func (l *logState) forwardedCommitted(ctx context.Context, request ForwardRequest) (bool, error) {
	if request.After > l.applied.Index {
		return false, ErrRequestMismatch
	}
	wanted := make(map[string][]byte, len(request.Entries))
	for _, e := range request.Entries {
		wanted[e.ID] = e.Payload
	}
	found := map[string]bool{}
	cursor := l.head.Tail
	readBytes, records := 0, 0
	for cursor.Index > request.After {
		data, err := l.readRef(ctx, cursor, "wal")
		if err != nil {
			return false, err
		}
		readBytes += len(data)
		records++
		if readBytes > l.options.ReplayBytes || records > 4096 {
			return false, ErrReplayLimit
		}
		var r record
		if err := decode(data, &r); err != nil {
			return false, l.stop(err)
		}
		if !r.valid() || r.Index != cursor.Index {
			return false, l.stop(ErrCorrupt)
		}
		for i, e := range r.entries() {
			if r.Previous.Index+uint64(i)+1 <= request.After {
				continue
			}
			if payload, ok := wanted[e.ID]; ok {
				if !bytes.Equal(payload, e.Payload) {
					return false, ErrRequestMismatch
				}
				found[e.ID] = true
			}
		}
		if len(found) == len(wanted) {
			return true, nil
		}
		cursor = r.Previous
	}
	if len(found) != 0 {
		return false, ErrRequestMismatch
	}
	return false, nil
}
