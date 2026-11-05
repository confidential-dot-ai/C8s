package objectwal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// Options bound admitted work, batching latency, and recovery memory. Admission
// includes the active batch: removing a message from the mailbox frees no slot
// until it has completed. Independent CDS histories have independent actors.
type Options struct {
	QueueCapacity    int
	QueueBytes       int64
	BatchEntries     int
	BatchBytes       int
	BatchDelay       time.Duration
	OperationTimeout time.Duration
	ReplayBytes      int
	Writer           *WriterConfig
}

func (o Options) Check() error { _, err := o.defaults(); return err }

func (o Options) defaults() (Options, error) {
	if o.QueueCapacity == 0 {
		o.QueueCapacity = 256
	}
	if o.QueueBytes == 0 {
		o.QueueBytes = 16 << 20
	}
	if o.BatchEntries == 0 {
		o.BatchEntries = 64
	}
	if o.BatchBytes == 0 {
		o.BatchBytes = 4 << 20
	}
	if o.BatchDelay == 0 {
		o.BatchDelay = 2 * time.Millisecond
	}
	if o.OperationTimeout == 0 {
		o.OperationTimeout = 5 * time.Second
	}
	if o.ReplayBytes == 0 {
		o.ReplayBytes = 64 << 20
	}
	if o.Writer != nil {
		writer := *o.Writer
		if !(Owner{ID: writer.ID, Address: writer.Address, Epoch: 1}).valid() || writer.Forward == nil {
			return o, errors.New("object WAL: preferred writer needs identity, address and transport")
		}
		if writer.ForwardTimeout == 0 {
			writer.ForwardTimeout = 2 * time.Second
		}
		if writer.ForwardTimeout < time.Millisecond || writer.ForwardTimeout > o.OperationTimeout {
			return o, errors.New("object WAL: invalid forwarding timeout")
		}
		o.Writer = &writer
	}
	if o.QueueCapacity < 1 || o.QueueCapacity > 65536 || o.QueueBytes < 1 || o.QueueBytes > 1<<30 ||
		o.BatchEntries < 1 || o.BatchEntries > maxBatchEntries || o.BatchBytes < 1 || o.BatchBytes > maxBatchBytes ||
		o.BatchDelay < 0 || o.BatchDelay > time.Second || o.OperationTimeout < time.Millisecond || o.OperationTimeout > time.Minute ||
		o.ReplayBytes < 1 || o.ReplayBytes > 256<<20 {
		return o, errors.New("object WAL: invalid actor capacity, batch, timeout or replay limits")
	}
	return o, nil
}

type operation uint8

const (
	appendOp operation = iota
	syncOp
	checkpointOp
	forwardOp
	conditionalAppendOp
)

type request struct {
	kind    operation
	ctx     context.Context
	entry   entry
	forward *ForwardRequest
	// expected is an application index, not a head revision: checkpoints and
	// preferred-writer changes do not change the state the command was built on.
	expected uint64
	size     int64
	reply    chan response
	// Only the admission/cancellation handshake is shared. The actor owns all
	// log state; a caller can cancel a queued message before it starts.
	state atomic.Uint32 // 0 queued, 1 executing, 2 canceled before execution
}

type response struct {
	value any
	err   error
}
type observation struct {
	stats Stats
	fresh time.Time
}

// Log owns no application mutex. Its actor alone touches the WAL and machine;
// callers use a bounded mailbox and readers load immutable status snapshots.
// Go's channel implementation has its own synchronization: this is an actor
// design, not a claim of formal lock-free progress during storage IO.
type Log struct {
	inbox             chan *request
	stopping          chan struct{}
	done              chan struct{}
	wake              chan struct{}
	cancel            context.CancelFunc
	options           Options
	view              atomic.Pointer[observation]
	admitted          atomic.Uint64
	admittedBytes     atomic.Int64
	peakAdmitted      atomic.Uint64
	peakAdmittedBytes atomic.Int64
	rejected          atomic.Uint64
}

const admissionClosed = uint64(1) << 63

// New starts a log actor. The owner must call Close before closing its machine.
// NewWithOptions also ties the actor's lifetime to a parent context.
func New(store Store, machine Machine, key []byte, prefix, scope string) (*Log, error) {
	return NewWithOptions(context.Background(), store, machine, key, prefix, scope, Options{})
}

func NewWithOptions(parent context.Context, store Store, machine Machine, key []byte, prefix, scope string, options Options) (*Log, error) {
	options, err := options.defaults()
	if err != nil {
		return nil, err
	}
	state, err := newState(store, machine, key, prefix, scope)
	if err != nil {
		return nil, err
	}
	state.options = options
	ctx, cancel := context.WithCancel(parent)
	l := &Log{inbox: make(chan *request, options.QueueCapacity), stopping: make(chan struct{}), done: make(chan struct{}), wake: make(chan struct{}, 1), cancel: cancel, options: options}
	l.publish(state)
	go l.run(ctx, state)
	return l, nil
}

func (l *Log) Close() { l.admitted.Or(admissionClosed); l.cancel(); <-l.done }

func (l *Log) Stats() Stats {
	s := l.view.Load().stats
	s.Admitted, s.AdmittedBytes, s.Rejected = int64(l.admitted.Load() & ^admissionClosed), l.admittedBytes.Load(), l.rejected.Load()
	s.AdmissionLimit, s.AdmissionByteLimit = l.options.QueueCapacity, l.options.QueueBytes
	s.PeakAdmitted, s.PeakAdmittedBytes = l.peakAdmitted.Load(), l.peakAdmittedBytes.Load()
	return s
}

// Fresh is dated before the successful observation's IO, never when a delayed
// response arrived. A failed actor operation clears it.
func (l *Log) Fresh() time.Time { return l.view.Load().fresh }

func (l *Log) Sync(ctx context.Context) error {
	_, err := l.submit(ctx, syncOp, nil)
	return err
}

func (l *Log) Checkpoint(ctx context.Context) error {
	_, err := l.submit(ctx, checkpointOp, nil)
	return err
}

// Append waits for durable publication and ordered application. Cancellation
// after execution starts reports an unknown outcome. It never silently retries
// a separate business request, nor lets one canceled caller cancel its batch.
func (l *Log) Append(ctx context.Context, payload []byte) (any, error) {
	if len(payload) == 0 || len(payload) > min(maxEntryBytes, l.options.BatchBytes) {
		return nil, errors.New("object WAL: entry must be between 1 byte and 4 MiB")
	}
	return l.submit(ctx, appendOp, payload)
}

// AppendIfCurrent commits one command only if expected is still the applied
// application index. A conflicting application write returns ErrStateChanged;
// the caller must re-evaluate its command against the new state. Lost replies
// are reconciled by request ID before testing the precondition again.
//
// Conditional maintenance is unbatched and publishes directly by head CAS,
// preserving the preferred writer's identity and epoch. It never forwards a
// stale command or changes writer ownership to perform maintenance. The entry
// and object formats are the same as Append's.
func (l *Log) AppendIfCurrent(ctx context.Context, expected uint64, payload []byte) (any, error) {
	if len(payload) == 0 || len(payload) > min(maxEntryBytes, l.options.BatchBytes) {
		return nil, errors.New("object WAL: entry must be between 1 byte and 4 MiB")
	}
	return l.submitRequest(ctx, conditionalAppendOp, payload, nil, expected)
}

// CommitForwarded is called only by the authenticated replica transport. A nil
// result is a durable receipt; the origin replays to recover its own FSM result.
func (l *Log) CommitForwarded(ctx context.Context, forwarded ForwardRequest) error {
	if !forwarded.valid() || len(forwarded.Entries) > l.options.BatchEntries {
		return ErrRequestMismatch
	}
	bytes := 0
	for _, e := range forwarded.Entries {
		bytes += len(e.Payload)
	}
	if bytes > l.options.BatchBytes {
		return ErrRequestMismatch
	}
	_, err := l.submitRequest(ctx, forwardOp, nil, &forwarded, 0)
	return err
}

func (l *Log) submit(ctx context.Context, kind operation, payload []byte) (any, error) {
	return l.submitRequest(ctx, kind, payload, nil, 0)
}

func (l *Log) submitRequest(ctx context.Context, kind operation, payload []byte, forwarded *ForwardRequest, expected uint64) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-l.stopping:
		return nil, ErrClosed
	default:
	}
	if err := l.admit(); err != nil {
		return nil, err
	}
	size := int64(len(payload))
	if forwarded != nil {
		for _, e := range forwarded.Entries {
			size += int64(len(e.Payload))
		}
	}
	if !reserve(&l.admittedBytes, &l.peakAdmittedBytes, size, l.options.QueueBytes) {
		l.releaseSlot()
		l.rejected.Add(1)
		return nil, ErrBackpressure
	}
	r := &request{kind: kind, ctx: ctx, reply: make(chan response, 1), size: size, expected: expected}
	if kind == appendOp || kind == conditionalAppendOp {
		r.entry = entry{ID: randomID(), Payload: bytes.Clone(payload)}
	}
	if forwarded != nil {
		copy := *forwarded
		copy.Entries = make([]Entry, len(forwarded.Entries))
		for i, e := range forwarded.Entries {
			copy.Entries[i] = Entry{ID: e.ID, Payload: bytes.Clone(e.Payload)}
		}
		r.forward = &copy
	}
	select {
	case <-l.stopping:
		l.release(r)
		return nil, ErrClosed
	case l.inbox <- r:
	default:
		l.release(r)
		l.rejected.Add(1)
		return nil, ErrBackpressure
	}
	select {
	case result := <-r.reply:
		return result.value, result.err
	case <-ctx.Done():
		if r.state.CompareAndSwap(0, 2) || !kind.appends() {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: %w", ErrInDoubt, ctx.Err())
	case <-l.stopping:
		// A buffered completion wins over shutdown when both are ready.
		select {
		case result := <-r.reply:
			return result.value, result.err
		default:
		}
		if kind.appends() && r.state.Load() == 1 {
			return nil, fmt.Errorf("%w: %w", ErrInDoubt, ErrClosed)
		}
		return nil, ErrClosed
	}
}

func (kind operation) appends() bool {
	return kind == appendOp || kind == forwardOp || kind == conditionalAppendOp
}

func (l *Log) admit() error {
	for {
		held := l.admitted.Load()
		if held&admissionClosed != 0 {
			return ErrClosed
		}
		if held >= uint64(l.options.QueueCapacity) {
			l.rejected.Add(1)
			return ErrBackpressure
		}
		if l.admitted.CompareAndSwap(held, held+1) {
			// Record the successful reservation value, not a later observation
			// which could miss a concurrent completion. Closed is not a slot.
			for peak := l.peakAdmitted.Load(); peak < held+1; peak = l.peakAdmitted.Load() {
				if l.peakAdmitted.CompareAndSwap(peak, held+1) {
					break
				}
			}
			return nil
		}
	}
}

func (l *Log) releaseSlot() {
	l.admitted.Add(^uint64(0))
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func reserve(counter, highWater *atomic.Int64, amount, limit int64) bool {
	for {
		old := counter.Load()
		if amount > limit-old {
			return false
		}
		if counter.CompareAndSwap(old, old+amount) {
			for peak := highWater.Load(); peak < old+amount; peak = highWater.Load() {
				if highWater.CompareAndSwap(peak, old+amount) {
					break
				}
			}
			return true
		}
	}
}

func (l *Log) release(r *request) {
	l.admittedBytes.Add(-r.size)
	l.releaseSlot()
}

func (l *Log) finish(r *request, value any, err error) {
	l.release(r)
	r.reply <- response{value, err} // buffer is owned by this one completion
}

func (l *Log) start(r *request) bool {
	if !r.state.CompareAndSwap(0, 1) || r.ctx.Err() != nil {
		l.finish(r, nil, r.ctx.Err())
		return false
	}
	return true
}

func (l *Log) publish(state *logState) {
	l.view.Store(&observation{stats: state.Stats(), fresh: state.fresh})
}

func (l *Log) run(ctx context.Context, state *logState) {
	var pending *request
	defer func() {
		l.admitted.Or(admissionClosed)
		close(l.stopping)
		state.fresh = time.Time{}
		l.publish(state)
		if pending != nil {
			l.finish(pending, nil, ErrClosed)
		}
		// Admission and shutdown share one atomic word. Already-admitted
		// senders may still be copying a payload; drain them before closing.
		for l.admitted.Load() & ^admissionClosed != 0 {
			select {
			case r := <-l.inbox:
				l.finish(r, nil, ErrClosed)
			case <-l.wake:
			}
		}
		close(l.done)
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		r := pending
		pending = nil
		if r == nil {
			select {
			case <-ctx.Done():
				return
			case r = <-l.inbox:
			}
		}
		if r.kind == appendOp || r.kind == forwardOp {
			batch := []*request{r}
			size := r.size
			count := r.commands()
			timer := time.NewTimer(l.options.BatchDelay)
		collect:
			for count < l.options.BatchEntries && size < int64(l.options.BatchBytes) {
				select {
				case <-ctx.Done():
					break collect
				case <-timer.C:
					break collect
				case next := <-l.inbox:
					if next.kind != r.kind || size+next.size > int64(l.options.BatchBytes) || count+next.commands() > l.options.BatchEntries {
						pending = next
						break collect
					}
					batch = append(batch, next)
					size += next.size
					count += next.commands()
				}
			}
			timer.Stop()
			active := batch[:0]
			var entries []entry
			for _, item := range batch {
				if l.start(item) {
					active = append(active, item)
					if item.kind == appendOp {
						entries = append(entries, item.entry)
					}
				}
			}
			if len(active) == 0 {
				continue
			}
			operation, cancel := context.WithTimeout(ctx, l.options.OperationTimeout)
			start := time.Now()
			if r.kind == forwardOp {
				errorsFor := state.acceptForwarded(operation, active)
				cancel()
				state.fresh = start
				for _, err := range errorsFor {
					if err != nil {
						state.fresh = time.Time{}
					}
				}
				l.publish(state)
				for i, item := range active {
					l.finish(item, nil, errorsFor[i])
				}
				continue
			}
			answers, err := state.appendBatch(operation, entries, func() bool {
				for _, item := range active {
					if item.ctx.Err() == nil {
						return true
					}
				}
				return false
			}, nil)
			cancel()
			state.fresh = start
			if err != nil {
				state.fresh = time.Time{}
			}
			l.publish(state)
			for _, item := range active {
				l.finish(item, answers[item.entry.ID], err)
			}
			continue
		}
		group := []*request{r}
		// Readers already queued before this observation share its GET. A
		// reader arriving during IO waits for the next fresh observation.
		if r.kind == syncOp {
		drain:
			for len(group) < l.options.QueueCapacity {
				select {
				case next := <-l.inbox:
					if next.kind != syncOp {
						pending = next
						break drain
					}
					group = append(group, next)
				default:
					break drain
				}
			}
		}
		active := group[:0]
		for _, item := range group {
			if l.start(item) {
				active = append(active, item)
			}
		}
		if len(active) == 0 {
			continue
		}
		operation, cancel := context.WithTimeout(ctx, l.options.OperationTimeout)
		start := time.Now()
		var err error
		var value any
		switch r.kind {
		case syncOp:
			err = state.Sync(operation)
		case checkpointOp:
			err = state.Checkpoint(operation)
		case conditionalAppendOp:
			var answers map[string]any
			answers, err = state.appendBatchIfCurrent(operation, []entry{r.entry}, func() bool {
				return r.ctx.Err() == nil
			}, nil, &r.expected)
			value = answers[r.entry.ID]
		}
		cancel()
		state.fresh = start
		if err != nil && !errors.Is(err, ErrStateChanged) {
			state.fresh = time.Time{}
		}
		l.publish(state)
		for _, item := range active {
			l.finish(item, value, err)
		}
	}
}

func (r *request) commands() int {
	if r.kind == forwardOp {
		return len(r.forward.Entries)
	}
	return 1
}
