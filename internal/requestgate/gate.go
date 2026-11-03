// Package requestgate bounds a cluster's work before handlers read bodies or
// begin verification. An actor owns the queue and active permits; it never runs
// a handler or performs network/storage IO itself.
package requestgate

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
)

var (
	ErrBusy   = errors.New("request admission full")
	ErrClosed = errors.New("request admission closed")
)

const closedBit = uint64(1) << 63

type ticket struct {
	ctx      context.Context
	reply    chan error
	state    atomic.Uint32 // queued, granted, or canceled before grant
	released atomic.Bool
}

type Stats struct {
	Admitted int
	Active   int
	Rejected uint64
}

// Gate belongs to one cluster and traffic class. Capacity counts queued AND
// active requests, including canceled messages until the actor retires them.
// No process-wide budget lets one cluster consume another cluster's permits.
type Gate struct {
	workers, capacity int
	ctx               context.Context
	cancel            context.CancelFunc
	inbox             chan *ticket
	completed         chan *ticket
	wake              chan struct{}
	stopping, done    chan struct{}
	admitted          atomic.Uint64
	active            atomic.Int64
	rejected          atomic.Uint64
}

func New(parent context.Context, workers, capacity int) (*Gate, error) {
	if workers < 1 || capacity < workers || capacity > 65536 {
		return nil, errors.New("request gate requires 1 <= workers <= capacity <= 65536")
	}
	ctx, cancel := context.WithCancel(parent)
	g := &Gate{workers: workers, capacity: capacity, ctx: ctx, cancel: cancel,
		inbox: make(chan *ticket, capacity), completed: make(chan *ticket, capacity), wake: make(chan struct{}, 1),
		stopping: make(chan struct{}), done: make(chan struct{})}
	go g.run()
	return g, nil
}

func (g *Gate) Stats() Stats {
	return Stats{Admitted: int(g.admitted.Load() & ^closedBit), Active: int(g.active.Load()), Rejected: g.rejected.Load()}
}

// Close cancels admission and waits for active owners to release their permits.
// Handler propagates that cancellation into requests already executing.
func (g *Gate) Close() { g.admitted.Or(closedBit); g.cancel(); <-g.done }

func (g *Gate) reserve() error {
	for {
		held := g.admitted.Load()
		if held&closedBit != 0 {
			return ErrClosed
		}
		if held >= uint64(g.capacity) {
			g.rejected.Add(1)
			return ErrBusy
		}
		if g.admitted.CompareAndSwap(held, held+1) {
			return nil
		}
	}
}

func (g *Gate) signal() {
	select {
	case g.wake <- struct{}{}:
	default:
	}
}
func (g *Gate) retire() { g.admitted.Add(^uint64(0)); g.signal() }

// Acquire either returns a permit, an immediate capacity refusal, or waits in
// the bounded mailbox. A canceled waiter never enters its handler. A permit's
// release function is idempotent and must be called after the handler finishes.
func (g *Gate) Acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := g.reserve(); err != nil {
		return nil, err
	}
	t := &ticket{ctx: ctx, reply: make(chan error, 1)}
	select {
	case <-g.stopping:
		g.retire()
		return nil, ErrClosed
	case g.inbox <- t:
	}
	release := func() {
		if t.released.CompareAndSwap(false, true) {
			g.completed <- t
		}
	}
	for {
		select {
		case err := <-t.reply:
			if err != nil {
				return nil, err
			}
			if err := ctx.Err(); err != nil {
				release()
				return nil, err
			}
			if g.ctx.Err() != nil {
				release()
				return nil, ErrClosed
			}
			return release, nil
		case <-ctx.Done():
			if t.state.CompareAndSwap(0, 2) {
				g.signal()
				return nil, ctx.Err()
			}
			// A granted permit must be returned even when cancellation wins
			// the race with the buffered grant reply.
			if t.state.Load() == 1 {
				release()
			}
			return nil, ctx.Err()
		case <-g.stopping:
			if t.state.CompareAndSwap(0, 2) {
				g.signal()
				return nil, ErrClosed
			}
			if t.state.Load() == 1 {
				release()
			}
			return nil, ErrClosed
		}
	}
}

func (g *Gate) run() {
	defer close(g.done)
	var pending []*ticket
	active, closing := 0, false
	stop := g.ctx.Done()
	for {
		if !closing && g.ctx.Err() != nil {
			g.admitted.Or(closedBit)
			close(g.stopping)
			closing, stop = true, nil
		}
		kept := pending[:0]
		for _, t := range pending {
			err := t.ctx.Err()
			if closing {
				err = ErrClosed
			}
			if err != nil || t.state.Load() == 2 {
				if err == nil {
					err = context.Canceled
				}
				t.state.CompareAndSwap(0, 2)
				g.retire()
				t.reply <- err
				continue
			}
			if active < g.workers && t.state.CompareAndSwap(0, 1) {
				active++
				t.reply <- nil
				continue
			}
			kept = append(kept, t)
		}
		clear(pending[len(kept):])
		pending = kept
		g.active.Store(int64(active))
		if closing && g.admitted.Load()&^closedBit == 0 {
			return
		}
		select {
		case <-stop:
		case t := <-g.inbox:
			pending = append(pending, t)
		case <-g.completed:
			active--
			g.retire()
		case <-g.wake:
		}
	}
}

// Handler retains the original HTTP goroutine as the permit owner. The actor
// only schedules: it cannot be blocked by a slow verifier, body, or datastore.
func (g *Gate) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		release, err := g.Acquire(r.Context())
		if err != nil {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "CDS is busy or stopping; retry later", http.StatusServiceUnavailable)
			return
		}
		defer release()
		ctx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(g.ctx, cancel)
		defer func() { stop(); cancel() }()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
