package casregister

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"math"
	randv2 "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

const (
	queued uint32 = iota
	preparing
	accepting
	finished
	canceled
)

type Transform = func([]byte) ([]byte, error)

type Proposer struct {
	peers   [3]Peer
	slots   [3]chan struct{}
	cluster string
	owner   [32]byte
	round   uint64
	inbox   chan *proposal
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	workers sync.WaitGroup
}

type proposal struct {
	ctx       context.Context
	transform Transform
	phase     atomic.Uint32
	result    chan proposalResult
}

type proposalResult struct {
	value []byte
	err   error
}

type peerReply struct {
	promise Promise
	err     error
}

func NewProposer(
	peers []Peer,
	cluster string,
	queueSize int,
) (*Proposer, error) {
	if len(peers) != 3 || cluster == "" || len(cluster) > 256 || queueSize < 1 || queueSize > 1024 {
		return nil, ErrInvalid
	}
	identities := make(map[string]bool)
	for _, peer := range peers {
		if peer == nil || peer.ID() == "" || identities[peer.ID()] {
			return nil, ErrInvalid
		}
		identities[peer.ID()] = true
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Proposer{
		cluster: cluster,
		inbox: make(
			chan *proposal,
			queueSize,
		),
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	if _, err := rand.Read(p.owner[:]); err != nil {
		cancel()
		return nil, err
	}
	if p.owner == [32]byte{} {
		cancel()
		return nil, ErrInvalid
	}
	copy(
		p.peers[:],
		peers,
	)
	for i := range p.slots {
		p.slots[i] = make(
			chan struct{},
			1,
		)
	}
	go p.run()
	return p, nil
}

// Update retries only before acceptance. Once acceptance may have been sent,
// losing a quorum response returns ErrUnknown without rerunning the transform.
// The transform executes on the owner and must be bounded and free of effects.
// Its errors abort computation; a state-dependent refusal must return the current
// value with nil error so identity acceptance makes that observation durable.
// The returned value belongs to the caller and does not alias pending peer calls.
func (p *Proposer) Update(
	ctx context.Context,
	transform Transform,
) ([]byte, error) {
	if transform == nil {
		return nil, errors.Join(
			ErrUnavailable,
			ErrInvalid,
		)
	}
	ctx, cancel := context.WithTimeout(
		ctx,
		5*time.Second,
	)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(
			ErrUnavailable,
			err,
		)
	}
	r := &proposal{
		ctx:       ctx,
		transform: transform,
		result: make(
			chan proposalResult,
			1,
		),
	}
	select {
	case <-p.ctx.Done():
		return nil, errors.Join(
			ErrUnavailable,
			ErrClosed,
		)
	case p.inbox <- r:
	default:
		return nil, errors.Join(
			ErrUnavailable,
			ErrBusy,
		)
	}
	select {
	case result := <-r.result:
		return result.value, result.err
	case <-ctx.Done():
		return r.cancel(ctx.Err())
	case <-p.ctx.Done():
		return r.cancel(ErrClosed)
	}
}

func (r *proposal) cancel(cause error) ([]byte, error) {
	for {
		switch phase := r.phase.Load(); phase {
		case queued:
			// Winning this CAS prevents the owner from dispatching acceptance.
			if r.phase.CompareAndSwap(
				phase,
				canceled,
			) {
				return nil, errors.Join(
					ErrUnavailable,
					cause,
				)
			}
		case preparing:
			if r.phase.CompareAndSwap(
				preparing,
				canceled,
			) {
				// Captured application input remains owned until the callback exits.
				<-r.result
				return nil, errors.Join(
					ErrUnavailable,
					cause,
				)
			}
		case accepting:
			return nil, errors.Join(
				ErrUnknown,
				cause,
			)
		case finished:
			result := <-r.result
			return result.value, result.err
		case canceled:
			return nil, errors.Join(
				ErrUnavailable,
				cause,
			)
		}
	}
}

// Read commits an identity transformation; prepare-only maximum reads are unsafe.
func (p *Proposer) Read(ctx context.Context) ([]byte, error) {
	return p.Update(
		ctx,
		func(value []byte) ([]byte, error) { return value, nil },
	)
}

func (p *Proposer) Close() {
	p.cancel()
	<-p.done
	p.workers.Wait()
}

func (p *Proposer) run() {
	defer close(p.done)
	for {
		select {
		case <-p.ctx.Done():
			return
		case r := <-p.inbox:
			if !r.phase.CompareAndSwap(
				queued,
				preparing,
			) {
				continue
			}
			ctx, cancel := context.WithCancel(r.ctx)
			stop := context.AfterFunc(
				p.ctx,
				cancel,
			)
			value, err := p.execute(
				ctx,
				r,
			)
			stop()
			cancel()
			r.result <- proposalResult{
				value: value,
				err:   err,
			}
			r.phase.Store(finished)
		}
	}
}

func (p *Proposer) execute(
	ctx context.Context,
	r *proposal,
) ([]byte, error) {
	var last error
	for attempt := range 16 {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(
				ErrUnavailable,
				err,
			)
		}
		if p.round == math.MaxUint64 {
			return nil, errors.Join(
				ErrUnavailable,
				ErrInvalid,
			)
		}
		p.round++
		ballot := Ballot{
			Round: p.round,
			Owner: p.owner,
		}
		promises, err := p.quorum(
			ctx,
			ballot,
			nil,
			false,
		)
		if err != nil {
			last = err
			if err := backoff(
				ctx,
				attempt,
			); err != nil {
				return nil, errors.Join(
					ErrUnavailable,
					err,
				)
			}
			continue
		}
		base := promises[0]
		for _, promise := range promises[1:] {
			if promise.Accepted == base.Accepted && !bytes.Equal(
				promise.Value,
				base.Value,
			) {
				return nil, errors.Join(
					ErrUnavailable,
					ErrEquivocation,
				)
			}
			if promise.Accepted.Compare(base.Accepted) > 0 {
				base = promise
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(
				ErrUnavailable,
				err,
			)
		}
		candidate, err := r.transform(bytes.Clone(base.Value))
		if err != nil {
			return nil, errors.Join(
				ErrUnavailable,
				err,
			)
		}
		if len(candidate) > MaxValueBytes {
			return nil, errors.Join(
				ErrUnavailable,
				ErrInvalid,
			)
		}
		candidate = bytes.Clone(candidate)
		if ctx.Err() != nil || !r.phase.CompareAndSwap(
			preparing,
			accepting,
		) {
			return nil, errors.Join(
				ErrUnavailable,
				ctx.Err(),
			)
		}
		if _, err := p.quorum(
			ctx,
			ballot,
			candidate,
			true,
		); err != nil {
			return nil, errors.Join(
				ErrUnknown,
				err,
			)
		}
		return bytes.Clone(candidate), nil
	}
	return nil, errors.Join(
		ErrUnavailable,
		last,
	)
}

func backoff(
	ctx context.Context,
	attempt int,
) error {
	maximum := time.Millisecond << min(
		attempt,
		5,
	)
	timer := time.NewTimer(maximum/2 + time.Duration(randv2.Int64N(int64(maximum/2)+1)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (p *Proposer) quorum(
	ctx context.Context,
	ballot Ballot,
	value []byte,
	accept bool,
) ([]Promise, error) {
	ctx, cancel := context.WithTimeout(
		ctx,
		time.Second,
	)
	defer cancel()
	replies := make(
		chan peerReply,
		3,
	)
	for i, peer := range p.peers {
		select {
		case p.slots[i] <- struct{}{}:
			p.workers.Add(1)
			go func() {
				defer p.workers.Done()
				var reply peerReply
				if accept {
					reply.err = peer.Accept(
						ctx,
						p.cluster,
						ballot,
						value,
					)
				} else {
					reply.promise, reply.err = peer.Prepare(
						ctx,
						p.cluster,
						ballot,
					)
				}
				<-p.slots[i]
				replies <- reply
			}()
		default:
			replies <- peerReply{err: ErrBusy}
		}
	}
	var good []Promise
	var last error
	for range 3 {
		select {
		case <-ctx.Done():
			return nil, errors.Join(
				last,
				ctx.Err(),
			)
		case reply := <-replies:
			if reply.err != nil {
				last = reply.err
				var higher *Preempted
				if errors.As(
					reply.err,
					&higher,
				) {
					p.round = max(
						p.round,
						higher.Promise.Round,
					)
				}
				continue
			}
			if len(reply.promise.Value) > MaxValueBytes || reply.promise.Accepted.Compare(ballot) > 0 {
				return nil, ErrInvalid
			}
			good = append(
				good,
				reply.promise,
			)
			if len(good) == 2 {
				return good, nil
			}
		}
	}
	return nil, errors.Join(
		ErrUnavailable,
		last,
	)
}
