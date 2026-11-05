package cdsdirect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/directstate"
	"github.com/confidential-dot-ai/c8s/internal/requestgate"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

type policyReply struct {
	result cdsha.OperatorResult
	err    error
}
type policyRequest struct {
	ctx     context.Context
	command cdsha.OperatorCommand
	reply   chan policyReply
}

// One bounded mailbox per cluster combines already queued policy writes. The
// admission actor remains responsive while this worker does IO. It owns no
// authoritative state or lease: every batch reads current metadata and CASes
// all read predicates, just like an individual current-state transaction.
type policyBatcher struct {
	ctx                        context.Context
	cancel                     context.CancelFunc
	gate                       *requestgate.Gate
	inbox                      chan policyRequest
	done                       chan struct{}
	closed                     atomic.Bool
	batches, requests, largest atomic.Uint64
	apply                      func(context.Context, []cdsha.OperatorCommand) ([]cdsha.OperatorResult, error)
}

func newPolicyBatcher(parent context.Context, apply func(context.Context, []cdsha.OperatorCommand) ([]cdsha.OperatorResult, error)) *policyBatcher {
	ctx, cancel := context.WithCancel(parent)
	gate, _ := requestgate.New(ctx, directstate.ShardCapacity, directstate.ShardCapacity)
	b := &policyBatcher{ctx: ctx, cancel: cancel, gate: gate, inbox: make(chan policyRequest, directstate.ShardCapacity), done: make(chan struct{}), apply: apply}
	go b.run()
	return b
}

func (b *policyBatcher) submit(ctx context.Context, c cdsha.OperatorCommand) (cdsha.OperatorResult, error) {
	release, err := b.gate.Acquire(ctx)
	if err != nil {
		return cdsha.OperatorResult{}, err
	}
	defer release()
	r := policyRequest{ctx: ctx, command: c, reply: make(chan policyReply, 1)}
	b.inbox <- r // A reserved permit guarantees mailbox space, including shutdown.
	// Retain ownership of the caller's body until the worker finishes. Returning
	// on cancellation here would race the caller's plaintext buffer clearing.
	answer := <-r.reply
	return answer.result, answer.err
}

func (b *policyBatcher) close() {
	b.cancel()
	b.gate.Close() // All accepted senders have received their replies.
	if b.closed.CompareAndSwap(false, true) {
		close(b.inbox)
	}
	<-b.done
}

func (b *policyBatcher) run() {
	defer close(b.done)
	for first := range b.inbox {
		batch := []policyRequest{first}
		// One millisecond bounds the coalescing delay; existing operation
		// deadlines and the eight-request capacity are not extended.
		timer := time.NewTimer(time.Millisecond)
	collect:
		for len(batch) < directstate.ShardCapacity {
			select {
			case r := <-b.inbox:
				batch = append(batch, r)
			case <-timer.C:
				break collect
			case <-b.ctx.Done():
				break collect
			}
		}
		timer.Stop()
		b.execute(batch)
	}
}

func (b *policyBatcher) execute(batch []policyRequest) {
	active := batch[:0]
	for _, r := range batch {
		err := r.ctx.Err()
		if err == nil {
			err = b.ctx.Err()
		}
		if err != nil {
			r.reply <- policyReply{err: err}
		} else {
			active = append(active, r)
		}
	}
	if len(active) == 0 {
		return
	}
	ctx, cancel := context.WithCancel(b.ctx)
	defer cancel()
	commands := make([]cdsha.OperatorCommand, len(active))
	for i, r := range active {
		commands[i] = r.command
		stop := context.AfterFunc(r.ctx, cancel)
		defer stop()
	}
	b.batches.Add(1)
	b.requests.Add(uint64(len(commands)))
	// This worker is the only writer of the maximum; diagnostics only load.
	if uint64(len(commands)) > b.largest.Load() {
		b.largest.Store(uint64(len(commands)))
	}
	answers, err := b.apply(ctx, commands)
	if err == nil && len(answers) != len(active) {
		err = errors.New("direct state: missing policy batch decisions")
	}
	for i, r := range active {
		a := policyReply{err: err}
		if err == nil {
			a.result = answers[i]
		}
		r.reply <- a
	}
}

// All commands were authenticated before admission. Evaluate them in mailbox
// order in ONE disposable FSM, then publish one encrypted policy image and
// every token receipt atomically. A conflict re-evaluates the entire batch;
// an unknown commit outcome is never retried or acknowledged as successful.
func (s *State) applyPolicies(ctx context.Context, commands []cdsha.OperatorCommand) ([]cdsha.OperatorResult, error) {
	keys := []string{coreKey, policyKey}
	for _, c := range commands {
		key := spentKey(c.Token)
		if !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}
	answer, err := s.store.Update(ctx, policyKey, keys, func(v *directstate.View) (map[string][]byte, any, error) {
		if _, _, err := s.core(v); err != nil {
			return nil, nil, err
		}
		f, al, _, err := s.machine(v)
		if err != nil {
			return nil, nil, err
		}
		defer al.Close()
		writes := map[string][]byte{}
		good := false
		defer func() {
			if !good {
				for _, b := range writes {
					clear(b)
				}
			}
		}()
		answers := make([]cdsha.OperatorResult, len(commands))
		for i, c := range commands {
			key := spentKey(c.Token)
			_, spent := v.Get(key)
			if spent || writes[key] != nil {
				answers[i] = textResult(http.StatusConflict, operatorauth.ErrTokenReused.Error())
				continue
			}
			body, err := json.Marshal(cdsha.Entry{Kind: cdsha.KindOperator, Operator: &c})
			if err != nil {
				return nil, nil, err
			}
			r := f.Apply(uint64(i+1), body)
			clear(body)
			if r.Stop != nil {
				return nil, nil, r.Stop
			}
			if r.Operator == nil {
				return nil, nil, errors.New("direct state: missing operator decision")
			}
			answers[i] = *r.Operator
			writes[key], err = json.Marshal(answers[i])
			if err != nil {
				return nil, nil, err
			}
		}
		if len(writes) > 0 {
			writes[policyKey], err = policyBytes(al)
			if err != nil {
				return nil, nil, err
			}
		}
		good = true
		return writes, answers, nil
	})
	if err != nil {
		return nil, err
	}
	return answer.([]cdsha.OperatorResult), nil
}
