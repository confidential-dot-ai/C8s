package taha

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cdschain"
)

func validateInput(cfg Config, store Store) error {
	if cfg.InputConfigMap == "" {
		return nil
	}
	if len(validation.IsDNS1123Subdomain(cfg.InputConfigMap)) != 0 || strings.HasPrefix(cfg.InputConfigMap, "cds-"+cfg.Cluster+"-") {
		return errors.New("policy input must name a ConfigMap outside the chain store's reserved names")
	}
	if _, ok := store.(*Kube); store != nil && !ok {
		return errors.New("policy input requires the Kubernetes chain store")
	}
	if cfg.StoreTimeout <= 0 {
		return errors.New("policy input requires a positive store timeout")
	}
	return nil
}

type inputResult struct {
	digest  [sha256.Size]byte
	head    cdschain.Head
	entry   cdschain.Hash
	seq     uint64
	outcome string
	reason  string
}

type inputPoller struct {
	name     string
	last     inputResult
	terminal bool
}

// poll never writes the input. Submit alone owns validation, catch-up and commit.
func (p *inputPoller) poll(ctx context.Context, r *Replica) (result inputResult, retry bool) {
	r.mu.Lock()
	store, ok := r.store.(*Kube)
	serving := r.slot() >= 0 && r.refusalLocked() == nil
	if r.state != nil {
		result.head = r.state.Head
	}
	r.mu.Unlock()
	result.outcome, result.reason = "waiting", "replica_not_serving"
	if !serving || !ok {
		return result, true
	}
	readCtx, cancel := context.WithTimeout(ctx, r.cfg.StoreTimeout)
	cm, err := store.ConfigMaps.Get(readCtx, p.name, metav1.GetOptions{})
	cancel()
	if err != nil {
		result.reason = "input_unavailable"
		return result, true
	}
	data := cm.BinaryData["entry"]
	result.digest = sha256.Sum256(data)
	result.outcome, result.reason = "invalid", "input_shape_or_size"
	if len(cm.Data) != 0 || len(cm.BinaryData) != 1 || len(data) == 0 || len(data) > MaxKubeEntry {
		return result, false
	}
	if p.terminal && result.digest == p.last.digest && result.head == p.last.head {
		return p.last, false
	}
	defer func() {
		// Key the result to the head BEFORE Submit: authority may change in flight.
		p.last, p.terminal = result, !retry
	}()
	e, err := cdschain.ParseEntry(data)
	if err != nil {
		result.reason = "invalid_encoding"
		return result, false
	}
	b, err := e.Decode()
	if err != nil || b.Seq == 0 || (b.Type != cdschain.TypePolicy && b.Type != cdschain.TypeRoutes) {
		result.reason = "invalid_body_or_type"
		return result, false
	}
	result.entry, result.seq = e.Hash(), b.Seq
	_, confirmed, err := r.Submit(ctx, e)
	switch {
	case errors.Is(err, ErrInvalid):
		result.reason = "entry_rejected"
	case errors.Is(err, ErrConflict):
		result.outcome, result.reason = "conflicting", "predecessor_changed"
	case err != nil || !confirmed:
		result.outcome, result.reason = "unconfirmed", "retry_same_artifact"
		return result, true
	default:
		result.outcome, result.reason = "confirmed", "accepted_history"
	}
	return result, false
}

func (r *Replica) consumeInput(ctx context.Context, name string) {
	poller := inputPoller{name: name}
	var logged inputResult
	delay := 5 * time.Second
	for ctx.Err() == nil {
		result, retry := poller.poll(ctx, r)
		if result != logged {
			slog.Info("Trust Authority policy input", "configmap", poller.name,
				"cluster", r.cfg.Cluster, "artifact_sha256", fmt.Sprintf("%x", result.digest),
				"input_entry_hash", result.entry, "input_seq", result.seq,
				"observed_head", result.head, "outcome", result.outcome, "reason", result.reason)
			logged = result
		}
		wait := 5 * time.Second
		if retry {
			delay = min(2*delay, time.Minute)
			wait = delay/2 + time.Duration(rand.Float64()*float64(delay/2))
		} else {
			delay = wait
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
