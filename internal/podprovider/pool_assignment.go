package podprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
)

type assignmentSession interface {
	ServingKey() []byte
	Prepare(context.Context, *ecdsa.PrivateKey, []byte, []byte, []byte) ([]byte, error)
	Send(context.Context, []byte) (string, error)
	Close()
}

type assignmentVerifier func(context.Context, *poolRecord, string) (assignmentSession, error)

func verifyAssignmentTarget(ctx context.Context, p *poolRecord, address string) (assignmentSession, error) {
	cfg, cleanup, err := attestConfig(address, p.Request.Trust.LaunchKey, p.Manifest)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	target, err := podstatus.VerifyAssignmentTarget(ctx, cfg)
	if err != nil {
		return nil, errors.New("generic guest attestation unavailable")
	}
	return target, nil
}

func (r *Reconciler) assignmentTarget(ctx context.Context, p *poolRecord, address string) (assignmentSession, error) {
	verify := r.assignment
	if verify == nil {
		verify = verifyAssignmentTarget
	}
	return verify(ctx, p, address)
}

func assignmentPayload(rec *record) ([]byte, []byte, []byte, error) {
	doc, err := rec.document()
	if err != nil {
		return nil, nil, nil, err
	}
	peers := doc.Pod.MeshPeers
	if peers == nil {
		peers = []string{}
	}
	data, err := json.Marshal(peers)
	return []byte(doc.Pod.Manifest), []byte(doc.Workloads), data, err
}

// assignPool verifies the slot, signs the assignment over that connection's
// serving key and persists the bytes before sending them. A persisted
// assignment is sent again unchanged, and only to the same serving key.
func (r *Reconciler) assignPool(ctx context.Context, rec *record, p *poolRecord, secret *corev1.Secret, address string) error {
	if len(p.Assignment) == 0 && p.Request.Trust.LaunchKey != r.cfg.pub {
		return errors.New("provider launch key changed before assignment")
	}
	target, err := r.assignmentTarget(ctx, p, address)
	if err != nil {
		return err
	}
	defer target.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if r.verificationExpired(rec) {
		return context.DeadlineExceeded
	}
	if len(p.Assignment) == 0 {
		manifest, entries, peers, err := assignmentPayload(rec)
		if err != nil {
			return err
		}
		data, err := target.Prepare(ctx, r.cfg.key, manifest, entries, peers)
		if err != nil {
			return errors.New("guest assignment preparation unavailable")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if r.verificationExpired(rec) {
			return context.DeadlineExceeded
		}
		p.Assignment, p.ServingKey = data, target.ServingKey()
		// Publication is the only permission to POST. On conflict or lost write,
		// reconcile reloads this exact intent rather than generating another one.
		if err := r.savePool(ctx, p, secret); err != nil {
			return err
		}
	} else if !bytes.Equal(p.ServingKey, target.ServingKey()) {
		return errors.New("assignment serving key changed; retaining the immutable claim")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if r.verificationExpired(rec) {
		return context.DeadlineExceeded
	}
	uid, err := target.Send(ctx, p.Assignment)
	if errors.Is(err, podstatus.ErrAlreadyAssigned) {
		return nil
	}
	if err != nil {
		return errors.New("guest assignment outcome is uncertain")
	}
	if uid != string(rec.UID) {
		return errors.New("guest assignment acknowledged another Pod")
	}
	return nil
}

// poolIngress opens the pod's application ports on a claimed generic boot,
// one idempotent rule at a time, and reports whether every wanted rule is
// applied. The rules are the pod record's frozen create request.
func (r *Reconciler) poolIngress(ctx context.Context, rec *record, p *poolRecord, in *instance) (bool, error) {
	api, ok := r.cloud.(cloudIngressAPI)
	if !ok {
		return false, errors.New("cloud adapter does not support assignment ingress")
	}
	if in.Network.IngressUpdating {
		return false, nil
	}
	wanted := rec.Request.Network.Ingress
	present := map[string]int{}
	for _, rule := range in.Network.Ingress {
		if _, exists := present[rule.Name]; exists {
			return false, errors.New("cloud returned duplicate ingress rules")
		}
		present[rule.Name] = rule.Port
	}
	for _, rule := range wanted {
		port, exists := present[rule.Name]
		if exists {
			if port != rule.Port {
				return false, errors.New("cloud ingress differs from the frozen Pod")
			}
			continue
		}
		key := identityKey(p.Key, "ingress-"+rule.Name)
		updated, err := api.AddIngress(ctx, p.InstanceID, key, rule)
		if err != nil {
			return false, err
		}
		if err := p.owns(updated); err != nil {
			return false, err
		}
		return false, nil
	}
	if len(present) != len(wanted) {
		return false, errors.New("cloud generic guest has unexpected ingress")
	}
	return !in.Network.IngressUpdating, nil
}
