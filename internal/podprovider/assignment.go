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

type assignmentVerifier func(context.Context, *record, string) (assignmentSession, error)

func verifyAssignmentTarget(ctx context.Context, rec *record, address string) (assignmentSession, error) {
	cfg, cleanup, err := attestConfig(address, rec.Request.Trust.LaunchKey, rec.Manifest)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	target, err := podstatus.VerifyAssignmentTarget(ctx, cfg)
	if err != nil {
		return nil, guestFailure(ctx, "generic guest attestation unavailable", err)
	}
	return target, nil
}

func (r *Reconciler) assignmentTarget(ctx context.Context, rec *record, address string) (assignmentSession, error) {
	verify := r.assignment
	if verify == nil {
		verify = verifyAssignmentTarget
	}
	return verify(ctx, rec, address)
}

// assignmentPayload is the frozen pod, entries and peer list of the record.
func assignmentPayload(rec *record) ([]byte, []byte, []byte, error) {
	peers := rec.MeshPeers
	if peers == nil {
		peers = []string{}
	}
	data, err := json.Marshal(peers)
	return rec.Pod, []byte(rec.Entries), data, err
}

// assign verifies the pod's instance as an unassigned guest, signs the
// assignment over that connection's serving key and persists the bytes before
// sending them. A persisted assignment is sent again unchanged, and only to
// the same serving key.
func (r *Reconciler) assign(ctx context.Context, rec *record, secret *corev1.Secret, address string) error {
	if len(rec.Assignment) == 0 && rec.Request.Trust.LaunchKey != r.cfg.pub {
		return errors.New("provider launch key changed before assignment")
	}
	target, err := r.assignmentTarget(ctx, rec, address)
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
	if len(rec.Assignment) == 0 {
		manifest, entries, peers, err := assignmentPayload(rec)
		if err != nil {
			return err
		}
		data, err := target.Prepare(ctx, r.cfg.key, manifest, entries, peers)
		if err != nil {
			return guestFailure(ctx, "guest assignment preparation unavailable", err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if r.verificationExpired(rec) {
			return context.DeadlineExceeded
		}
		rec.Assignment, rec.ServingKey = data, target.ServingKey()
		// Publication is the only permission to POST. On conflict or lost write,
		// reconcile reloads this exact intent rather than generating another one.
		if err := r.save(ctx, rec, secret); err != nil {
			return err
		}
	} else if !bytes.Equal(rec.ServingKey, target.ServingKey()) {
		return errors.New("assignment serving key changed; retaining the persisted assignment")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if r.verificationExpired(rec) {
		return context.DeadlineExceeded
	}
	uid, err := target.Send(ctx, rec.Assignment)
	var held *podstatus.AlreadyAssignedError
	if errors.As(err, &held) {
		if held.HeldUID != string(rec.UID) {
			return errors.New("guest holds another Pod")
		}
		return nil
	}
	if errors.Is(err, podstatus.ErrAlreadyAssigned) {
		return nil
	}
	if err != nil {
		return guestFailure(ctx, "guest assignment outcome is uncertain", err)
	}
	if uid != string(rec.UID) {
		return errors.New("guest assignment acknowledged another Pod")
	}
	return nil
}
