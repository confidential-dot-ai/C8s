//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync/atomic"

	"k8s.io/apimachinery/pkg/types"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
)

// The empty verified session is retained through the negative POST. Reopening
// VerifyAssignmentTarget after assignment would correctly refuse measured guests.
type cloudAssignmentObserver struct {
	run    *cloudRun
	reader *Reconciler
	verify assignmentVerifier
	reads  atomic.Int64
	posts  atomic.Int64
}

func (o *cloudAssignmentObserver) read(ctx context.Context, rec *record, address string) (podstatus.PodProjection, error) {
	projection, err := readGuest(ctx, rec, address)
	if err == nil {
		o.reads.Add(1)
	}
	return projection, err
}

func (o *cloudAssignmentObserver) counts() (int64, int64) { return o.reads.Load(), o.posts.Load() }

type cloudObservedAssignment struct {
	assignmentSession
	observer   *cloudAssignmentObserver
	allocation string
	conflict   []byte
}

func (o *cloudAssignmentObserver) target(ctx context.Context, p *poolRecord, address string) (assignmentSession, error) {
	verify := o.verify
	if verify == nil {
		verify = verifyAssignmentTarget
	}
	target, err := verify(ctx, p, address)
	if err != nil {
		return nil, err
	}
	return &cloudObservedAssignment{assignmentSession: target, observer: o, allocation: p.Key}, nil
}

func (s *cloudObservedAssignment) Prepare(ctx context.Context, key *ecdsa.PrivateKey, manifest, entries, peers []byte) ([]byte, error) {
	body, err := s.assignmentSession.Prepare(ctx, key, manifest, entries, peers)
	if err != nil {
		return nil, err
	}
	pod, err := launchconfig.ParsePodManifest(manifest)
	if err != nil {
		return nil, err
	}
	pod.UID = types.UID(string(pod.UID) + "-conflict")
	changed, err := json.Marshal(pod)
	if err != nil {
		return nil, err
	}
	s.conflict, err = s.assignmentSession.Prepare(ctx, key, changed, entries, peers)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (s *cloudObservedAssignment) Send(ctx context.Context, body []byte) (string, error) {
	o := s.observer
	tracked := &cloudTrackedAPI{run: o.run, reader: o.reader}
	p, slot, err := tracked.pool(ctx, s.allocation)
	if err != nil {
		return "", err
	}
	if p.Claim == nil {
		return "", errors.New("assignment POST has no durable claim")
	}
	rec, secret, err := o.reader.loadRecord(ctx, p.Claim.RecordName)
	if err != nil {
		return "", err
	}
	current, currentSlot, err := o.reader.linkedPool(ctx, rec, secret)
	if err != nil {
		return "", err
	}
	if currentSlot.UID != slot.UID || current.Key != s.allocation || !bytes.Equal(current.Assignment, body) || !bytes.Equal(current.ServingKey, s.ServingKey()) {
		return "", errors.New("assignment POST differs from durable bytes or serving identity")
	}
	if err = assignmentMatches(rec, current); err != nil {
		return "", err
	}
	submitted, ok := o.run.submittedPod("a")
	if !ok || submitted.UID != string(rec.UID) || submitted.Key != secret.Name {
		return "", errors.New("assignment POST names an unsubmitted Pod")
	}
	if err = o.run.bindCloudPod("a", submitted, current, currentSlot); err != nil {
		return "", err
	}
	owned, _, err := o.run.ownedSnapshot(current.Key)
	if err != nil {
		return "", err
	}
	if owned.Receipt == nil || owned.Receipt.ID != current.InstanceID {
		return "", errors.New("assignment POST has no exact owned Cloud receipt")
	}
	if err = cloudWrite(filepath.Join(o.run.dir, "assignment-intent-"+current.Key+".json"), currentSlot); err != nil {
		return "", err
	}
	o.posts.Add(1)
	// Repeated primary POSTs remain observable even when the guest returns 409;
	// the live scenario requires exactly one, including across leader restart.
	uid, err := s.assignmentSession.Send(ctx, body)
	if err != nil {
		return uid, err
	}
	if uid != string(rec.UID) {
		return "", errors.New("assignment acknowledged another Pod")
	}
	if len(s.conflict) == 0 {
		return "", errors.New("recovered POST has no independently prepared conflict probe")
	}
	conflict, err := podassign.Decode(s.conflict)
	if err != nil {
		return "", err
	}
	conflictingPod, err := launchconfig.ParsePodManifest(conflict.Manifest)
	if err != nil || conflictingPod.UID == rec.UID {
		return "", errors.New("negative assignment did not name another Pod")
	}
	_, rejected := s.assignmentSession.Send(ctx, s.conflict)
	if !errors.Is(rejected, podstatus.ErrAlreadyAssigned) {
		return "", errors.New("assigned guest did not refuse the conflicting signed assignment")
	}
	if err = cloudWrite(filepath.Join(o.run.dir, "assignment-accepted-"+current.Key+".json"), map[string]any{
		"podUID": uid, "allocationUID": currentSlot.UID, "assignmentSHA256": cloudHash(body),
		"servingKeySHA256": cloudHash(current.ServingKey), "conflictingAssignment": s.conflict,
		"conflictingAssignmentRejected": true, "uidFencedClaim": true, "assignmentBeforePOST": true,
	}); err != nil {
		return "", err
	}
	return uid, nil
}
