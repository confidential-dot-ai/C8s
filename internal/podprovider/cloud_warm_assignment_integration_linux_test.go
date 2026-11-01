//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
)

// The empty verified session is retained through the negative POST. Reopening
// VerifyAssignmentTarget after assignment would correctly refuse measured guests.
type cloudAssignmentObserver struct {
	run         *cloudRun
	reader      *Reconciler
	verify      assignmentVerifier
	reads       atomic.Int64
	posts       atomic.Int64
	diagnostics cloudWarmDiagnostics
	postMu      sync.Mutex
	postProof   cloudWarmPostProof
}

func (o *cloudAssignmentObserver) read(ctx context.Context, rec *record, address string) (podstatus.PodProjection, error) {
	start := time.Now().UTC()
	projection, err, detail := cloudReadGuest(ctx, rec, address, podstatus.Get)
	o.observeRead(rec, address, start, time.Now().UTC(), err == nil, detail)
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
	if err = o.beginPost(string(rec.UID), current.Key, body, current.ServingKey); err != nil {
		return "", err
	}
	uid, err := s.assignmentSession.Send(ctx, body)
	if proofErr := o.finishPost(uid, err); proofErr != nil {
		return "", proofErr
	}
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

// Primary retries may recover an uncertain response while the immutable guest
// assignment is being installed. A new identity or a POST after independently
// verified readiness is never a retry of that transition.
type cloudWarmPostProof struct {
	PodUID           string `json:"podUID"`
	Allocation       string `json:"allocation"`
	AssignmentSHA256 string `json:"assignmentSHA256"`
	ServingKeySHA256 string `json:"servingKeySHA256"`
	Attempts         int64  `json:"attempts"`
	Accepted         int64  `json:"accepted"`
	AlreadyAssigned  int64  `json:"alreadyAssigned"`
	Uncertain        int64  `json:"uncertain"`
	Frozen           bool   `json:"frozenAfterVerifiedReadiness"`
	Violated         bool   `json:"violated"`
}

func (o *cloudAssignmentObserver) beginPost(uid, allocation string, body, serving []byte) error {
	o.postMu.Lock()
	defer o.postMu.Unlock()
	p := &o.postProof
	if p.Frozen || (p.Attempts != 0 && (p.PodUID != uid || p.Allocation != allocation || p.AssignmentSHA256 != cloudHash(body) || p.ServingKeySHA256 != cloudHash(serving))) {
		p.Violated = true
		return errors.New("primary assignment changed identity or followed verified readiness")
	}
	p.PodUID, p.Allocation, p.AssignmentSHA256, p.ServingKeySHA256 = uid, allocation, cloudHash(body), cloudHash(serving)
	p.Attempts++
	o.posts.Add(1)
	return cloudWrite(filepath.Join(o.run.dir, "assignment-posts.json"), p)
}

func (o *cloudAssignmentObserver) finishPost(uid string, err error) error {
	o.postMu.Lock()
	defer o.postMu.Unlock()
	p := &o.postProof
	switch {
	case errors.Is(err, podstatus.ErrAlreadyAssigned):
		p.AlreadyAssigned++
	case err != nil:
		p.Uncertain++
	case uid != p.PodUID || p.Accepted != 0:
		p.Violated = true
		return errors.New("primary assignment was accepted more than once or for another UID")
	default:
		p.Accepted++
	}
	return cloudWrite(filepath.Join(o.run.dir, "assignment-posts.json"), p)
}

func (o *cloudAssignmentObserver) freezePosts() error {
	o.postMu.Lock()
	defer o.postMu.Unlock()
	p := &o.postProof
	if p.Violated || p.Accepted != 1 || p.Attempts != p.Accepted+p.AlreadyAssigned+p.Uncertain {
		return errors.New("assignment attempts lack one immutable acknowledged acceptance")
	}
	p.Frozen = true
	return cloudWrite(filepath.Join(o.run.dir, "assignment-posts.json"), p)
}

func (o *cloudAssignmentObserver) checkFrozenPosts(want int64) error {
	o.postMu.Lock()
	defer o.postMu.Unlock()
	if !o.postProof.Frozen || o.postProof.Violated || o.postProof.Attempts != want || o.posts.Load() != want {
		return errors.New("verified warm lifecycle attempted another assignment POST")
	}
	return o.diagnostics.failure()
}
