//go:build linux && pod_cloud_integration

package acceptance

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
)

type assignmentSession interface {
	ServingKey() []byte
	Prepare(context.Context, *ecdsa.PrivateKey, []byte, []byte, []byte) ([]byte, error)
	Send(context.Context, []byte) (string, error)
	Close()
}

// verifyAssignmentTarget opens the generic guest's key-pinned channel after
// fresh launch evidence with an empty measured list.
func verifyAssignmentTarget(ctx context.Context, generic *record, address string) (assignmentSession, error) {
	dir, err := os.MkdirTemp("", "c8s-pod-assign-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	key, manifest := filepath.Join(dir, "pubkey"), filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(key, []byte(generic.Request.Trust.LaunchKey), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(manifest, generic.Manifest, 0o600); err != nil {
		return nil, err
	}
	target, err := podstatus.VerifyAssignmentTarget(ctx, podstatus.AttestConfig{Node: address, LaunchKeyPubPath: key, ImageManifestPath: manifest, Timeout: 15 * time.Second})
	if err != nil {
		return nil, errors.New("generic guest attestation unavailable")
	}
	return target, nil
}

// The empty verified session is retained through the negative POST. Reopening
// VerifyAssignmentTarget after assignment would correctly refuse measured guests.
type cloudAssignmentObserver struct {
	run       *cloudRun
	posts     atomic.Int64
	postMu    sync.Mutex
	postProof cloudWarmPostProof
}

type cloudObservedAssignment struct {
	assignmentSession
	observer   *cloudAssignmentObserver
	allocation string
	conflict   []byte
}

func (o *cloudAssignmentObserver) target(session assignmentSession, allocation string) *cloudObservedAssignment {
	return &cloudObservedAssignment{assignmentSession: session, observer: o, allocation: allocation}
}

// Prepare also signs a conflicting assignment for another Pod UID, so the
// guest's refusal of a second signed assignment is proven with real bytes.
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

// Send requires the exact bytes and serving identity to be durable in the
// generic record, matching the submitted Pod, before the guest sees them.
func (s *cloudObservedAssignment) Send(ctx context.Context, body []byte) (string, error) {
	o := s.observer
	generic, err := o.run.snapshot(s.allocation)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(generic.Assignment, body) || !bytes.Equal(generic.ServingKey, s.ServingKey()) {
		return "", errors.New("assignment POST differs from durable bytes or serving identity")
	}
	rec, err := o.run.snapshot("a")
	if err != nil {
		return "", err
	}
	if rec.Allocation != s.allocation {
		return "", errors.New("assignment POST names another allocation")
	}
	if err = assignmentMatches(rec, generic); err != nil {
		return "", err
	}
	owned, _, err := o.run.ownedSnapshot("a")
	if err != nil {
		return "", err
	}
	if owned.Receipt == nil || owned.Receipt.ID != generic.InstanceID {
		return "", errors.New("assignment POST has no exact owned Cloud receipt")
	}
	if err = cloudWrite(filepath.Join(o.run.dir, "assignment-intent-"+generic.Key+".json"), generic); err != nil {
		return "", err
	}
	if err = o.beginPost(string(rec.UID), generic.Key, body, generic.ServingKey); err != nil {
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
		return "", errors.New("accepted POST has no independently prepared conflict probe")
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
	if err = cloudWrite(filepath.Join(o.run.dir, "assignment-accepted-"+generic.Key+".json"), map[string]any{
		"podUID": uid, "allocation": generic.Key, "instanceID": generic.InstanceID, "assignmentSHA256": cloudHash(body),
		"servingKeySHA256": cloudHash(generic.ServingKey), "conflictingAssignment": s.conflict,
		"conflictingAssignmentRejected": true, "assignmentBeforePOST": true,
	}); err != nil {
		return "", err
	}
	return uid, nil
}

// Retries may recover an uncertain response while the immutable guest
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
	return nil
}
