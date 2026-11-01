package podprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
)

type assignmentSession interface {
	ServingKey() []byte
	Prepare(context.Context, *ecdsa.PrivateKey, []byte, []byte, []byte) ([]byte, error)
	Send(context.Context, []byte) (string, error)
	Close()
}

type assignmentVerifier func(context.Context, *poolRecord, string) (assignmentSession, error)

func verifyAssignmentTarget(ctx context.Context, p *poolRecord, address string) (assignmentSession, error) {
	dir, err := os.MkdirTemp("", "c8s-pod-assign-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	key, manifest := filepath.Join(dir, "pubkey"), filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(key, []byte(p.Request.Trust.LaunchKey), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(manifest, p.Manifest, 0o600); err != nil {
		return nil, err
	}
	target, err := podstatus.VerifyAssignmentTarget(ctx, podstatus.AttestConfig{Node: address, LaunchKeyPubPath: key, ImageManifestPath: manifest, Timeout: 15 * time.Second})
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

func validateStoredAssignment(p *poolRecord) error {
	req, err := podassign.Decode(p.Assignment)
	if err != nil {
		return errors.New("stored assignment is malformed")
	}
	serving, err := x509.ParsePKIXPublicKey(p.ServingKey)
	if err != nil {
		return errors.New("stored assignment serving key is invalid")
	}
	block, rest := pem.Decode([]byte(p.Request.Trust.LaunchKey))
	if block == nil || len(rest) != 0 {
		return errors.New("stored assignment launch key is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errors.New("stored assignment launch key is invalid")
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || podassign.Verify(key, serving, req) != nil {
		return errors.New("stored assignment signature is invalid")
	}
	return nil
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

func assignmentMatches(rec *record, p *poolRecord) error {
	if err := validateStoredAssignment(p); err != nil {
		return err
	}
	req, err := podassign.Decode(p.Assignment)
	if err != nil {
		return err
	}
	manifest, entries, peers, err := assignmentPayload(rec)
	if err != nil {
		return err
	}
	if !bytes.Equal(req.Manifest, manifest) || !bytes.Equal(req.Entries, entries) || !bytes.Equal(req.MeshPeers, peers) {
		return errors.New("stored assignment differs from the frozen Pod")
	}
	return nil
}

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
		if err := assignmentMatches(rec, p); err != nil {
			return err
		}
		// Publication is the only permission to POST. On conflict or lost write,
		// reconcile reloads this exact intent rather than generating another one.
		if err := r.savePool(ctx, p, secret); err != nil {
			return err
		}
	} else {
		if err := assignmentMatches(rec, p); err != nil {
			return err
		}
		if !bytes.Equal(p.ServingKey, target.ServingKey()) {
			return errors.New("assignment serving key changed; retaining the immutable claim")
		}
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

func expectedPoolIngress(rec *record) ([]ingress, error) {
	doc, err := rec.document()
	if err != nil {
		return nil, err
	}
	ports, err := doc.Pod.IngressPorts()
	if err != nil {
		return nil, err
	}
	rules := []ingress{{Name: "pod-status", Port: 8443}}
	for _, port := range ports {
		rules = append(rules, ingress{Name: fmt.Sprintf("app-%d", port), Port: int(port)})
	}
	if !reflect.DeepEqual(rules, rec.Request.Network.Ingress) {
		return nil, errors.New("stored ingress differs from the signed Pod")
	}
	return rules, nil
}

func (r *Reconciler) poolIngress(ctx context.Context, rec *record, p *poolRecord, in *instance) (bool, error) {
	api, ok := r.cloud.(cloudIngressAPI)
	if !ok {
		return false, errors.New("cloud adapter does not support assignment ingress")
	}
	if in.Network.IngressUpdating {
		return false, nil
	}
	wanted, err := expectedPoolIngress(rec)
	if err != nil {
		return false, err
	}
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
		// Exact rules and deterministic per-generation keys are already frozen in
		// the reciprocal claim before this idempotent network operation.
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

func (r *Reconciler) pooled(ctx context.Context, pod *corev1.Pod, rec *record, podSecret *corev1.Secret) (ctrl.Result, error) {
	_, _, err := r.selectPool(ctx, rec, podSecret)
	if err != nil {
		return r.unverified(ctx, pod, rec, podSecret, "AllocationPending", err)
	}
	// Re-read both references before side effects, including after an ambiguous
	// CAS. The stored desired Pod never substitutes for the actual VM request.
	p, secret, err := r.linkedPool(ctx, rec, podSecret)
	if err != nil {
		return r.unverified(ctx, pod, rec, podSecret, "AllocationUnavailable", err)
	}
	if err := r.checkPoolBinding(rec, p); err != nil {
		return r.unverified(ctx, pod, rec, podSecret, "AllocationUnavailable", err)
	}
	if len(p.Assignment) != 0 {
		if err := assignmentMatches(rec, p); err != nil {
			return r.unverified(ctx, pod, rec, podSecret, "AllocationUnavailable", err)
		}
	}
	if p.DeleteRequested || p.Deleted {
		return r.stop(ctx, pod, rec, podSecret, "InstanceEnded")
	}
	callCtx, cancel := r.verificationContext(ctx, rec)
	defer cancel()
	in, err := ensureCloudInstance(callCtx, r.cloud, &p.instanceIntent, r.now(), func() error { return r.savePool(callCtx, p, secret) })
	if ctx.Err() != nil {
		return ctrl.Result{}, ctx.Err()
	}
	if r.verificationExpired(rec) {
		return r.stop(ctx, pod, rec, podSecret, verificationTimeoutReason)
	}
	if err != nil {
		return r.unverified(ctx, pod, rec, podSecret, "CloudUnavailable", err)
	}
	if in == nil {
		return r.stop(ctx, pod, rec, podSecret, "InstanceGone")
	}
	if err := validateInstance(p.instanceRecord(), in); err != nil {
		return r.stop(ctx, pod, rec, podSecret, "InstanceIdentityMismatch")
	}
	if in.Boot.Count > 1 {
		return r.stop(ctx, pod, rec, podSecret, "GuestRebooted")
	}
	switch in.Status {
	case "failed", "terminated", "terminating", "stopped":
		return r.stop(ctx, pod, rec, podSecret, "InstanceEnded")
	case "running":
	default:
		return r.unverified(ctx, pod, rec, podSecret, "InstanceStarting", nil)
	}
	ready, err := r.poolIngress(callCtx, rec, p, in)
	if ctx.Err() != nil {
		return ctrl.Result{}, ctx.Err()
	}
	if r.verificationExpired(rec) {
		return r.stop(ctx, pod, rec, podSecret, verificationTimeoutReason)
	}
	if err != nil || !ready {
		return r.unverified(ctx, pod, rec, podSecret, "EndpointsPending", err)
	}
	actual := p.instanceRecord()
	actual.Request.Network.Ingress = rec.Request.Network.Ingress
	address, apps, podIP, err := endpoints(actual, in)
	if err != nil {
		return r.unverified(ctx, pod, rec, podSecret, "EndpointsPending", err)
	}
	projection, readErr := r.guest(callCtx, rec, address)
	if ctx.Err() != nil {
		return ctrl.Result{}, ctx.Err()
	}
	if r.verificationExpired(rec) {
		return r.stop(ctx, pod, rec, podSecret, verificationTimeoutReason)
	}
	if readErr == nil {
		status, err := projectedStatusForNode(rec, projection, pod, podIP, p.Key)
		if err == nil {
			if len(p.Assignment) == 0 {
				return r.stop(ctx, pod, rec, podSecret, "UnexpectedAssignedGuest")
			}
			if status.Phase == corev1.PodSucceeded || status.Phase == corev1.PodFailed {
				rec.TerminalStatus = &status
				if err := r.save(ctx, rec, podSecret); err != nil {
					return ctrl.Result{}, err
				}
				return r.finish(ctx, pod, rec, podSecret)
			}
			if rec.VerificationDeadline != nil {
				rec.VerificationDeadline = nil
				if err := r.save(ctx, rec, podSecret); err != nil {
					return ctrl.Result{}, err
				}
			}
			if err := r.publishEndpoints(ctx, pod, apps); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: pollInterval}, r.publishStatus(ctx, pod, status)
		}
	}
	err = r.assignPool(callCtx, rec, p, secret, address)
	if ctx.Err() != nil {
		return ctrl.Result{}, ctx.Err()
	}
	if r.verificationExpired(rec) {
		return r.stop(ctx, pod, rec, podSecret, verificationTimeoutReason)
	}
	return r.unverified(ctx, pod, rec, podSecret, "AssignmentPending", err)
}
