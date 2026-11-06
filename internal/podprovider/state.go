package podprovider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// recordVersion names the record shape this provider writes. A record of
// another version is unreadable: its instance lives under a shape this code
// cannot resolve, so the pod stays held until an operator drains it with the
// provider that wrote it.
const recordVersion = 3

// record is the durable authority for one Pod UID's Cloud side effects: the
// generic instance the embedded intent created for the pod, the pod frozen at
// record time, and the assignment once it is signed. It deliberately has no
// Pod owner reference, so forced Pod deletion cannot garbage-collect cleanup
// intent.
type record struct {
	instanceIntent
	Version   int       `json:"version"`
	UID       types.UID `json:"uid"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	// Pod is the frozen pod manifest the assignment carries; Entries and
	// MeshPeers are the allowlist entries and peer endpoints frozen with it.
	Pod       []byte   `json:"pod"`
	Entries   string   `json:"entries"`
	MeshPeers []string `json:"meshPeers"`
	// Assignment and ServingKey are written together before the assignment
	// is first sent, and never changed afterwards.
	Assignment                 []byte            `json:"assignment,omitempty"`
	ServingKey                 []byte            `json:"servingKey,omitempty"`
	TerminalStatus             *corev1.PodStatus `json:"terminalStatus,omitempty"`
	VerificationTimeoutSeconds int64             `json:"verificationTimeoutSeconds,omitempty"`
	VerificationDeadline       *time.Time        `json:"verificationDeadline,omitempty"`
}

func (r *Reconciler) loadRecord(ctx context.Context, key string) (*record, *corev1.Secret, error) {
	secret := &corev1.Secret{}
	err := r.client.Get(ctx, types.NamespacedName{Namespace: r.cfg.Namespace, Name: key}, secret)
	if err != nil {
		return nil, nil, err
	}
	var rec record
	if err := decode(secret.Data["state.json"], &rec); err != nil {
		return nil, nil, errors.New("provider record is invalid")
	}
	if rec.Version != recordVersion {
		return nil, nil, fmt.Errorf("provider record version %d is not readable by this provider; drain it with the provider that wrote it", rec.Version)
	}
	if rec.Key != key || identityKey(rec.ProviderID, string(rec.UID)) != key {
		return nil, nil, errors.New("provider record identity differs from its key")
	}
	if rec.CredentialHash != credentialHash(r.cfg.token) {
		return nil, nil, errors.New("cloud credential changed while provider records exist; drain with the original credential before rotating")
	}
	return &rec, secret, nil
}

// ensureRecord returns the pod's record, writing it first when none exists.
// The record is written before any cloud call and only within the pod budget:
// every record whose instance is not confirmed destroyed counts.
func (r *Reconciler) ensureRecord(ctx context.Context, pod *corev1.Pod) (*record, *corev1.Secret, error) {
	key := identityKey(r.cfg.ProviderID, string(pod.UID))
	rec, secret, err := r.loadRecord(ctx, key)
	if err == nil {
		return rec, secret, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, nil, err
	}
	req, frozen, err := r.cfg.launch(pod)
	if err != nil {
		return nil, nil, fmt.Errorf("pod cannot be launched: %w", err)
	}
	held, err := r.heldRecords(ctx)
	if err != nil {
		return nil, nil, err
	}
	if held >= r.cfg.MaxPods {
		return nil, nil, errors.New("waiting for Pod CVM capacity")
	}
	peers := r.cfg.MeshPeers
	if peers == nil {
		peers = []string{}
	}
	rec = &record{Version: recordVersion, UID: pod.UID, Namespace: pod.Namespace, Name: pod.Name, Pod: frozen, Entries: r.cfg.workloads, MeshPeers: peers, instanceIntent: r.cfg.intent(key, req, r.now())}
	rec.VerificationTimeoutSeconds = r.cfg.VerificationTimeoutSeconds
	deadline := rec.CreatedAt.Add(time.Duration(rec.VerificationTimeoutSeconds) * time.Second)
	rec.VerificationDeadline = &deadline
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, nil, err
	}
	secret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: key, Namespace: r.cfg.Namespace, Labels: map[string]string{ownerLabel: r.cfg.ProviderID}}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"state.json": data}}
	if err := r.client.Create(ctx, secret); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return r.loadRecord(ctx, key)
		}
		return nil, nil, err
	}
	return rec, secret, nil
}

// heldRecords counts the records whose instance is not confirmed destroyed,
// unresolved creates included. An unreadable record is counted, never skipped.
func (r *Reconciler) heldRecords(ctx context.Context) (int64, error) {
	list := &corev1.SecretList{}
	if err := r.client.List(ctx, list, client.InNamespace(r.cfg.Namespace), client.MatchingLabels{ownerLabel: r.cfg.ProviderID}); err != nil {
		return 0, err
	}
	var held int64
	for _, secret := range list.Items {
		rec, _, err := r.loadRecord(ctx, secret.Name)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil || !rec.Deleted {
			held++
		}
	}
	return held, nil
}

// intent freezes the provider identity, credential and capacity a create
// request was written under.
func (c *Config) intent(key string, req createRequest, now time.Time) instanceIntent {
	return instanceIntent{ProviderID: c.ProviderID, CloudURL: c.CloudURL, CredentialHash: credentialHash(c.token), NodeName: c.NodeName, Key: key, Request: req, Manifest: c.manifest, VCPUs: c.VCPUs, MemoryMiB: c.MemoryMiB, CreatedAt: now}
}

func (r *Reconciler) save(ctx context.Context, rec *record, secret *corev1.Secret) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	secret.Data = map[string][]byte{"state.json": b}
	return r.client.Update(ctx, secret)
}

func (r *Reconciler) discard(ctx context.Context, secret *corev1.Secret) error {
	return client.IgnoreNotFound(r.client.Delete(ctx, secret, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &secret.UID, ResourceVersion: &secret.ResourceVersion}}))
}

func credentialHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
