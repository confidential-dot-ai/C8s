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

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

// record is the durable authority for one Pod UID's Cloud side effects. A
// direct launch owns its instance through the embedded intent; a pooled Pod
// (Version 2) references the slot that owns it instead. It deliberately has no
// Pod owner reference, so forced Pod deletion cannot garbage-collect cleanup
// intent.
type record struct {
	instanceIntent
	Pool                       *poolRef          `json:"pool,omitempty"`
	Version                    int               `json:"version"`
	UID                        types.UID         `json:"uid"`
	Namespace                  string            `json:"namespace"`
	Name                       string            `json:"name"`
	TerminalStatus             *corev1.PodStatus `json:"terminalStatus,omitempty"`
	VerificationTimeoutSeconds int64             `json:"verificationTimeoutSeconds,omitempty"`
	VerificationDeadline       *time.Time        `json:"verificationDeadline,omitempty"`
}

func (r *record) document() (*launchconfig.Document, error) {
	return storedDocument(r.Request.Trust)
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
	if rec.Key != key || identityKey(rec.ProviderID, string(rec.UID)) != key {
		return nil, nil, errors.New("provider record identity differs from its key")
	}
	if rec.CredentialHash != credentialHash(r.cfg.token) {
		return nil, nil, errors.New("cloud credential changed while provider records exist; drain with the original credential before rotating")
	}
	return &rec, secret, nil
}

func (r *Reconciler) ensureRecord(ctx context.Context, pod *corev1.Pod) (*record, *corev1.Secret, error) {
	key := identityKey(r.cfg.ProviderID, string(pod.UID))
	rec, secret, err := r.loadRecord(ctx, key)
	if err == nil {
		return rec, secret, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, nil, err
	}
	req, err := r.cfg.launch(pod)
	if err != nil {
		return nil, nil, fmt.Errorf("pod cannot be launched: %w", err)
	}
	rec = &record{Version: 1, UID: pod.UID, Namespace: pod.Namespace, Name: pod.Name, instanceIntent: r.cfg.intent(key, req, r.now())}
	pooled, err := r.poolMode(ctx)
	if err != nil {
		return nil, nil, err
	}
	if pooled {
		rec.Version = 2
	}
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

// intent freezes the provider identity, credential and capacity a create
// request was written under, for a direct launch or a generic slot alike.
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
