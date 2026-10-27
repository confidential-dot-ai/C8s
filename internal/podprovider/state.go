package podprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// record is the durable authority for one Pod UID's Cloud side effects. Keep
// versioned launch fields stable across upgrades: retrying must preserve the
// original signature, request and account binding. It deliberately has no Pod
// owner reference, so forced Pod deletion cannot garbage-collect cleanup intent.
type record struct {
	Version         int               `json:"version"`
	ProviderID      string            `json:"providerID"`
	CloudURL        string            `json:"cloudURL"`
	CredentialHash  string            `json:"credentialHash"`
	UID             types.UID         `json:"uid"`
	Namespace       string            `json:"namespace"`
	Name            string            `json:"name"`
	NodeName        string            `json:"nodeName"`
	Key             string            `json:"key"`
	Request         createRequest     `json:"request"`
	Manifest        []byte            `json:"manifest"`
	VCPUs           int64             `json:"vCPUs"`
	MemoryMiB       int64             `json:"memoryMiB"`
	CreatedAt       time.Time         `json:"createdAt"`
	CreateAttempted bool              `json:"createAttempted,omitempty"`
	InstanceID      string            `json:"instanceID,omitempty"`
	DeleteRequested bool              `json:"deleteRequested,omitempty"`
	Deleted         bool              `json:"deleted,omitempty"`
	TerminalStatus  *corev1.PodStatus `json:"terminalStatus,omitempty"`
}

func (r *record) document() (*launchconfig.Document, error) {
	doc, err := launchconfig.Parse(r.Request.Trust.InitData.Document)
	if err != nil {
		return nil, errors.New("stored Pod launch document is invalid")
	}
	if doc.Role != launchconfig.Pod || doc.Pod == nil || doc.Pod.UID != string(r.UID) || doc.Pod.Name != r.Name || doc.Pod.Namespace != r.Namespace || doc.Node.Name != r.Key || doc.PodOperatorPublicKey != r.Request.Trust.LaunchKey {
		return nil, errors.New("stored Pod identity differs from its signed launch")
	}
	block, rest := pem.Decode([]byte(r.Request.Trust.LaunchKey))
	if block == nil || len(rest) != 0 {
		return nil, errors.New("invalid stored launch public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid stored launch public key")
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid stored launch key type")
	}
	if err := operatorauth.VerifyDetached([]*ecdsa.PublicKey{pub}, r.Request.Trust.InitData.Document, string(r.Request.Trust.InitData.Signature)); err != nil {
		return nil, errors.New("stored launch signature does not verify")
	}
	return doc, nil
}

func (r *Reconciler) loadRecord(ctx context.Context, key string) (*record, *corev1.Secret, error) {
	secret := &corev1.Secret{}
	err := r.client.Get(ctx, types.NamespacedName{Namespace: r.cfg.Namespace, Name: key}, secret)
	if err != nil {
		return nil, nil, err
	}
	if secret.Labels[ownerLabel] != r.cfg.ProviderID {
		return nil, nil, errors.New("refusing a foreign provider record")
	}
	var rec record
	if err := decode(secret.Data["state.json"], &rec); err != nil {
		return nil, nil, errors.New("provider record is invalid")
	}
	if rec.Version != 1 || rec.ProviderID != r.cfg.ProviderID || rec.CloudURL != r.cfg.CloudURL || rec.NodeName != r.cfg.NodeName || rec.Key != key || identityKey(rec.ProviderID, string(rec.UID)) != key || rec.CreatedAt.IsZero() || len(rec.Manifest) == 0 {
		return nil, nil, errors.New("provider record identity or origin differs from this provider")
	}
	if rec.CredentialHash != credentialHash(r.cfg.token) {
		return nil, nil, errors.New("cloud credential changed while provider records exist; drain with the original credential before rotating")
	}
	if _, err := rec.document(); err != nil {
		return nil, nil, err
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
	rec = &record{Version: 1, ProviderID: r.cfg.ProviderID, CloudURL: r.cfg.CloudURL, CredentialHash: credentialHash(r.cfg.token), UID: pod.UID, Namespace: pod.Namespace, Name: pod.Name, NodeName: r.cfg.NodeName, Key: key, Request: req, Manifest: r.cfg.manifest, VCPUs: r.cfg.VCPUs, MemoryMiB: r.cfg.MemoryMiB, CreatedAt: r.now()}
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, nil, err
	}
	if len(data) > 900<<10 {
		return nil, nil, errors.New("frozen provider record exceeds the Secret size budget")
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

func (r *Reconciler) save(ctx context.Context, rec *record, secret *corev1.Secret) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if len(b) > 900<<10 {
		return errors.New("provider record exceeds the Secret size budget")
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
