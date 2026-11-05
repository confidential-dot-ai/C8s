package podprovider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

const slotLabel = "confidential.ai/pod-cvm-slot"

// poolRef binds a Pod intent to one particular allocation-slot generation.
// A recreated Secret with the same name is never the same allocation.
type poolRef struct {
	Name string    `json:"name"`
	UID  types.UID `json:"uid"`
}

// poolClaim marks a slot as claimed by one Pod for the rest of its life.
type poolClaim struct {
	PodUID     types.UID `json:"podUID"`
	RecordName string    `json:"recordName"`
}

// poolRecord owns the actual generic VM. Its claim is irreversible: even a
// request whose assignment response is lost must destroy this VM before the
// allocation can be reused. No ownerReference can erase cleanup authority.
type poolRecord struct {
	Version int `json:"version"`
	instanceIntent
	Claim                      *poolClaim `json:"claim,omitempty"`
	VerificationTimeoutSeconds int64      `json:"verificationTimeoutSeconds"`
	VerificationDeadline       *time.Time `json:"verificationDeadline,omitempty"`
	Assignment                 []byte     `json:"assignment,omitempty"`
	ServingKey                 []byte     `json:"servingKey,omitempty"`
}

type poolState struct {
	record *poolRecord
	secret *corev1.Secret
}

// slotName names the slot record after its random allocation identity.
func slotName(key string) string {
	return "podcvm-slot-" + strings.TrimPrefix(key, "podcvm-")
}

func (p *poolRecord) document() (*launchconfig.Document, error) {
	return storedDocument(p.Request.Trust)
}

func (r *Reconciler) loadPool(ctx context.Context, name string) (*poolRecord, *corev1.Secret, error) {
	secret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Namespace: r.cfg.Namespace, Name: name}, secret); err != nil {
		return nil, nil, err
	}
	if secret.Labels[slotLabel] != "true" {
		return nil, nil, errors.New("record is not an allocation slot")
	}
	var p poolRecord
	if err := decode(secret.Data["state.json"], &p); err != nil {
		return nil, nil, errors.New("allocation slot is invalid")
	}
	if p.CredentialHash != credentialHash(r.cfg.token) {
		return nil, nil, errors.New("cloud credential changed while allocation slots exist; drain with the original credential before rotating")
	}
	return &p, secret, nil
}

func (r *Reconciler) savePool(ctx context.Context, p *poolRecord, secret *corev1.Secret) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	secret.Data = map[string][]byte{"state.json": data}
	return r.client.Update(ctx, secret)
}

// allocations lists every slot and counts the direct launches that share the
// pod budget with them. It is a direct API read under the provider's mutex.
func (r *Reconciler) allocations(ctx context.Context) ([]poolState, int64, error) {
	list := &corev1.SecretList{}
	if err := r.client.List(ctx, list, client.InNamespace(r.cfg.Namespace), client.MatchingLabels{ownerLabel: r.cfg.ProviderID}); err != nil {
		return nil, 0, err
	}
	var pools []poolState
	var direct int64
	for _, secret := range list.Items {
		if secret.Labels[slotLabel] == "true" {
			p, current, err := r.loadPool(ctx, secret.Name)
			if apierrors.IsNotFound(err) {
				continue
			}
			if err != nil {
				return nil, 0, err
			}
			pools = append(pools, poolState{p, current})
		} else {
			rec, _, err := r.loadRecord(ctx, secret.Name)
			if apierrors.IsNotFound(err) {
				continue
			}
			if err != nil {
				return nil, 0, err
			}
			if rec.Version == 1 && !rec.Deleted {
				direct++
			}
		}
	}
	sort.Slice(pools, func(i, j int) bool { return pools[i].secret.Name < pools[j].secret.Name })
	return pools, direct, nil
}

// reservePool writes a new slot record under a fresh random allocation
// identity, within the pod budget. Deleted slots occupy the budget until the
// maintenance sweep discards them, after their instance is confirmed gone.
func (r *Reconciler) reservePool(ctx context.Context) (*poolRecord, *corev1.Secret, error) {
	pools, direct, err := r.allocations(ctx)
	if err != nil {
		return nil, nil, err
	}
	if direct+int64(len(pools)) >= r.cfg.MaxPods {
		return nil, nil, errors.New("waiting for Pod CVM allocation capacity")
	}
	generation := make([]byte, 20)
	if _, err := rand.Read(generation); err != nil {
		return nil, nil, err
	}
	key := "podcvm-" + hex.EncodeToString(generation)
	req, err := r.cfg.genericLaunch(key)
	if err != nil {
		return nil, nil, err
	}
	now := r.now()
	deadline := now.Add(time.Duration(r.cfg.VerificationTimeoutSeconds) * time.Second)
	p := &poolRecord{Version: 1, instanceIntent: r.cfg.intent(key, req, now), VerificationTimeoutSeconds: r.cfg.VerificationTimeoutSeconds, VerificationDeadline: &deadline}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, nil, err
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: slotName(key), Namespace: r.cfg.Namespace, Labels: map[string]string{ownerLabel: r.cfg.ProviderID, slotLabel: "true"}}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"state.json": data}}
	if err := r.client.Create(ctx, secret); err != nil {
		return nil, nil, err
	}
	return p, secret, nil
}

// claimPool binds the Pod to the slot in two persisted steps: the Pod record
// names the slot first, then the slot is marked claimed. Either half alone is
// repaired on the next reconciliation; neither is ever reversed.
func (r *Reconciler) claimPool(ctx context.Context, rec *record, podSecret *corev1.Secret, p *poolRecord, secret *corev1.Secret) error {
	if p.DeleteRequested || p.Deleted {
		return errors.New("allocation cannot be claimed")
	}
	ref := &poolRef{Name: secret.Name, UID: secret.UID}
	if rec.Pool != nil && !reflect.DeepEqual(rec.Pool, ref) {
		return errors.New("pod already selected another allocation")
	}
	want := &poolClaim{PodUID: rec.UID, RecordName: podSecret.Name}
	if p.Claim != nil && !reflect.DeepEqual(p.Claim, want) {
		return errors.New("allocation was claimed by another Pod")
	}
	if rec.Pool == nil {
		rec.Pool = ref
		if err := r.save(ctx, rec, podSecret); err != nil {
			return err
		}
	}
	if p.Claim == nil {
		p.Claim = want
		if err := r.savePool(ctx, p, secret); err != nil {
			return err
		}
	}
	return nil
}

// compatiblePool reports whether an unclaimed slot still matches the
// provider's current image, size, location, address mode, launch key, cluster,
// server and CDS configuration.
func (r *Reconciler) compatiblePool(p *poolRecord) bool {
	doc, err := p.document()
	if err != nil {
		return false
	}
	return p.Request.Image == r.cfg.Image && p.Request.Size == r.cfg.Size && p.Request.Location == r.cfg.Location && p.Request.Tee == r.cfg.tee() && p.VCPUs == r.cfg.VCPUs && p.MemoryMiB == r.cfg.MemoryMiB && p.Request.Network.PublicIP == r.cfg.PublicIP && p.Request.Trust.LaunchKey == r.cfg.pub && reflect.DeepEqual(p.Manifest, r.cfg.manifest) && doc.ClusterID == r.cfg.ClusterID && doc.Server.Address == r.cfg.ServerAddress && doc.Server.OperatorPublicKey == r.cfg.serverPub && doc.CDS == r.cfg.cds
}
