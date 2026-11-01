package podprovider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
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

type poolClaim struct {
	PodUID        types.UID `json:"podUID"`
	RecordName    string    `json:"recordName"`
	RecordUID     types.UID `json:"recordUID"`
	DesiredDigest string    `json:"desiredDigest"`
}

// poolRecord owns the actual generic VM. Its claim is irreversible: even a
// request whose assignment response is lost must destroy this VM before the
// allocation slot can be reused. No ownerReference can erase cleanup authority.
type poolRecord struct {
	Version int   `json:"version"`
	Slot    int64 `json:"slot"`
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

func slotName(provider string, slot int64) string {
	sum := sha256.Sum256([]byte(provider))
	return "podcvm-slot-" + hex.EncodeToString(sum[:12]) + "-" + strconv.FormatInt(slot, 10)
}

func desiredDigest(rec *record) string {
	// createRequest has only JSON-marshalable fields; encoding/json orders keys.
	data, _ := json.Marshal(rec.Request)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (p *poolRecord) document() (*launchconfig.Document, error) {
	if len(p.Key) != len("podcvm-")+40 {
		return nil, errors.New("allocation generation is invalid")
	}
	doc, err := signedDocument(p.Request.Trust)
	if err != nil {
		return nil, err
	}
	if doc.Role != launchconfig.Pod || doc.Pod != nil || doc.Workloads != "" || doc.Node.Name != p.Key || doc.PodOperatorPublicKey != p.Request.Trust.LaunchKey {
		return nil, errors.New("pool launch is not the frozen generic Pod boot")
	}
	if p.Request.Name != p.Key || p.Request.Count != 1 || len(p.Request.Labels) != 2 || p.Request.Labels["podcvm-provider"] != p.ProviderID || p.Request.Labels["podcvm-uid"] != p.Key[len("podcvm-"):] || !reflect.DeepEqual(p.Request.Network.Ingress, []ingress{{Name: "pod-status", Port: 8443}}) || len(p.Request.Readiness.TCPPorts) != 0 {
		return nil, errors.New("pool request differs from its generic launch identity")
	}
	return doc, nil
}

func (r *Reconciler) loadPool(ctx context.Context, name string) (*poolRecord, *corev1.Secret, error) {
	secret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Namespace: r.cfg.Namespace, Name: name}, secret); err != nil {
		return nil, nil, err
	}
	if secret.UID == "" || secret.Labels[ownerLabel] != r.cfg.ProviderID || secret.Labels[slotLabel] != "true" {
		return nil, nil, errors.New("refusing a foreign or unidentified allocation slot")
	}
	var p poolRecord
	if err := decode(secret.Data["state.json"], &p); err != nil {
		return nil, nil, errors.New("allocation slot is invalid")
	}
	if p.Version != 1 || p.Slot < 0 || p.Slot >= 10000 || name != slotName(r.cfg.ProviderID, p.Slot) || p.ProviderID != r.cfg.ProviderID || p.CloudURL != r.cfg.CloudURL || p.CredentialHash != credentialHash(r.cfg.token) || p.NodeName != r.cfg.NodeName || p.CreatedAt.IsZero() || len(p.Manifest) == 0 || len(p.Key) != len("podcvm-")+40 || !validVerificationTimeout(p.VerificationTimeoutSeconds) {
		return nil, nil, errors.New("allocation slot identity or origin differs from this provider")
	}
	if _, err := hex.DecodeString(p.Key[len("podcvm-"):]); err != nil || p.Key[:len("podcvm-")] != "podcvm-" {
		return nil, nil, errors.New("allocation generation is invalid")
	}
	if p.VerificationDeadline != nil && p.VerificationDeadline.IsZero() {
		return nil, nil, errors.New("allocation verification deadline is invalid")
	}
	if p.Claim == nil && (len(p.Assignment) != 0 || len(p.ServingKey) != 0) {
		return nil, nil, errors.New("unclaimed allocation contains an assignment")
	}
	if (len(p.Assignment) == 0) != (len(p.ServingKey) == 0) {
		return nil, nil, errors.New("allocation assignment binding is incomplete")
	}
	if p.Claim != nil && (p.Claim.PodUID == "" || p.Claim.RecordUID == "" || p.Claim.RecordName != identityKey(p.ProviderID, string(p.Claim.PodUID)) || len(p.Claim.DesiredDigest) != 64) {
		return nil, nil, errors.New("allocation claim is invalid")
	}
	if _, err := p.document(); err != nil {
		return nil, nil, err
	}
	if len(p.Assignment) != 0 {
		if err := validateStoredAssignment(&p); err != nil {
			return nil, nil, err
		}
	}
	return &p, secret, nil
}

func (r *Reconciler) savePool(ctx context.Context, p *poolRecord, secret *corev1.Secret) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(data) > 900<<10 {
		return errors.New("allocation record exceeds the Secret size budget")
	}
	secret.Data = map[string][]byte{"state.json": data}
	return r.client.Update(ctx, secret)
}

// allocations is a direct API read under the provider's leader/mutex. Reserving
// the first free fixed slot uses Create/CAS, so concurrent reservations contend
// on the same budget slot instead of each inventing a new VM name.
func (r *Reconciler) allocations(ctx context.Context) ([]poolState, int64, error) {
	list := &corev1.SecretList{}
	if err := r.client.List(ctx, list, client.InNamespace(r.cfg.Namespace), client.MatchingLabels{ownerLabel: r.cfg.ProviderID}); err != nil {
		return nil, 0, err
	}
	var pools []poolState
	var legacy int64
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
				legacy++
			}
		}
	}
	sort.Slice(pools, func(i, j int) bool { return pools[i].record.Slot < pools[j].record.Slot })
	return pools, legacy, nil
}

func (r *Reconciler) reservePool(ctx context.Context) (*poolRecord, *corev1.Secret, error) {
	pools, legacy, err := r.allocations(ctx)
	if err != nil {
		return nil, nil, err
	}
	// Deleted tombstones occupy a name until the maintenance sweep discards
	// them; retaining them is conservative and prevents an ABA claim race.
	if legacy+int64(len(pools)) >= r.cfg.MaxPods {
		return nil, nil, errors.New("waiting for Pod CVM allocation capacity")
	}
	occupied := map[int64]bool{}
	for _, p := range pools {
		occupied[p.record.Slot] = true
	}
	var slot int64
	for occupied[slot] {
		slot++
	}
	if slot >= r.cfg.MaxPods {
		return nil, nil, errors.New("waiting for a free allocation slot")
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
	p := &poolRecord{Version: 1, Slot: slot, instanceIntent: instanceIntent{ProviderID: r.cfg.ProviderID, CloudURL: r.cfg.CloudURL, CredentialHash: credentialHash(r.cfg.token), NodeName: r.cfg.NodeName, Key: key, Request: req, Manifest: r.cfg.manifest, VCPUs: r.cfg.VCPUs, MemoryMiB: r.cfg.MemoryMiB, CreatedAt: now}, VerificationTimeoutSeconds: r.cfg.VerificationTimeoutSeconds, VerificationDeadline: &deadline}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, nil, err
	}
	if len(data) > 900<<10 {
		return nil, nil, errors.New("allocation record exceeds the Secret size budget")
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: slotName(r.cfg.ProviderID, slot), Namespace: r.cfg.Namespace, Labels: map[string]string{ownerLabel: r.cfg.ProviderID, slotLabel: "true"}}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"state.json": data}}
	if err := r.client.Create(ctx, secret); err != nil {
		return nil, nil, err
	}
	if secret.UID == "" {
		return nil, nil, errors.New("allocation slot has no Kubernetes UID")
	}
	return p, secret, nil
}

func (r *Reconciler) linkedPool(ctx context.Context, rec *record, podSecret *corev1.Secret) (*poolRecord, *corev1.Secret, error) {
	if rec.Pool == nil || !rec.PoolCommitted {
		return nil, nil, errors.New("pod has no committed allocation")
	}
	current, currentSecret, err := r.loadRecord(ctx, podSecret.Name)
	if err != nil {
		return nil, nil, err
	}
	if currentSecret.UID != podSecret.UID || currentSecret.ResourceVersion != podSecret.ResourceVersion || !current.PoolCommitted || !reflect.DeepEqual(current.Pool, rec.Pool) || desiredDigest(current) != desiredDigest(rec) || current.TerminalStatus != nil || current.DeleteRequested || current.Deleted {
		return nil, nil, errors.New("pod allocation commitment changed")
	}
	p, secret, err := r.loadPool(ctx, rec.Pool.Name)
	if err != nil {
		return nil, nil, err
	}
	if secret.UID != rec.Pool.UID {
		return nil, nil, errors.New("pod allocation generation changed")
	}
	want := &poolClaim{PodUID: rec.UID, RecordName: podSecret.Name, RecordUID: podSecret.UID, DesiredDigest: desiredDigest(rec)}
	if !reflect.DeepEqual(p.Claim, want) {
		return nil, nil, errors.New("allocation does not reciprocate the immutable Pod claim")
	}
	return p, secret, nil
}

func (r *Reconciler) claimPool(ctx context.Context, rec *record, podSecret *corev1.Secret, p *poolRecord, secret *corev1.Secret) error {
	if rec.Version != 2 || podSecret.UID == "" || p.DeleteRequested || p.Deleted {
		return errors.New("pod or allocation cannot be claimed")
	}
	ref := &poolRef{Name: secret.Name, UID: secret.UID}
	if rec.Pool != nil && !reflect.DeepEqual(rec.Pool, ref) {
		return errors.New("pod already selected another allocation")
	}
	want := &poolClaim{PodUID: rec.UID, RecordName: podSecret.Name, RecordUID: podSecret.UID, DesiredDigest: desiredDigest(rec)}
	if p.Claim != nil && !reflect.DeepEqual(p.Claim, want) {
		return errors.New("allocation was claimed by another Pod")
	}
	if rec.PoolCommitted && p.Claim == nil {
		return errors.New("committed allocation lost its immutable claim")
	}
	// The Pod anchor precedes the VM claim. Neither half alone authorizes a
	// Cloud side effect or assignment. Lost writes are recovered by exact UID.
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
	if !rec.PoolCommitted {
		rec.PoolCommitted = true
		if err := r.save(ctx, rec, podSecret); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) compatiblePool(p *poolRecord) bool {
	doc, err := p.document()
	if err != nil {
		return false
	}
	return p.Request.Image == r.cfg.Image && p.Request.Size == r.cfg.Size && p.Request.Location == r.cfg.Location && p.VCPUs == r.cfg.VCPUs && p.MemoryMiB == r.cfg.MemoryMiB && p.Request.Network.PublicIP == r.cfg.PublicIP && p.Request.Trust.LaunchKey == r.cfg.pub && reflect.DeepEqual(p.Manifest, r.cfg.manifest) && doc.ClusterID == r.cfg.ClusterID && doc.Server.Address == r.cfg.ServerAddress && doc.Server.OperatorPublicKey == r.cfg.serverPub && doc.CDS == r.cfg.cds
}

// instanceRecord is a read-only adapter for existing endpoint and Cloud shape
// validation. It must never be saved as the Pod's signed desired document.
func (p *poolRecord) instanceRecord() *record {
	return &record{ProviderID: p.ProviderID, Key: p.Key, Request: p.Request, Manifest: p.Manifest, VCPUs: p.VCPUs, MemoryMiB: p.MemoryMiB, InstanceID: p.InstanceID}
}

func (r *Reconciler) checkPoolBinding(rec *record, p *poolRecord) error {
	desired, err := rec.document()
	if err != nil {
		return err
	}
	actual, err := p.document()
	if err != nil {
		return err
	}
	if desired.ClusterID != actual.ClusterID || !reflect.DeepEqual(desired.Image, actual.Image) || !reflect.DeepEqual(desired.Server, actual.Server) || desired.CDS != actual.CDS || desired.PodOperatorPublicKey != actual.PodOperatorPublicKey || rec.Request.Image != p.Request.Image || rec.Request.Size != p.Request.Size || rec.Request.Location != p.Request.Location || rec.Request.Network.PublicIP != p.Request.Network.PublicIP || rec.VCPUs != p.VCPUs || rec.MemoryMiB != p.MemoryMiB || !reflect.DeepEqual(rec.Manifest, p.Manifest) {
		return errors.New("allocation trust or capacity differs from the frozen Pod")
	}
	if len(rec.Name)+1+len(actual.Node.Name) > 253 {
		return errors.New("pod name exceeds the allocated guest's static name limit")
	}
	return nil
}
