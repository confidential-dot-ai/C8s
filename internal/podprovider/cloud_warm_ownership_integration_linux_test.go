//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The observer and elected worker share this ledger. Every mutation is durable
// before its caller gains authority; callers never hold this lock over network I/O.
func (r *cloudRun) updateLedger(change func(*cloudLedger) error) error {
	r.ledgerMu.Lock()
	defer r.ledgerMu.Unlock()
	raw, err := json.Marshal(r.ledger)
	if err != nil {
		return err
	}
	var next cloudLedger
	if err = json.Unmarshal(raw, &next); err != nil {
		return err
	}
	if err = change(&next); err != nil {
		return err
	}
	if next.Version != r.ledger.Version || next.Run != r.ledger.Run || next.Config != r.ledger.Config || next.CredentialHash != r.ledger.CredentialHash || !reflect.DeepEqual(next.Before, r.ledger.Before) {
		return errors.New("ledger update changed immutable cleanup authority")
	}
	if err = r.saveLocked(next); err != nil {
		return err
	}
	// Keep immutable fields at their original addresses for concurrent readers.
	// A failed write never publishes tentative create/deletion authority in memory.
	r.ledger.Owned, r.ledger.Pods, r.ledger.Complete = next.Owned, next.Pods, next.Complete
	return nil
}

func (r *cloudRun) submittedPod(side string) (cloudPodIntent, bool) {
	r.ledgerMu.Lock()
	defer r.ledgerMu.Unlock()
	if p, ok := r.ledger.Pods[side]; ok {
		return p, true
	}
	if o := r.ledger.Owned[side]; o != nil && o.UID != "" {
		return cloudPodIntent{UID: o.UID, Key: o.Key}, true
	}
	return cloudPodIntent{}, false
}

func (r *cloudRun) ownedSnapshot(side string) (*cloudOwned, string, error) {
	r.ledgerMu.Lock()
	defer r.ledgerMu.Unlock()
	if p, ok := r.ledger.Pods[side]; ok {
		side = p.Allocation
	}
	o := r.ledger.Owned[side]
	if o == nil {
		return nil, "", errors.New("missing exact owned Cloud intent")
	}
	copy := *o
	copy.Labels = maps.Clone(o.Labels)
	if o.Receipt != nil {
		receipt := *o.Receipt
		receipt.Labels = maps.Clone(o.Receipt.Labels)
		copy.Receipt = &receipt
	}
	return &copy, side, nil
}

func (r *cloudRun) ownedHandles() []string {
	r.ledgerMu.Lock()
	defer r.ledgerMu.Unlock()
	out := make([]string, 0, len(r.ledger.Owned))
	for key := range r.ledger.Owned {
		if key != "cds" {
			out = append(out, key)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	if r.ledger.Owned["cds"] != nil {
		out = append(out, "cds")
	}
	return out
}

func (r *cloudRun) markTerminated(side string) error {
	_, handle, err := r.ownedSnapshot(side)
	if err != nil {
		return err
	}
	return r.updateLedger(func(ledger *cloudLedger) error { ledger.Owned[handle].Terminated = true; return nil })
}

func (r *cloudRun) cloudPool(ctx context.Context, reader *Reconciler, rec *record, podSecret *corev1.Secret) (*poolRecord, *corev1.Secret, error) {
	if rec.Version != 2 || rec.Pool == nil || !rec.PoolCommitted {
		return nil, nil, errors.New("Pod has no committed warm allocation")
	}
	p, slot, err := reader.loadPool(ctx, rec.Pool.Name)
	if err != nil {
		return nil, nil, err
	}
	want := &poolClaim{PodUID: rec.UID, RecordName: podSecret.Name, RecordUID: podSecret.UID, DesiredDigest: desiredDigest(rec)}
	if podSecret.UID == "" || slot.UID != rec.Pool.UID || !reflect.DeepEqual(p.Claim, want) {
		return nil, nil, errors.New("warm allocation lost its reciprocal UID fence")
	}
	if err := reader.checkPoolBinding(rec, p); err != nil {
		return nil, nil, err
	}
	return p, slot, nil
}

func (r *cloudRun) bindCloudPod(side string, observed cloudPodIntent, p *poolRecord, slot *corev1.Secret) error {
	return r.updateLedger(func(ledger *cloudLedger) error {
		current, ok := ledger.Pods[side]
		owned := ledger.Owned[p.Key]
		if !ok || current.UID != observed.UID || current.Key != observed.Key ||
			(current.Allocation != "" && current.Allocation != p.Key) ||
			owned == nil || owned.SlotName != slot.Name || owned.SlotUID != string(slot.UID) {
			return errors.New("warm Pod cannot adopt an unowned allocation")
		}
		current.Allocation = p.Key
		ledger.Pods[side] = current
		return nil
	})
}

func (r *cloudRun) recordCloudPool(p *poolRecord, slot *corev1.Secret, attempted bool) error {
	if _, err := p.document(); err != nil {
		return err
	}
	if slot.UID == "" || slot.Name != slotName(p.ProviderID, p.Slot) || p.ProviderID != r.ledger.Run || p.Request.Image != r.cfg.Image || p.CloudURL != r.cfg.CloudURL || p.CredentialHash != r.ledger.CredentialHash {
		return errors.New("allocation differs from live run authority")
	}
	raw, err := json.Marshal(p.Request)
	if err != nil {
		return err
	}
	want := &cloudOwned{Key: p.Key, Image: p.Request.Image, LaunchKey: p.Request.Trust.LaunchKey, Labels: maps.Clone(p.Request.Labels), IntentAt: p.CreatedAt.UTC(), Attempted: attempted, SlotName: slot.Name, SlotUID: string(slot.UID), RequestHash: cloudHash(raw)}
	return r.updateLedger(func(ledger *cloudLedger) error {
		if prior := ledger.Owned[p.Key]; prior != nil {
			if prior.Key != want.Key || prior.Image != want.Image || prior.LaunchKey != want.LaunchKey || !maps.Equal(prior.Labels, want.Labels) || !prior.IntentAt.Equal(want.IntentAt) || prior.SlotName != want.SlotName || prior.SlotUID != want.SlotUID || prior.RequestHash != want.RequestHash || prior.Terminated {
				return errors.New("warm Cloud creation changed its durable identity")
			}
			prior.Attempted = prior.Attempted || attempted
			return nil
		}
		count := 0
		for _, owned := range ledger.Owned {
			if owned.SlotUID != "" {
				count++
			}
		}
		if count >= 2 {
			return errors.New("warm acceptance allocation generation budget exhausted")
		}
		ledger.Owned[p.Key] = want
		return nil
	})
}

// cloudTrackedAPI observes the real adapter. It cannot mint an allocation or
// adopt an instance discovered without a previously persisted create attempt.
type cloudTrackedAPI struct {
	run    *cloudRun
	reader *Reconciler
}

func (c *cloudTrackedAPI) pool(ctx context.Context, key string) (*poolRecord, *corev1.Secret, error) {
	pools, _, err := c.reader.allocations(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, state := range pools {
		if state.record.Key == key {
			return state.record, state.secret, nil
		}
	}
	return nil, nil, errors.New("Cloud operation has no exact durable allocation")
}

func (c *cloudTrackedAPI) Find(ctx context.Context, key string) (*instance, error) {
	p, slot, err := c.pool(ctx, key)
	if err != nil {
		return nil, err
	}
	if err = c.run.recordCloudPool(p, slot, false); err != nil {
		return nil, err
	}
	owned, _, err := c.run.ownedSnapshot(key)
	if err != nil {
		return nil, err
	}
	in, err := c.run.api.Find(ctx, key)
	if err != nil || in == nil {
		return in, err
	}
	if !owned.Attempted {
		return nil, errors.New("refusing Cloud identity preceding this run's create attempt")
	}
	return c.run.getOwned(ctx, key)
}

func (c *cloudTrackedAPI) Create(ctx context.Context, key string, req createRequest) (*instance, error) {
	p, slot, err := c.pool(ctx, key)
	if err != nil {
		return nil, err
	}
	if !p.CreateAttempted || !reflect.DeepEqual(p.Request, req) {
		return nil, errors.New("Cloud POST differs from persisted allocation request")
	}
	if err = c.run.recordCloudPool(p, slot, true); err != nil {
		return nil, err
	}
	in, err := c.run.api.Create(ctx, key, req)
	if err != nil {
		return nil, err
	}
	checked, err := c.run.getOwned(ctx, key)
	if err != nil {
		return nil, err
	}
	if checked == nil || in == nil || checked.ID != in.ID {
		return nil, errors.New("Cloud create receipt differs from exact lookup")
	}
	return checked, nil
}

func (c *cloudTrackedAPI) byID(id string) (string, error) {
	for _, handle := range c.run.ownedHandles() {
		o, _, err := c.run.ownedSnapshot(handle)
		if err != nil {
			return "", err
		}
		if o.SlotUID != "" && o.Receipt != nil && o.Receipt.ID == id {
			return handle, nil
		}
	}
	return "", errors.New("Cloud instance has no persisted owned receipt")
}

func (c *cloudTrackedAPI) Get(ctx context.Context, id string) (*instance, error) {
	key, err := c.byID(id)
	if err != nil {
		return nil, err
	}
	in, err := c.run.getOwned(ctx, key)
	if err != nil || in == nil || in.Status != "terminated" {
		return in, err
	}
	p, slot, err := c.pool(ctx, key)
	if err != nil {
		return nil, err
	}
	if !p.DeleteRequested || p.Deleted || p.InstanceID != id {
		return nil, errors.New("termination observation lost allocation cleanup authority")
	}
	if p.Claim != nil {
		rec, secret, err := c.reader.loadRecord(ctx, p.Claim.RecordName)
		if err != nil {
			return nil, err
		}
		if _, _, err = c.run.cloudPool(ctx, c.reader, rec, secret); err != nil {
			return nil, err
		}
		if !rec.DeleteRequested || rec.Deleted {
			return nil, errors.New("Pod record released before observed termination")
		}
		pod := &corev1.Pod{}
		if err = c.reader.client.Get(ctx, client.ObjectKey{Namespace: rec.Namespace, Name: rec.Name}, pod); err != nil {
			return nil, err
		}
		if pod.UID != rec.UID || pod.DeletionTimestamp.IsZero() || !slices.Contains(pod.Finalizers, finalizer) {
			return nil, errors.New("Pod finalizer released before observed termination")
		}
	}
	if err = cloudWrite(filepath.Join(c.run.dir, "termination-"+key+".json"), map[string]any{"instanceID": id, "allocationUID": slot.UID, "terminationBeforeRelease": true}); err != nil {
		return nil, err
	}
	return in, nil
}

func (c *cloudTrackedAPI) Delete(ctx context.Context, id string) error {
	key, err := c.byID(id)
	if err != nil {
		return err
	}
	p, _, err := c.pool(ctx, key)
	if err != nil {
		return err
	}
	if !p.DeleteRequested || p.InstanceID != id {
		return errors.New("Cloud DELETE lacks its exact persisted intent")
	}
	if _, err = c.run.getOwned(ctx, key); err != nil {
		return err
	}
	return c.run.api.Delete(ctx, id)
}

func (c *cloudTrackedAPI) AddIngress(ctx context.Context, id, key string, rule ingress) (*instance, error) {
	handle, err := c.byID(id)
	if err != nil {
		return nil, err
	}
	p, _, err := c.pool(ctx, handle)
	if err != nil {
		return nil, err
	}
	if p.Claim == nil {
		return nil, errors.New("unclaimed generic VM cannot receive workload ingress")
	}
	rec, secret, err := c.reader.loadRecord(ctx, p.Claim.RecordName)
	if err != nil {
		return nil, err
	}
	if _, _, err = c.run.cloudPool(ctx, c.reader, rec, secret); err != nil {
		return nil, err
	}
	wanted, err := expectedPoolIngress(rec)
	if err != nil {
		return nil, err
	}
	for _, expected := range wanted {
		if expected == rule && key == identityKey(p.Key, "ingress-"+rule.Name) {
			return c.run.api.AddIngress(ctx, id, key, rule)
		}
	}
	return nil, errors.New("ingress addition differs from frozen signed Pod")
}

func (c *cloudTrackedAPI) Ping(ctx context.Context) error { return c.run.api.Ping(ctx) }
