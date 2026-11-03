//go:build linux && podprovider_integration

package podprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"slices"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
)

// The Cloud fake reads the real API before every effect. Generic creation needs
// a durable allocation; ingress and assignment additionally need both UID-bound
// claim records and the scheduled Pod's cleanup finalizer.
func (f *controlPlaneCloud) poolIntent(ctx context.Context, key string) (*Reconciler, *poolRecord, *corev1.Secret, error) {
	reader := &Reconciler{client: f.client, cfg: f.cfg}
	pools, _, err := reader.allocations(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, pool := range pools {
		if pool.record.Key == key {
			return reader, pool.record, pool.secret, nil
		}
	}
	return nil, nil, nil, errors.New("test fake Cloud: generic VM has no durable allocation")
}

func (f *controlPlaneCloud) requireDurablePoolIntent(ctx context.Context, key string, proposed []byte) error {
	_, p, secret, err := f.poolIntent(ctx, key)
	if err != nil {
		return err
	}
	frozen, err := json.Marshal(p.Request)
	if err != nil || !p.CreateAttempted || secret.UID == "" || !bytes.Equal(frozen, proposed) {
		return errors.New("test fake Cloud: generic creation preceded its exact durable intent")
	}
	return nil
}

func requireControlPlaneClaim(ctx context.Context, reader *Reconciler, p *poolRecord, slot *corev1.Secret) (*record, error) {
	if p.Claim == nil {
		return nil, errors.New("test fake: mutation has no permanent claim")
	}
	rec, podSecret, err := reader.loadRecord(ctx, p.Claim.RecordName)
	if err != nil {
		return nil, err
	}
	linked, current, err := reader.linkedPool(ctx, rec, podSecret)
	if err != nil || current.UID != slot.UID || linked.Key != p.Key {
		return nil, errors.New("test fake: mutation lacks reciprocal committed claim")
	}
	pod := &corev1.Pod{}
	if err := reader.client.Get(ctx, client.ObjectKey{Namespace: rec.Namespace, Name: rec.Name}, pod); err != nil {
		return nil, err
	}
	if pod.UID != rec.UID || !slices.Contains(pod.Finalizers, finalizer) {
		return nil, errors.New("test fake: mutation lacks Pod UID and cleanup finalizer")
	}
	return rec, nil
}

func (f *controlPlaneCloud) AddIngress(ctx context.Context, id, key string, rule ingress) (*instance, error) {
	f.mu.Lock()
	generation := ""
	for k, instanceID := range f.keys {
		if instanceID == id {
			generation = k
			break
		}
	}
	f.mu.Unlock()
	if generation == "" {
		return nil, errCloudNotFound
	}
	reader, p, slot, err := f.poolIntent(ctx, generation)
	if err != nil {
		return nil, err
	}
	rec, err := requireControlPlaneClaim(ctx, reader, p, slot)
	if err != nil {
		return nil, err
	}
	rules, err := expectedPoolIngress(rec)
	if err != nil || !slices.Contains(rules, rule) || key != identityKey(generation, "ingress-"+rule.Name) || p.InstanceID != id {
		return nil, errors.New("test fake Cloud: ingress differs from frozen assignment")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	in := f.instances[id]
	if in == nil {
		return nil, errCloudNotFound
	}
	for _, existing := range in.Network.Ingress {
		if existing.Name == rule.Name {
			if existing != rule {
				return nil, errors.New("test fake Cloud: ingress key changed meaning")
			}
			return cloneControlPlaneInstance(in), nil
		}
	}
	in.Network.Ingress = append(in.Network.Ingress, rule)
	port := 30000 + len(in.Network.Ingress)
	if rec.Request.Network.PublicIP == "dedicated" {
		port = rule.Port
	}
	in.Endpoints = append(in.Endpoints, endpoint{Name: rule.Name, Host: "203.0.113.5", Port: port})
	return cloneControlPlaneInstance(in), nil
}

type controlPlaneAssignedGuest struct {
	key  *ecdsa.PrivateKey
	spki []byte
	body []byte
	uid  string
}

type controlPlaneAssignment struct {
	mu              sync.Mutex
	reader          *Reconciler
	guests          map[string]*controlPlaneAssignedGuest
	prepares, sends int
	holdReads       bool
}

func newControlPlaneAssignment(reader *Reconciler) *controlPlaneAssignment {
	return &controlPlaneAssignment{reader: reader, guests: map[string]*controlPlaneAssignedGuest{}, holdReads: true}
}

func (g *controlPlaneAssignment) verify(_ context.Context, p *poolRecord, _ string) (assignmentSession, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	guest := g.guests[p.Key]
	if guest == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return nil, err
		}
		guest = &controlPlaneAssignedGuest{key: key, spki: spki}
		g.guests[p.Key] = guest
	}
	if guest.uid != "" {
		return nil, errors.New("test fake guest: measured assignment is no longer empty")
	}
	return &controlPlaneAssignmentSession{owner: g, poolName: slotName(p.ProviderID, p.Slot), generation: p.Key, key: guest.key, spki: bytes.Clone(guest.spki)}, nil
}

func (g *controlPlaneAssignment) allowReads() { g.mu.Lock(); defer g.mu.Unlock(); g.holdReads = false }
func (g *controlPlaneAssignment) snapshot() (int, int, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	accepted := 0
	for _, guest := range g.guests {
		if guest.uid != "" {
			accepted++
		}
	}
	return g.prepares, g.sends, accepted
}

func (g *controlPlaneAssignment) read(ctx context.Context, rec *record, _ string) (podstatus.PodProjection, error) {
	if rec.Pool == nil {
		return podstatus.PodProjection{}, errors.New("test fake guest: no pool reference")
	}
	p, _, err := g.reader.loadPool(ctx, rec.Pool.Name)
	if err != nil {
		return podstatus.PodProjection{}, err
	}
	g.mu.Lock()
	guest := g.guests[p.Key]
	ready := !g.holdReads && guest != nil && guest.uid == string(rec.UID) && bytes.Equal(guest.body, p.Assignment)
	g.mu.Unlock()
	if !ready {
		return podstatus.PodProjection{}, errors.New("test fake guest: projection unavailable")
	}
	projection := fixtureProjection(rec)
	projection.Metadata.Name = rec.Name + "-" + p.Key
	return projection, nil
}

type controlPlaneAssignmentSession struct {
	owner                *controlPlaneAssignment
	poolName, generation string
	key                  *ecdsa.PrivateKey
	spki                 []byte
}

func (s *controlPlaneAssignmentSession) ServingKey() []byte { return bytes.Clone(s.spki) }
func (*controlPlaneAssignmentSession) Close()               {}

func (s *controlPlaneAssignmentSession) Prepare(_ context.Context, key *ecdsa.PrivateKey, manifest, entries, peers []byte) ([]byte, error) {
	s.owner.mu.Lock()
	s.owner.prepares++
	s.owner.mu.Unlock()
	nonce := make([]byte, podassign.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	req, err := podassign.Sign(key, &s.key.PublicKey, podassign.Request{Nonce: nonce, Manifest: manifest, Entries: entries, MeshPeers: peers})
	if err != nil {
		return nil, err
	}
	return podassign.Encode(req)
}

func (s *controlPlaneAssignmentSession) Send(ctx context.Context, body []byte) (string, error) {
	g := s.owner
	p, slot, err := g.reader.loadPool(ctx, s.poolName)
	if err != nil {
		return "", err
	}
	if p.Key != s.generation || !bytes.Equal(p.Assignment, body) || !bytes.Equal(p.ServingKey, s.spki) {
		return "", errors.New("test fake guest: POST preceded exact durable assignment")
	}
	rec, err := requireControlPlaneClaim(ctx, g.reader, p, slot)
	if err != nil {
		return "", err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sends++
	guest := g.guests[p.Key]
	if guest.uid != "" {
		return "", podstatus.ErrAlreadyAssigned
	}
	guest.body = bytes.Clone(body)
	guest.uid = string(rec.UID)
	// The guest accepted the immutable assignment, but its POST response is lost.
	return "", errors.New("test fake guest: committed assignment response lost")
}
