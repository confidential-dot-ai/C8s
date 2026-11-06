//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsobject"
	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/testutil/etcdtest"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	protected "github.com/confidential-dot-ai/c8s/test/pilot/cds-three-host/recovery"
)

type haMetadataFixture struct {
	m        *metadataFixture
	etcd     *etcdtest.Cluster
	adapters [3]*process
	args     [3][]string
}

// Real mTLS etcd members and three adapter processes. The loopback TLS router
// forwards each request exactly once and owns no authoritative state.
func attachHAMetadata(t *testing.T, f *objectFixture) *haMetadataFixture {
	t.Helper()
	e := etcdtest.New(t)
	attachMetadataWithBackend(t, f, []string{
		"--etcd-endpoints", strings.Join(e.URLs, ","), "--etcd-cluster-id", e.ClusterID,
		"--etcd-root-ca", filepath.Join(e.Dir, "ca.pem"),
		"--etcd-client-cert", filepath.Join(e.Dir, "cert.pem"), "--etcd-client-key", filepath.Join(e.Dir, "key.pem"),
	})
	m := f.metadata
	h := &haMetadataFixture{m: m, etcd: e}
	h.adapters[0], h.args[0] = m.process, m.args
	m.upstreams = []string{m.upstream}
	for i := 1; i < 3; i++ {
		address := fmt.Sprintf("127.0.0.1:%d", freePort(t))
		h.args[i] = append([]string(nil), m.args...)
		h.args[i][1] = address // fixed --listen argument, not a caller-selected URL
		m.upstreams = append(m.upstreams, "https://"+address)
		h.startAdapter(i)
	}
	h.ready()
	return h
}

func (h *haMetadataFixture) startAdapter(i int) {
	h.adapters[i] = h.m.owner.run(fmt.Sprintf("ha-metadata-%d", i), built.metadata, h.args[i], nil)
	h.m.owner.waitFor("HA metadata adapter", 10*time.Second, func() bool {
		r, err := h.m.request(h.m.upstreams[i], "/v1/stats")
		if err != nil {
			return false
		}
		defer r.Body.Close()
		return r.StatusCode == http.StatusOK
	})
	h.m.disabled.And(^(uint32(1) << i))
}

func (h *haMetadataFixture) stopAdapter(i int) {
	h.m.disabled.Or(uint32(1) << i)
	h.adapters[i].kill()
}

func (h *haMetadataFixture) ready() {
	t := h.m.owner.t
	for i := range 3 {
		if h.m.disabled.Load()&(1<<i) != 0 {
			continue
		}
		client, err := metadatapilot.NewClient(h.m.upstreams[i], h.m.namespace, h.m.token, h.m.client.Transport)
		if err != nil {
			t.Fatal(err)
		}
		h.m.owner.waitFor("linearizable metadata read through each live adapter", 20*time.Second, func() bool {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			_, err := client.Read(ctx, []string{strings.Repeat("a", 64)})
			return err == nil
		})
		client.Close()
	}
}

// This combines the real HA metadata provider and protected-grant CDS path.
// Attestation and the wrapping root remain software fixtures: passing this
// test is never reported as hardware custody or three-host qualification.
func TestHACurrentRecoveryAfterTotalCDSLoss(t *testing.T) {
	objects := newObjectFixture(t)
	ha := attachHAMetadata(t, objects)
	objects.config.DirectState, objects.config.AtomicOperatorWrites = true, true
	protectCurrentRecovery(t, objects)
	listener, host := inventoryListener(t)
	nodes := `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"node","measurement":"` + seededNodeImage.mrtd + `"}]}`
	c := newClusterWithNodes(t, threeReplicas, objects, nodes, []string{host + "/32"})
	w := startPilotWorkload(c, listener, host)
	ca := c.servedCA(c.replicas[0])
	c.replaceAllowlist(c.replicas[0], "ha-custody-warmup")
	w.setPolicy(true)
	value := []byte("synthetic three-host qualification secret")
	body := jsonBody(t, secrets.PutRequest{Value: base64.StdEncoding.EncodeToString(value)})
	if code, _ := c.put(c.replicas[0], "/secrets/pilot/operator", body); code != http.StatusCreated {
		t.Fatalf("create secret: HTTP %d", code)
	}
	w.issue(c.replicas[0], c.replicas[1])
	w.assertEveryReplicaReads("/pilot/operator", value)
	w.issuanceBurst(value)
	// Both independent failure domains are exercised before the cold recovery.
	leader := -1
	for i := range 3 {
		s, err := ha.etcd.Status(i)
		if err == nil && s.Leader == s.Header.MemberID {
			leader = i
		}
	}
	if leader < 0 {
		t.Fatal("observed metadata leader required")
	}
	ha.etcd.Stop(leader)
	ha.stopAdapter(0)
	ha.ready()
	w.setPolicy(false) // acknowledge revocation while one member and adapter are down
	for _, r := range c.replicas {
		if code, _ := pilotDo(t, w.client, w.secretRequest(r, "GET", "/pilot/operator")); code != http.StatusForbidden {
			t.Fatalf("revocation after failover: HTTP %d", code)
		}
	}
	spent, err := c.signer.WithTTL(operatorauth.MaxTokenValidity).Authorization("PUT", "/secrets/pilot/operator", body)
	if err != nil {
		t.Fatal(err)
	}
	put := func(r *replica) (int, []byte) {
		req := pilotRequest(t, "PUT", r.base+"/secrets/pilot/operator", body)
		req.Header.Set("Authorization", spent)
		return pilotDo(t, c.client, req)
	}
	if code, response := put(c.replicas[0]); code != 409 || strings.TrimSpace(string(response)) == operatorauth.ErrTokenReused.Error() {
		t.Fatalf("fresh token was not consumed: HTTP %d", code)
	}
	f := objects.recovery
	// Exercise the same fixed-phase registration and encrypted witness used by
	// the native three-guest agent. Only this local wrapping root is simulated.
	root := bytes.Clone(f.wrappingKey)
	t.Cleanup(func() { clear(root) })
	newProtected := func() *threeHostProtected {
		m, err := metadatapilot.NewClient(objects.config.MetadataEndpoint, objects.config.Prefix, ha.m.token, ha.m.client.Transport)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(m.Close)
		p := &threeHostProtected{owner: t, slot: 0, metadata: m, wrap: bytes.Clone(root), verifier: f.verifier}
		t.Cleanup(func() { clear(p.wrap) })
		return p
	}
	s := &threeHostState{c: c, w: w, protected: newProtected()}
	record, err := os.ReadFile(f.record)
	if err != nil {
		t.Fatal(err)
	}
	if err := protected.Publish(t.Context(), s.protected.metadata, protected.Registration, jsonBody(t, protectedRegistration{Record: record, Capsule: f.capsule})); err != nil {
		t.Fatal(err)
	}
	checkpoint := make(map[string]any)
	s.checkpointProtected(checkpoint)
	oldGrant := bytes.Clone(f.last[0])
	for _, r := range c.replicas {
		c.kill(r)
		select {
		case <-r.cds.exited:
		default:
			t.Fatal("source CDS process still running")
		}
	}
	f.closeAuthority()
	clear(f.key)
	f.key = nil
	clear(f.signer)
	f.signer = nil
	clear(f.wrappingKey)
	clear(s.protected.wrap)
	s.protected.metadata.Close()
	w.client.CloseIdleConnections()
	w.client, w.key = nil, newKey(t)
	// Drop every adapter process too: only the durable metadata and original
	// encrypted capsule, plus the software custody root, may recover the state.
	for i := range 3 {
		ha.stopAdapter(i)
	}
	for i := range 3 {
		ha.startAdapter(i)
	}
	// A fresh agent reconstructs its authority from the committed registration.
	objects.recovery = nil
	s = &threeHostState{c: c, w: w, protected: newProtected()}
	s.restoreProtected(make(map[string]any))
	f = objects.recovery
	second := (leader + 1) % 3
	ha.etcd.Stop(second)
	for _, r := range c.replicas {
		r.db = filepath.Join(c.dir, fmt.Sprintf("empty-replacement-%d.db", r.index))
		c.restart(r)
		c.awaitStatus(r)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	grant, releaseErr := f.authority.Release(ctx, c.replicas[0].base)
	cancel()
	if releaseErr == nil || grant != nil {
		t.Fatal("cold authority released a key without metadata quorum")
	}
	if code, _ := c.send(c.replicas[0], "POST", "/ha/object-wal/provision", oldGrant, nil); code != http.StatusForbidden {
		t.Fatalf("new incarnation accepted an earlier grant: HTTP %d", code)
	}
	var raw cdsobject.Provision
	if err := json.Unmarshal(objects.provision, &raw); err != nil || len(raw.Key) != 0 || raw.Grant != nil {
		t.Fatal("relay provisioning contains key material or a retained grant")
	}
	ha.etcd.Start(second)
	ha.etcd.Start(leader)
	ha.ready()
	for _, r := range c.replicas {
		c.provisionObjects(r)
	}
	c.waitServing(time.Minute)
	checks := make(map[string]any)
	s.checkProtected(checks)
	if checks["ca_fingerprint"] != checkpoint["ca_fingerprint"] || checks["original_leaf_and_secret_positive_control"] != true {
		t.Fatal("encrypted witness did not preserve the original client and CA")
	}
	_, expiry, err := operatorauth.UnverifiedTimes(strings.TrimPrefix(spent, "Bearer "))
	if err != nil || !time.Now().Before(expiry) {
		t.Fatal("replay probe expired before cold recovery; result invalid")
	}
	w.client.CloseIdleConnections()
	for _, r := range c.replicas {
		if c.servedCA(r) != ca {
			t.Fatal("cold recovery changed the CA identity")
		}
		if code, response := put(r); code != 409 || strings.TrimSpace(string(response)) != operatorauth.ErrTokenReused.Error() {
			t.Fatalf("cold recovery forgot a live spent token: HTTP %d", code)
		}
		if code, _ := pilotDo(t, w.client, w.secretRequest(r, "GET", "/pilot/operator")); code != http.StatusForbidden {
			t.Fatalf("cold recovery forgot acknowledged revocation: HTTP %d", code)
		}
	}
	// The original workload leaf remains usable after an explicit new grant.
	// This distinguishes revocation from broken identity or expired credentials.
	w.setPolicy(true)
	w.assertEveryReplicaReads("/pilot/operator", value)
	w.issue(c.replicas[1], c.replicas[2])
	t.Log("PASS: real 3-member metadata HA, 3 adapters, all CDS processes lost, cold capsule restoration, no grant without quorum, old grant refused, same CA, live replay rejection, revocation and original-leaf positive control; software custody only")
}
