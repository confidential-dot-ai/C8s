//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsobject"
	"github.com/confidential-dot-ai/c8s/internal/cdsrecovery"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// This separate logical authority is a SOFTWARE FIXTURE. It owns the WAL key,
// approves launch files, and retains the signed public registration on disk.
// Its secret keys remain in the test custodian's memory, without hardware
// protection. The relay payload contains only
// ciphertext and storage credentials. Tests run sequentially on fixed ports.
type recoveryFixture struct {
	key       []byte
	signer    ed25519.PrivateKey
	verifier  string
	record    string
	authority interface {
		Release(context.Context, string) (*cdsrecovery.Grant, error)
		Close()
	}
	currentPolicy bool
	wrappingKey   []byte // Software root only; never a hardware custody claim.
	capsule       cdsrecovery.Capsule
	closeReplay   func()
	last          map[int][]byte
}

func protectRecovery(t *testing.T, f *objectFixture) {
	t.Helper()
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var p cdsobject.Provision
	if err := json.Unmarshal(f.provision, &p); err != nil {
		t.Fatal(err)
	}
	f.recovery = &recoveryFixture{key: p.Key, signer: signer, last: make(map[int][]byte), record: filepath.Join(t.TempDir(), "registration.json")}
	f.config.KeySHA256 = ""
	f.config.RecoveryAuthority = base64.StdEncoding.EncodeToString(public)
	p.Key = nil
	clear(f.provision)
	f.provision = jsonBody(t, p) // Relay never receives plaintext key material.
	t.Cleanup(func() {
		f.recovery.closeAuthority()
		clear(f.recovery.key)
		clear(f.recovery.signer)
		clear(f.recovery.wrappingKey)
	})
}

func (f *recoveryFixture) enroll(c *cluster) {
	c.t.Helper()
	c.awaitStatus(c.replicas[0])
	f.verifier = c.attestationAPI("recovery-authority", testutil.TestMeasurement)
	hash := sha256.Sum256(c.config)
	policy := cdsrecovery.Enrollment{Identity: cdsrecovery.Identity{ClusterID: c.id(), ConfigSHA256: hex.EncodeToString(hash[:]), Prefix: c.objectWAL.config.Prefix},
		Pins: []byte(testutil.CDSPinDocument(testutil.TestMeasurement, string(c.config)))}
	for _, r := range c.replicas {
		policy.Origins = append(policy.Origins, r.base)
	}
	record, err := cdsrecovery.Enroll(c.t.Context(), policy, c.replicas[0].base, f.verifier, f.key, f.signer)
	if err != nil {
		c.t.Fatal(err)
	}
	file, err := os.OpenFile(f.record, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		c.t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write(record); err != nil {
		c.t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		c.t.Fatal(err)
	}
	if f.currentPolicy {
		f.capsule, err = cdsrecovery.SealAuthority(policy.Identity, record, f.key, f.signer, f.wrappingKey)
		if err != nil {
			c.t.Fatal(err)
		}
	}
	f.restore(c)
}

// Restore loads the same signed enrollment. It never infers initialization
// permission from a missing head or a restarted authority's empty memory.
func (f *recoveryFixture) restore(c *cluster) {
	c.t.Helper()
	f.closeAuthority()
	record, err := os.ReadFile(f.record)
	if err != nil {
		c.t.Fatal(err)
	}
	hash := sha256.Sum256(c.config)
	expected := cdsrecovery.Identity{ClusterID: c.id(), ConfigSHA256: hex.EncodeToString(hash[:]), Prefix: c.objectWAL.config.Prefix}
	if f.currentPolicy {
		f.restoreCurrent(c, expected, record)
		return
	}
	authority, err := cdsrecovery.NewAuthority(c.t.Context(), expected, record, f.key, f.signer, f.verifier)
	if err != nil {
		c.t.Fatal(err)
	}
	f.authority = authority
}

func (f *recoveryFixture) grant(c *cluster, r *replica, key []byte, initialize bool, signer ed25519.PrivateKey) *cdsrecovery.Grant {
	c.t.Helper()
	if f.verifier == "" {
		f.verifier = c.attestationAPI("recovery-authority", testutil.TestMeasurement)
	}
	h := sha256.Sum256(c.config)
	digest, err := hex.DecodeString(testutil.TestMeasurement)
	if err != nil {
		c.t.Fatal(err)
	}
	g, err := cdsrecovery.Release(c.t.Context(), cdsrecovery.Identity{
		ClusterID: c.id(), ConfigSHA256: hex.EncodeToString(h[:]), Prefix: c.objectWAL.config.Prefix,
	}, cdsrecovery.Target{Origin: r.base, AttestationURL: f.verifier, Images: []remote.ImagePin{{Digest: digest, LaunchFile: c.config}}},
		cdsrecovery.Material{Key: key, AllowGenesis: initialize}, signer)
	if err != nil {
		c.t.Fatal(err)
	}
	return g
}

func (f *recoveryFixture) payload(c *cluster, grant *cdsrecovery.Grant) []byte {
	c.t.Helper()
	var p cdsobject.Provision
	if err := json.Unmarshal(c.objectWAL.provision, &p); err != nil {
		c.t.Fatal(err)
	}
	p.Grant = grant
	return jsonBody(c.t, p)
}

func TestProtectedRecoveryRefusesDowngradeReplayAndMissingHistory(t *testing.T) {
	objects := newObjectFixture(t)
	protectRecovery(t, objects)
	f := objects.recovery
	c := newClusterWithObjects(t, threeReplicas, objects)
	c.replaceAllowlist(c.replicas[0], "acknowledged-before-recovery")
	a, b := c.replicas[0], c.replicas[1]
	post := func(r *replica, p []byte, want int) {
		t.Helper()
		code, answer := c.send(r, http.MethodPost, "/ha/object-wal/provision", p, nil)
		if code != want {
			t.Fatalf("provision replica %d: HTTP %d, want %d: %s", r.index, code, want, answer)
		}
	}
	// Retry in the same process is safe, including after a lost response.
	post(a, f.last[a.index], http.StatusNoContent)
	post(b, f.last[a.index], http.StatusForbidden)
	var raw cdsobject.Provision
	if err := json.Unmarshal(objects.provision, &raw); err != nil {
		t.Fatal(err)
	}
	raw.Key = bytes.Repeat([]byte{42}, 32)
	post(b, jsonBody(t, raw), http.StatusForbidden)
	_, impostor, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	post(b, f.payload(c, f.grant(c, b, f.key, false, impostor)), http.StatusForbidden)
	post(b, f.payload(c, f.grant(c, b, bytes.Repeat([]byte{99}, 32), false, f.signer)), http.StatusForbidden)
	bad := f.grant(c, b, f.key, false, f.signer)
	bad.Record.CT[0] ^= 1
	post(b, f.payload(c, bad), http.StatusForbidden)
	if !c.allServe("acknowledged-before-recovery") {
		t.Fatal("refused provisioning changed serving state")
	}
	stale := bytes.Clone(f.last[a.index])
	for _, r := range c.replicas {
		c.kill(r)
	}
	f.restore(c)
	// Delete only this fixture's head. Old immutable objects cannot establish
	// which history is current. A recovering process must not invent a new CA.
	head := "/" + objects.config.Bucket + "/" + objects.config.Prefix + "/head"
	shard := objects.shard(head)
	shard.mu.Lock()
	_, exists := shard.objects[head]
	delete(shard.objects, head)
	shard.mu.Unlock()
	if !exists {
		t.Fatal("test did not remove the committed head")
	}
	for _, r := range c.replicas {
		c.restart(r)
		c.awaitStatus(r)
	}
	post(a, stale, http.StatusForbidden)
	for _, r := range c.replicas {
		c.provisionObjects(r)
	}
	// Refreshing credentials cannot elevate a process that began in recovery
	// mode, even if a later grant carries initialization permission.
	post(a, f.payload(c, f.grant(c, a, f.key, true, f.signer)), http.StatusNoContent)
	// A valid operator decree cannot override a recovery-only grant.
	reported := c.awaitStatus(a)
	nodes, err := cdsdecree.NewNodeImages([]byte(nodeImagesDocument))
	if err != nil {
		t.Fatal(err)
	}
	d := cdsdecree.Decree{Kind: cdsdecree.Genesis, ClusterID: clusterID, IntentID: cdsdecree.NewIntentID(),
		ExpiresAt: time.Now().Add(time.Hour), IssuedAtMS: time.Now().UnixMilli(), TargetMember: reported.ID,
		TargetAddress: fmt.Sprintf("%s:%d", a.host, clientPort), GenesisCA: reported.GenesisCA,
		CDSPins: c.pinDocument(testutil.TestMeasurement), NodePins: nodes}
	signed, err := cdsdecree.Sign(d, c.operator)
	if err != nil {
		t.Fatal(err)
	}
	code, body := c.send(a, http.MethodPost, "/ha/decrees", jsonBody(t, signed), nil)
	if code == http.StatusOK || !bytes.Contains(body, []byte("does not authorize Genesis")) {
		t.Fatalf("recovery allowed replacement Genesis: HTTP %d %s", code, body)
	}
	for _, r := range c.replicas {
		if c.awaitStatus(r).Joined {
			t.Fatal("joined without committed history")
		}
		if code, _ := c.get(r, "/ca"); code != http.StatusServiceUnavailable {
			t.Fatalf("released identity without history: HTTP %d", code)
		}
	}
	t.Log("refused raw keys, wrong authority/key/recipient, tampering, stale grants, and replacement identity after head loss")
}
