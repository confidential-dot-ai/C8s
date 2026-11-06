//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsobject"
	"github.com/confidential-dot-ai/c8s/internal/cdsrecovery"
	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/test/pilot/cds-sealed-recovery/snpaccept"
	"github.com/confidential-dot-ai/c8s/test/pilot/cds-three-host/protocol"
	protected "github.com/confidential-dot-ai/c8s/test/pilot/cds-three-host/recovery"
)

// Owned by the agent's existing bounded phase actor. No key is accepted from
// the host and no wrapping, state, signing, CA or workload private key is output.
type threeHostProtected struct {
	owner     *testing.T
	slot      int
	hardware  *snpaccept.TDXHardware
	recipient *snpaccept.CustodyRecipient
	signer    ed25519.PrivateKey
	wrap      []byte
	metadata  *metadatapilot.Client
	verifier  string // Fixed guest loopback verifier; never accepted in a request.
}

type protectedRegistration struct {
	Record  []byte              `json:"record"`
	Capsule cdsrecovery.Capsule `json:"capsule"`
}

type protectedWitness struct {
	snpClientState
	Sandbox string `json:"sandbox"`
}

func (s *threeHostState) setupProtected(t *testing.T, slot int) {
	if s.c.objectWAL == nil || s.c.objectWAL.config.RecoveryAuthority == "" {
		return
	}
	f := s.c.objectWAL
	config := f.config
	var provision cdsobject.Provision
	if !config.DirectState || !config.AtomicOperatorWrites || config.KeySHA256 != "" ||
		json.Unmarshal(f.provision, &provision) != nil || len(provision.Key) != 0 || provision.Grant != nil || provision.MetadataToken == "" {
		t.Fatal("protected fixture requires direct state and credential-only provisioning")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(config.MetadataRootCA)) {
		t.Fatal("measured metadata CA required")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, ResponseHeaderTimeout: 6 * time.Second}
	f.client = &http.Client{Transport: transport, Timeout: 7 * time.Second}
	t.Cleanup(f.client.CloseIdleConnections)
	f.metadata = &metadataFixture{owner: s.c, endpoint: config.MetadataEndpoint, client: f.client, namespace: config.Prefix, token: provision.MetadataToken}
	m, err := metadatapilot.NewClient(config.MetadataEndpoint, config.Prefix, provision.MetadataToken, transport)
	if err != nil {
		t.Fatal(err)
	}
	p := &threeHostProtected{owner: t, slot: slot, metadata: m, verifier: "http://127.0.0.1:8400"}
	s.protected = p
	t.Cleanup(func() {
		m.Close()
		if p.hardware != nil {
			p.hardware.Close()
		}
		if f.recovery != nil {
			f.recovery.closeAuthority()
		}
		clear(p.signer)
		clear(p.wrap)
	})
}

func (s *threeHostState) recoveryIdentity() cdsrecovery.Identity {
	h := sha256.Sum256(s.c.config)
	return cdsrecovery.Identity{ClusterID: s.c.id(), ConfigSHA256: hex.EncodeToString(h[:]), Prefix: s.c.objectWAL.config.Prefix}
}

func (s *threeHostState) protectedPhase(q protocol.Request, out map[string]any) bool {
	p, c, t := s.protected, s.c, s.c.t
	switch q.Operation {
	case "custody-request":
		if q.Target != p.slot || p.recipient != nil || len(p.wrap) != 0 {
			t.Fatal("one custody recipient per owned guest incarnation")
		}
		var err error
		p.hardware, err = snpaccept.OpenTDXHardware(p.owner.Context(), c.config)
		if err != nil {
			t.Fatal(err)
		}
		var request snpaccept.CustodyRequest
		p.recipient, request, err = snpaccept.NewTDXCustodyRecipient(t.Context(), p.hardware)
		if err != nil {
			t.Fatal(err)
		}
		out["recipient"] = request // Public ephemeral recipient and native quote only.
	case "custody-accept":
		if q.Target != p.slot || p.recipient == nil || len(p.wrap) != 0 {
			t.Fatal("fresh local custody recipient required")
		}
		var grant snpaccept.CustodyGrant
		decoder := json.NewDecoder(bytes.NewReader(q.Custody))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&grant); err != nil {
			t.Fatal(err)
		}
		public, err := cdsrecovery.ParseAuthority(c.objectWAL.config.RecoveryAuthority)
		if err != nil {
			t.Fatal(err)
		}
		p.signer, p.wrap, err = p.recipient.Open(grant, public)
		if err != nil {
			t.Fatal(err)
		}
		out["attested_custodian_delegation"] = true
	case "recovery-enroll":
		if p.slot != 0 || q.Target != 0 || len(p.wrap) != 32 || c.objectWAL.recovery != nil {
			t.Fatal("protected first-guest enrollment required")
		}
		if _, err := protected.Read(t.Context(), p.metadata, protected.Registration); !errors.Is(err, objectwal.ErrNotFound) {
			t.Fatal("registration must be positively observed absent before enrollment")
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		defer clear(key)
		policy := cdsrecovery.Enrollment{Identity: s.recoveryIdentity(), Pins: []byte(c.cdsPinDocument())}
		for _, r := range c.replicas {
			policy.Origins = append(policy.Origins, r.base)
		}
		c.awaitStatus(c.replicas[0])
		var bundle protectedRegistration
		var err error
		bundle.Record, err = cdsrecovery.Enroll(t.Context(), policy, c.replicas[0].base, p.verifier, key, p.signer)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Capsule, err = cdsrecovery.SealAuthority(policy.Identity, bundle.Record, key, p.signer, p.wrap)
		if err != nil {
			t.Fatal(err)
		}
		if err = protected.Publish(t.Context(), p.metadata, protected.Registration, jsonBody(t, bundle)); err != nil {
			t.Fatal(err)
		}
		s.restoreProtected(out)
	case "recovery-restore":
		if q.Target != p.slot || len(p.wrap) != 32 || c.objectWAL.recovery != nil {
			t.Fatal("fresh protected custody required")
		}
		s.restoreProtected(out)
	case "recovery-genesis":
		if p.slot != 0 || q.Target != 0 || c.objectWAL.recovery == nil {
			t.Fatal("enrolled first guest required")
		}
		b, err := refvalues.Render(threeHostConfig.Nodes)
		if err != nil {
			t.Fatal(err)
		}
		c.genesisCertifying(c.replicas[0], string(b), 0)
		out["protected_genesis_decreed"] = true
	case "recovery-refuse":
		if c.objectWAL.recovery == nil {
			t.Fatal("restored authority required")
		}
		ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
		defer cancel()
		grant, err := c.objectWAL.recovery.authority.Release(ctx, c.replicas[q.Target].base)
		if err == nil || grant != nil {
			t.Fatal("authority released a key without current metadata")
		}
		out["recovery_key_release_refused"] = true
	case "recovery-checkpoint":
		s.checkpointProtected(out)
	case "recovery-check":
		s.checkProtected(out)
	default:
		return false
	}
	return true
}

func (s *threeHostState) restoreProtected(out map[string]any) {
	p, c, t := s.protected, s.c, s.c.t
	b, err := protected.Read(t.Context(), p.metadata, protected.Registration)
	if err != nil {
		t.Fatal(err)
	}
	var bundle protectedRegistration
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		t.Fatal(err)
	}
	f := &recoveryFixture{lifetime: p.owner.Context(), currentPolicy: true, wrappingKey: p.wrap,
		verifier: p.verifier, record: filepath.Join(c.dir, "registration.json"), capsule: bundle.Capsule, last: make(map[int][]byte)}
	c.objectWAL.recovery = f
	f.restoreCurrent(c, s.recoveryIdentity(), bundle.Record)
	clear(p.signer)
	p.signer = nil
	h := sha256.Sum256(b)
	out["registration_sha256"] = hex.EncodeToString(h[:])
}

func (s *threeHostState) witnessAAD() []byte {
	i := s.recoveryIdentity()
	return []byte("c8s/cds-three-host/protected-witness/v1\x00" + i.ClusterID + "\x00" + i.ConfigSHA256 + "\x00" + i.Prefix)
}

func (s *threeHostState) checkpointProtected(out map[string]any) {
	c, w, t, p := s.c, s.w, s.c.t, s.protected
	if c.objectWAL.recovery == nil || len(p.wrap) != 32 || w.client == nil {
		t.Fatal("provisioned workload and hardware custody required")
	}
	s.phase(protocol.Request{Operation: "prepare", Target: 0}, map[string]any{})
	w.setPolicy(false)
	for _, r := range c.replicas {
		if code, _ := pilotDo(t, w.client, w.secretRequest(r, "GET", "/pilot/operator")); code != 403 {
			t.Fatal("pre-loss revocation failed")
		}
	}
	_, expiry, err := operatorauth.UnverifiedTimes(strings.TrimPrefix(s.spent, "Bearer "))
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalECPrivateKey(w.key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	before := protectedWitness{Sandbox: pilotSandbox, snpClientState: snpClientState{
		CA: c.servedCA(c.replicas[0]), OperatorAuthorization: s.spent,
		OperatorBody:  jsonBody(t, secrets.PutRequest{Value: base64.StdEncoding.EncodeToString([]byte("synthetic three-host qualification secret"))}),
		ReplayExpires: expiry, Secret: []byte("synthetic three-host qualification secret"), WorkloadKey: key,
		WorkloadCertificates: w.client.Transport.(*http.Transport).TLSClientConfig.Certificates[0].Certificate}}
	plain := jsonBody(t, before)
	defer clear(plain)
	cipher, err := snpStateCipher(p.wrap)
	if err != nil {
		t.Fatal(err)
	}
	if err = protected.Publish(t.Context(), p.metadata, protected.Witness, cipher.Seal(nil, nil, plain, s.witnessAAD())); err != nil {
		t.Fatal(err)
	}
	out["ca_fingerprint"], out["replay_expires"] = before.CA, expiry.UTC().Format(time.RFC3339Nano)
	out["revocation_acknowledged_before_loss"], out["encrypted_witness_committed"] = true, true
}

func (s *threeHostState) checkProtected(out map[string]any) {
	c, w, t, p := s.c, s.w, s.c.t, s.protected
	if c.objectWAL.recovery == nil || len(p.wrap) != 32 {
		t.Fatal("protected recovery must precede witness checks")
	}
	b, err := protected.Read(t.Context(), p.metadata, protected.Witness)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := snpStateCipher(p.wrap)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := cipher.Open(nil, nil, b, s.witnessAAD())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	var before protectedWitness
	if err := json.Unmarshal(plain, &before); err != nil {
		t.Fatal(err)
	}
	defer clear(before.WorkloadKey)
	if time.Until(before.ReplayExpires) < 30*time.Second {
		t.Fatal("live pre-loss replay token required")
	}
	w.key, err = x509.ParseECPrivateKey(before.WorkloadKey)
	if err != nil {
		t.Fatal(err)
	}
	pilotSandbox = before.Sandbox
	if w.client != nil {
		w.client.CloseIdleConnections()
	}
	transport := c.client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: before.WorkloadCertificates, PrivateKey: w.key}}
	w.client = &http.Client{Transport: transport, Timeout: 15 * time.Second}
	p.owner.Cleanup(w.client.CloseIdleConnections)
	c.waitServing(time.Minute)
	for _, r := range c.replicas {
		if c.servedCA(r) != before.CA {
			t.Fatal("total replica loss changed CA")
		}
		if code, body := snpReplay(t, c, before.snpClientState, r); code != 409 || strings.TrimSpace(string(body)) != operatorauth.ErrTokenReused.Error() {
			t.Fatal("live spent token not rejected after total loss")
		}
		if code, _ := pilotDo(t, w.client, w.secretRequest(r, "GET", "/pilot/operator")); code != 403 {
			t.Fatal("revocation lost after total replica loss")
		}
	}
	w.setPolicy(true)
	w.assertEveryReplicaReads("/pilot/operator", before.Secret)
	w.setPolicy(false)
	out["ca_fingerprint"] = before.CA
	out["same_ca_all_replicas"], out["live_spent_tokens_rejected"], out["revocation_preserved"] = true, true, true
	out["original_leaf_and_secret_positive_control"] = true
}
