package cdsattest

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// An acme front door (TEE-held in-guest ACME serving key) serves attest-lb,
// with the mode committed into the transcript.
func TestAttestLBServedOnACMEFrontDoor(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	certPath, servingDER := writeTestServingLeaf(t)
	prov := &capturingProvider{}
	srv := NewServer(Config{
		Evidence:             prov,
		FrontDoorMode:        types.FrontDoorModeACME,
		ServingCertFile:      certPath,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(ts.URL + "/.well-known/c8s/attest-lb?nonce=" + b64url(nonce))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var b types.AttestationBundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	if b.Version != types.BindingAttestLB {
		t.Fatalf("version = %q", b.Version)
	}
	if b.FrontDoorMode != types.FrontDoorModeACME {
		t.Fatalf("front_door_mode = %q, want %q", b.FrontDoorMode, types.FrontDoorModeACME)
	}
	servingHash := sha256.Sum256(servingDER)
	if b.ServingLeafSHA256 != b64url(servingHash[:]) {
		t.Fatalf("serving_leaf_sha256 = %q, want hash of the served leaf", b.ServingLeafSHA256)
	}
	// Recompute the transcript from the served mode: report_data must commit
	// "acme", so a relay cannot re-serve this response under another mode.
	want, err := overenc.LBTranscriptHash(b.FrontDoorMode, nonce, servingDER, identity.leaf.Raw, identity.ca.Raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prov.lastReportData, want) {
		t.Fatal("report_data does not commit the acme-mode lb transcript")
	}
	other, err := overenc.LBTranscriptHash(types.FrontDoorModeCDS, nonce, servingDER, identity.leaf.Raw, identity.ca.Raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(prov.lastReportData, other) {
		t.Fatal("acme and cds transcripts collide: the mode is not bound")
	}
}

// attest-pq commits the front-door mode the same way.
func TestAttestPQCommitsFrontDoorMode(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	prov := &capturingProvider{}
	srv := NewServer(Config{
		Evidence:             prov,
		FrontDoorMode:        types.FrontDoorModeACME,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ck, err := overenc.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	b := fetchBundle(t, ts.URL, ck, nonce)
	if b.FrontDoorMode != types.FrontDoorModeACME {
		t.Fatalf("front_door_mode = %q, want %q", b.FrontDoorMode, types.FrontDoorModeACME)
	}
	ct, err := base64.RawURLEncoding.DecodeString(b.XWingCT)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := base64.RawURLEncoding.DecodeString(b.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	want, err := overenc.IdentityTranscriptHash(b.FrontDoorMode, ck.EncapsulationKey(), ct, sessionID, nonce, identity.leaf.Raw, identity.ca.Raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prov.lastReportData, want) {
		t.Fatal("report_data does not commit the front-door mode")
	}
}

// A front door with no stated mode has nothing to commit: attest-pq refuses
// rather than serve an unclassified binding.
func TestAttestPQRefusedWithoutFrontDoorMode(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence:             &capturingProvider{},
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ck, err := overenc.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(types.AttestPQRequest{
		Nonce:   b64url(make([]byte, 32)),
		XWingEK: b64url(ck.EncapsulationKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := postAttestPQ(t, ts.URL, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", resp.StatusCode)
	}
	if e := decodeErr(t, resp); e.Error != types.ErrorCodeBindingUnavailable {
		t.Fatalf("error code = %q, want %q", e.Error, types.ErrorCodeBindingUnavailable)
	}
}
