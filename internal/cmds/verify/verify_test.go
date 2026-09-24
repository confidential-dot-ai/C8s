package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// mintSelfSigned creates a throwaway self-signed P-256 certificate (cn,
// serial) around key — minting a fresh key when nil — and returns the key and
// the certificate DER.
func mintSelfSigned(t *testing.T, cn string, serial int64, key *ecdsa.PrivateKey) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	if key == nil {
		var err error
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31-1, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

// selfSignedCertPEM returns a throwaway ECDSA P-256 certificate (PEM) and its
// public key, for testing REPORTDATA-binding math without real SNP crypto.
func selfSignedCertPEM(t *testing.T) (string, *ecdsa.PublicKey) {
	t.Helper()
	key, der := mintSelfSigned(t, "cds", 1, nil)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), &key.PublicKey
}

func TestEvidenceFromDiscovery(t *testing.T) {
	certPEM, pub := selfSignedCertPEM(t)
	report := bytes.Repeat([]byte{0x01}, 1184)
	vcek := []byte("vcek-der-bytes")
	challenge := bytes.Repeat([]byte{0x05}, 32)

	buildDoc := func(platform, cert string) []byte {
		doc := map[string]any{
			"cds_tls": map[string]any{"certificate_pem": cert},
			"attestation": map[string]any{
				"platform":  platform,
				"challenge": base64.StdEncoding.EncodeToString(challenge),
				"evidence": map[string]any{
					"attestation_report": base64.StdEncoding.EncodeToString(report),
					"cert_chain":         map[string]any{"vcek": base64.StdEncoding.EncodeToString(vcek)},
				},
			},
		}
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	t.Run("forwards platform + evidence verbatim and binds cert key + challenge", func(t *testing.T) {
		ev, err := evidenceFromDiscovery(buildDoc("snp", certPEM), "test", leafTrust{}, nil)
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if ev.platform != "snp" {
			t.Errorf("platform = %q, want snp", ev.platform)
		}
		var inner map[string]any
		if err := json.Unmarshal(ev.rawEvidence, &inner); err != nil {
			t.Fatalf("rawEvidence not JSON: %v", err)
		}
		if inner["attestation_report"] != base64.StdEncoding.EncodeToString(report) {
			t.Error("evidence object not forwarded verbatim")
		}
		if ev.fresh {
			t.Error("discovery is bound to the issuance challenge, not a fresh nonce")
		}
		want, err := ratls.ReportDataForKey(pub, challenge)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ev.erd, keyAnchor(want)) {
			t.Error("erd must equal the unpadded ReportDataForKey(cert.pubkey, challenge) — the issuance binding")
		}
	})

	t.Run("forwards a non-snp platform (e.g. tdx) rather than rejecting it", func(t *testing.T) {
		ev, err := evidenceFromDiscovery(buildDoc("tdx", certPEM), "test", leafTrust{}, nil)
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if ev.platform != "tdx" {
			t.Errorf("platform = %q, want tdx forwarded", ev.platform)
		}
	})

	t.Run("rejects missing certificate", func(t *testing.T) {
		if _, err := evidenceFromDiscovery(buildDoc("snp", ""), "test", leafTrust{}, nil); err == nil {
			t.Fatal("expected error when certificate_pem is absent")
		}
	})
}

func TestNormalizeTarget(t *testing.T) {
	cases := []struct {
		raw      string
		port     int
		wantDial string
		wantBase string
	}{
		{"cds.example.com", 8443, "cds.example.com:8443", "https://cds.example.com:8443"},
		{"cds.example.com:9999", 8443, "cds.example.com:9999", "https://cds.example.com:9999"},
		{"https://lb.example.com", 443, "lb.example.com:443", "https://lb.example.com:443"},
		{"https://lb.example.com:8443/ignored", 443, "lb.example.com:8443", "https://lb.example.com:8443"},
		{"2001:db8::2", 8443, "[2001:db8::2]:8443", "https://[2001:db8::2]:8443"},
		{"[2001:db8::2]:9999", 8443, "[2001:db8::2]:9999", "https://[2001:db8::2]:9999"},
	}
	for _, c := range cases {
		dial, base, err := normalizeTarget(c.raw, c.port)
		if err != nil {
			t.Fatalf("normalizeTarget(%q): %v", c.raw, err)
		}
		if dial != c.wantDial || base != c.wantBase {
			t.Errorf("normalizeTarget(%q) = (%q,%q), want (%q,%q)", c.raw, dial, base, c.wantDial, c.wantBase)
		}
	}
}

func TestBuildPolicy_RejectsOutOfRangeMinTCB(t *testing.T) {
	if _, err := buildPolicy(config{minTCBSNP: 256}); err == nil {
		t.Fatal("expected --min-tcb-snp 256 to be rejected (would truncate to 0)")
	}
	if _, err := buildPolicy(config{minTCBBootloader: 255, minTCBTEE: 1}); err != nil {
		t.Errorf("in-range min-tcb values should be accepted: %v", err)
	}
}

func TestBuildPolicy_SandboxIDFlag(t *testing.T) {
	meshCA := writeMeshCAFile(t)

	t.Run("invalid sandbox ID is rejected", func(t *testing.T) {
		if _, err := buildPolicy(config{sandboxID: "not/valid!", meshCA: meshCA}); err == nil || !strings.Contains(err.Error(), "--sandbox-id") {
			t.Fatalf("err = %v, want a --sandbox-id validation error", err)
		}
	})

	t.Run("sandbox ID pin requires mesh-ca", func(t *testing.T) {
		// The ID lives in the leaf's signed area; without the chain check the
		// pin would compare a string the presenter chose.
		if _, err := buildPolicy(config{sandboxID: "8d9f6c2b1a0e"}); err == nil || !strings.Contains(err.Error(), "--mesh-ca") {
			t.Fatalf("err = %v, want the mesh-ca requirement", err)
		}
	})

	t.Run("sandbox ID with mesh-ca is accepted", func(t *testing.T) {
		if _, err := buildPolicy(config{sandboxID: "8d9f6c2b1a0e", meshCA: meshCA}); err != nil {
			t.Fatalf("buildPolicy: %v", err)
		}
	})
}

// writeMeshCAFile writes a valid CA PEM for the --mesh-ca flag.
func writeMeshCAFile(t *testing.T) string {
	t.Helper()
	id := mintEndpointIdentity(t)
	path := filepath.Join(t.TempDir(), "mesh-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.ca.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseExpectedReportData(t *testing.T) {
	if _, err := parseExpectedReportData(strings.Repeat("ab", 64)); err != nil {
		t.Errorf("64-byte hex should parse: %v", err)
	}
	if _, err := parseExpectedReportData(strings.Repeat("cd", 48)); err != nil {
		t.Errorf("48-byte hex should parse: %v", err)
	}
	// Any 1–64 bytes is accepted, kept unpadded — the binding digest length
	// isn't fixed across platforms/schemes.
	if got, err := parseExpectedReportData(strings.Repeat("ab", 10)); err != nil || len(got) != 10 {
		t.Errorf("10-byte hex should parse unpadded: %v (len %d)", err, len(got))
	}
	if _, err := parseExpectedReportData("zzzz"); err == nil {
		t.Error("non-hex should fail")
	}
	if _, err := parseExpectedReportData(""); err == nil {
		t.Error("empty should fail")
	}
	if _, err := parseExpectedReportData(strings.Repeat("ab", 65)); err == nil {
		t.Error("more than 64 bytes should fail")
	}
}

// endpointIdentity is a minted mesh identity (CA-signed ECDSA leaf plus its
// issuing CA) used to build attest-pq responses whose identity transcript and
// proof of possession actually verify.
type endpointIdentity struct {
	leaf     *x509.Certificate
	ca       *x509.Certificate
	key      *ecdsa.PrivateKey
	chainPEM string
}

func mintEndpointIdentity(t *testing.T) *endpointIdentity {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test mesh CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "lb.c8s-system.svc"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	return &endpointIdentity{leaf: leaf, ca: ca, key: leafKey, chainPEM: chain}
}

// ed25519Pub returns a fresh Ed25519 public key for the non-ECDSA-leaf case.
func ed25519Pub(t *testing.T) crypto.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// mintEndpointIdentityFrom is mintEndpointIdentity with the leaf's public key
// (nil => fresh ECDSA) and validity window chosen by the caller. The proof key
// stays ECDSA either way, so the verifier's own checks — not a build failure —
// decide the outcome.
func mintEndpointIdentityFrom(t *testing.T, leafPub crypto.PublicKey, notBefore, notAfter time.Time) *endpointIdentity {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test mesh CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if leafPub == nil {
		leafPub = &leafKey.PublicKey
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "lb.c8s-system.svc"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, leafPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	return &endpointIdentity{leaf: leaf, ca: ca, key: leafKey, chainPEM: chain}
}

// testSession is a fake X-Wing key exchange for response fixtures. Offline
// parsing only recomputes the transcript from these bytes, so arbitrary
// correctly-sized values suffice; a live-fetch fixture overwrites ek with the
// key the client actually sent (the gather checks the echo).
type testSession struct{ ek, ct, sid []byte }

func fakeSession(fill byte) testSession {
	return testSession{
		ek:  bytes.Repeat([]byte{fill}, overenc.XWingEKBytes),
		ct:  bytes.Repeat([]byte{fill + 1}, overenc.XWingCTBytes),
		sid: bytes.Repeat([]byte{fill + 2}, overenc.SessionIDBytes),
	}
}

// transcript computes the identity transcript the server would have bound for
// this identity and session.
func (id *endpointIdentity) transcript(t *testing.T, nonce []byte, s testSession) []byte {
	t.Helper()
	erd, err := overenc.IdentityTranscriptHash("cds", s.ek, s.ct, s.sid, nonce, id.leaf.Raw, id.ca.Raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return erd
}

// proofJSON builds the wire identity_proof object: ECDSA-SHA384 by the leaf
// key over sha512.Sum384(transcript), mirroring the sidecar's prove().
func (id *endpointIdentity) proofJSON(t *testing.T, transcript []byte) map[string]any {
	t.Helper()
	digest := sha512.Sum384(transcript)
	sig, err := ecdsa.SignASN1(rand.Reader, id.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	leafHash := sha256.Sum256(id.leaf.Raw)
	caHash := sha256.Sum256(id.ca.Raw)
	b64u := base64.RawURLEncoding.EncodeToString
	return map[string]any{
		"algorithm":      "ecdsa-sha384",
		"leaf_sha256":    b64u(leafHash[:]),
		"mesh_ca_sha256": b64u(caHash[:]),
		"signature":      b64u(sig),
	}
}

// buildEndpointJSON makes an attest-pq attestation-response body with the
// given fields. A nil identity omits the mesh chain and identity proof.
func buildEndpointJSON(t *testing.T, id *endpointIdentity, nonce, report, vcek []byte, s testSession) []byte {
	t.Helper()
	evidence := map[string]any{
		"attestation_report": base64.StdEncoding.EncodeToString(report),
		"cert_chain":         map[string]any{"vcek": base64.StdEncoding.EncodeToString(vcek)},
	}
	return buildEndpointJSONWithEvidence(t, id, nonce, evidence, s)
}

func buildEndpointJSONWithEvidence(t *testing.T, id *endpointIdentity, nonce []byte, evidence any, s testSession) []byte {
	t.Helper()
	b64u := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	resp := map[string]any{
		"version":         types.BindingAttestPQ,
		"platform":        "snp",
		"nonce":           b64u(nonce),
		"evidence":        evidence,
		"front_door_mode": "cds",
		"xwing_ek":        b64u(s.ek),
		"xwing_ct":        b64u(s.ct),
		"session_id":      b64u(s.sid),
	}
	if id != nil {
		resp["cds_cert_pem"] = id.chainPEM
		resp["identity_proof"] = id.proofJSON(t, id.transcript(t, nonce, s))
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// attestPQHandler answers POST /.well-known/c8s/attest-pq the way the sidecar
// does: echo the client's nonce and X-Wing key (a live gather checks both
// echoes) around a fake encapsulation.
func attestPQHandler(t *testing.T, id *endpointIdentity, report []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != attestationPath {
			http.NotFound(w, r)
			return
		}
		var req types.AttestPQRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		nonce, err := base64.RawURLEncoding.DecodeString(req.Nonce)
		if err != nil {
			http.Error(w, "bad nonce", http.StatusBadRequest)
			return
		}
		sess := fakeSession(0x02)
		if sess.ek, err = base64.RawURLEncoding.DecodeString(req.XWingEK); err != nil {
			http.Error(w, "bad xwing_ek", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildEndpointJSON(t, id, nonce, report, []byte("vcek"), sess))
	}
}

func TestEvidenceFromEndpointJSON(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x07}, nonceSize)
	report := bytes.Repeat([]byte{0x01}, 64)
	sess := fakeSession(0x02)
	id := mintEndpointIdentity(t)
	data := buildEndpointJSON(t, id, nonce, report, []byte("vcek"), sess)

	// mutateProof rebuilds data with one identity_proof field replaced.
	mutateProof := func(t *testing.T, field, value string) []byte {
		t.Helper()
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			t.Fatal(err)
		}
		obj["identity_proof"].(map[string]any)[field] = value
		out, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	t.Run("fresh when nonce echoes; erd is the identity transcript", func(t *testing.T) {
		ev, err := evidenceFromEndpointJSON(data, nonce, sess.ek, "test")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if !ev.fresh {
			t.Error("expected fresh=true when challenge echoes")
		}
		if !bytes.Equal(ev.erd, id.transcript(t, nonce, sess)) {
			t.Error("erd does not match the identity transcript over keys, nonce, leaf, and CA")
		}
		if ev.leaf == nil || !bytes.Equal(ev.leaf.Raw, id.leaf.Raw) {
			t.Error("the transcript-committed mesh leaf should surface for the --mesh-ca/--workload paths")
		}
	})

	t.Run("from-file (no expected nonce) verifies but stays non-fresh", func(t *testing.T) {
		ev, err := evidenceFromEndpointJSON(data, nil, nil, "file")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if ev.fresh {
			t.Error("a saved response must not count as a freshness proof")
		}
		if !bytes.Equal(ev.erd, id.transcript(t, nonce, sess)) {
			t.Error("erd must still be the identity transcript")
		}
	})

	t.Run("tampered proof signature is a security error", func(t *testing.T) {
		sig, err := ecdsa.SignASN1(rand.Reader, id.key, bytes.Repeat([]byte{0x5C}, 48))
		if err != nil {
			t.Fatal(err)
		}
		mutated := mutateProof(t, "signature", base64.RawURLEncoding.EncodeToString(sig))
		if _, err := evidenceFromEndpointJSON(mutated, nonce, sess.ek, "test"); err == nil || !isSecurityError(err) {
			t.Fatalf("expected securityError on a signature over the wrong transcript, got %v", err)
		}
	})

	t.Run("wrong leaf hash in the proof is a security error", func(t *testing.T) {
		otherHash := sha256.Sum256([]byte("not-the-leaf"))
		mutated := mutateProof(t, "leaf_sha256", base64.RawURLEncoding.EncodeToString(otherHash[:]))
		if _, err := evidenceFromEndpointJSON(mutated, nonce, sess.ek, "test"); err == nil || !isSecurityError(err) {
			t.Fatalf("expected securityError on leaf_sha256 mismatch, got %v", err)
		}
	})

	t.Run("committed CA absent from the served chain is a security error", func(t *testing.T) {
		otherHash := sha256.Sum256([]byte("not-a-served-ca"))
		mutated := mutateProof(t, "mesh_ca_sha256", base64.RawURLEncoding.EncodeToString(otherHash[:]))
		if _, err := evidenceFromEndpointJSON(mutated, nonce, sess.ek, "test"); err == nil || !isSecurityError(err) {
			t.Fatalf("expected securityError when no served cert matches mesh_ca_sha256, got %v", err)
		}
	})

	t.Run("unknown proof algorithm is a security error", func(t *testing.T) {
		mutated := mutateProof(t, "algorithm", "ecdsa-sha256")
		if _, err := evidenceFromEndpointJSON(mutated, nonce, sess.ek, "test"); err == nil || !isSecurityError(err) {
			t.Fatalf("expected securityError on an unknown proof algorithm, got %v", err)
		}
	})

	t.Run("undecodable proof fields are plain errors", func(t *testing.T) {
		// "!" is outside the base64url alphabet in every position.
		for field, want := range map[string]string{
			"mesh_ca_sha256": "mesh_ca_sha256",
			"leaf_sha256":    "leaf_sha256",
			"signature":      "signature",
		} {
			mutated := mutateProof(t, field, "!!!!")
			if _, err := evidenceFromEndpointJSON(mutated, nonce, sess.ek, "test"); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("field %s: err = %v, want a decode error naming it", field, err)
			}
		}
	})

	t.Run("unparseable or single-cert mesh chain rejected", func(t *testing.T) {
		for name, chain := range map[string]string{
			"garbage":   "not a certificate",
			"leaf only": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.leaf.Raw})),
		} {
			var obj map[string]any
			if err := json.Unmarshal(data, &obj); err != nil {
				t.Fatal(err)
			}
			obj["cds_cert_pem"] = chain
			mutated, err := json.Marshal(obj)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := evidenceFromEndpointJSON(mutated, nonce, sess.ek, "test"); err == nil || !strings.Contains(err.Error(), "cds_cert_pem") {
				t.Errorf("%s chain: err = %v, want a cds_cert_pem error", name, err)
			}
		}
	})

	t.Run("non-ECDSA mesh leaf key rejected", func(t *testing.T) {
		// A proof over an Ed25519 leaf cannot be the sidecar's ecdsa-sha384
		// construction, whatever the signature bytes claim.
		other := mintEndpointIdentityFrom(t, ed25519Pub(t), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		body := buildEndpointJSON(t, other, nonce, report, []byte("vcek"), sess)
		if _, err := evidenceFromEndpointJSON(body, nonce, sess.ek, "test"); err == nil || !strings.Contains(err.Error(), "ECDSA") {
			t.Fatalf("err = %v, want the ECDSA-only refusal", err)
		}
	})

	t.Run("expired committed leaf is a security error", func(t *testing.T) {
		// The committed chain must be currently valid: a stale saved identity
		// replayed after expiry fails closed even with a correct proof.
		expired := mintEndpointIdentityFrom(t, nil, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
		body := buildEndpointJSON(t, expired, nonce, report, []byte("vcek"), sess)
		if _, err := evidenceFromEndpointJSON(body, nonce, sess.ek, "test"); err == nil || !isSecurityError(err) || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("err = %v, want an expired-chain security error", err)
		}
	})

	t.Run("leaf not signed by the committed CA is a security error", func(t *testing.T) {
		// Serve id's leaf with a *different* identity's CA and commit that CA
		// honestly in the transcript and proof: everything verifies except the
		// issuing relationship, which must fail closed.
		other := mintEndpointIdentity(t)
		b64u := base64.RawURLEncoding.EncodeToString
		erd, err := overenc.IdentityTranscriptHash("cds", sess.ek, sess.ct, sess.sid, nonce, id.leaf.Raw, other.ca.Raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha512.Sum384(erd)
		sig, err := ecdsa.SignASN1(rand.Reader, id.key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		leafHash := sha256.Sum256(id.leaf.Raw)
		caHash := sha256.Sum256(other.ca.Raw)
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			t.Fatal(err)
		}
		obj["cds_cert_pem"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.leaf.Raw})) +
			string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.ca.Raw}))
		obj["identity_proof"] = map[string]any{
			"algorithm":      "ecdsa-sha384",
			"leaf_sha256":    b64u(leafHash[:]),
			"mesh_ca_sha256": b64u(caHash[:]),
			"signature":      b64u(sig),
		}
		mutated, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceFromEndpointJSON(mutated, nonce, sess.ek, "test"); err == nil || !isSecurityError(err) || !strings.Contains(err.Error(), "not signed by") {
			t.Fatalf("expected a chain securityError, got %v", err)
		}
	})

	t.Run("missing identity proof rejected", func(t *testing.T) {
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			t.Fatal(err)
		}
		delete(obj, "identity_proof")
		mutated, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceFromEndpointJSON(mutated, nonce, sess.ek, "test"); err == nil || !strings.Contains(err.Error(), "identity_proof") {
			t.Fatalf("expected a missing-proof error, got %v", err)
		}
	})

	t.Run("nonce mismatch is a security error (not swallowed by auto fallback)", func(t *testing.T) {
		_, err := evidenceFromEndpointJSON(data, bytes.Repeat([]byte{0x09}, nonceSize), sess.ek, "test")
		if err == nil || !isSecurityError(err) {
			t.Fatalf("expected securityError on nonce mismatch, got %v", err)
		}
		if isConnectError(err) {
			t.Error("nonce mismatch must not be a connectError (would trigger silent cert fallback)")
		}
	})

	t.Run("wrong or missing version rejected (cross-endpoint responses)", func(t *testing.T) {
		for _, version := range []string{"", "c8s-verify/v1", types.BindingAttestLB, "c8s/attest-pq/v2"} {
			var obj map[string]any
			if err := json.Unmarshal(data, &obj); err != nil {
				t.Fatal(err)
			}
			if version == "" {
				delete(obj, "version")
			} else {
				obj["version"] = version
			}
			mutated, err := json.Marshal(obj)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := evidenceFromEndpointJSON(mutated, nonce, sess.ek, "test"); err == nil || !strings.Contains(err.Error(), "version") {
				t.Errorf("version %q should be rejected, got %v", version, err)
			}
		}
	})

	t.Run("missing key exchange rejected", func(t *testing.T) {
		bare := buildEndpointJSON(t, nil, nonce, report, []byte("vcek"), testSession{})
		if _, err := evidenceFromEndpointJSON(bare, nonce, nil, "test"); err == nil || !strings.Contains(err.Error(), "xwing_ct") {
			t.Fatalf("expected error when the key-exchange fields are absent, got %v", err)
		}
	})

	t.Run("missing front_door_mode rejected", func(t *testing.T) {
		// The mode is a transcript field: a response without one cannot be
		// recomputed, so it fails closed rather than verifying mode-lessly.
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			t.Fatal(err)
		}
		delete(obj, "front_door_mode")
		mutated, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceFromEndpointJSON(mutated, nonce, sess.ek, "test"); err == nil || !strings.Contains(err.Error(), "front-door mode") {
			t.Fatalf("expected a missing-mode transcript error, got %v", err)
		}
	})

	t.Run("wrong-size key-exchange fields rejected", func(t *testing.T) {
		// The transcript is length-framed; IdentityTranscriptHash refuses a
		// non-canonical field size outright rather than producing a binding that
		// fails report-data match downstream.
		for field, want := range map[string]string{
			"xwing_ek":   "X-Wing key",
			"xwing_ct":   "ciphertext",
			"session_id": "session id",
		} {
			var obj map[string]any
			if err := json.Unmarshal(data, &obj); err != nil {
				t.Fatal(err)
			}
			obj[field] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x02}, 8))
			mutated, err := json.Marshal(obj)
			if err != nil {
				t.Fatal(err)
			}
			// From-file semantics (no expected key), so the echo check cannot
			// mask the size rejection under test.
			if _, err := evidenceFromEndpointJSON(mutated, nil, nil, "test"); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("truncated %s: err = %v, want a size error from the transcript", field, err)
			}
		}
	})

	t.Run("non-snp platform is forwarded, not rejected", func(t *testing.T) {
		var obj map[string]any
		_ = json.Unmarshal(data, &obj)
		obj["platform"] = "tdx"
		other, _ := json.Marshal(obj)
		ev, err := evidenceFromEndpointJSON(other, nonce, sess.ek, "test")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if ev.platform != "tdx" {
			t.Errorf("platform = %q, want tdx forwarded", ev.platform)
		}
	})
}

// TestEvidenceFromEndpointJSON_RealShape feeds a literal JSON document in the
// exact shape the attestation endpoint emits (per c8s-verify-js PROTOCOL.md),
// rather than one built from this package's own structs — so a renamed or
// re-nested wire field fails here even though the struct-built fixtures above
// wouldn't notice.
func TestEvidenceFromEndpointJSON_RealShape(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xA1}, nonceSize)
	sess := fakeSession(0xB2)
	report := bytes.Repeat([]byte{0xD4}, 64)
	b64u := base64.RawURLEncoding.EncodeToString

	id := mintEndpointIdentity(t)
	erd := id.transcript(t, nonce, sess)
	digest := sha512.Sum384(erd)
	sig, err := ecdsa.SignASN1(rand.Reader, id.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	leafHash := sha256.Sum256(id.leaf.Raw)
	caHash := sha256.Sum256(id.ca.Raw)

	payload := fmt.Sprintf(`{
  "version": %q,
  "platform": "snp",
  "nonce": %q,
  "evidence": {
    "attestation_report": %q,
    "cert_chain": { "vcek": %q }
  },
  "cds_cert_pem": %q,
  "front_door_mode": "cds",
  "xwing_ek": %q,
  "xwing_ct": %q,
  "session_id": %q,
  "identity_proof": { "algorithm": "ecdsa-sha384", "leaf_sha256": %q, "mesh_ca_sha256": %q, "signature": %q }
}`,
		types.BindingAttestPQ,
		b64u(nonce),
		base64.StdEncoding.EncodeToString(report),
		base64.StdEncoding.EncodeToString([]byte("vcek-der")),
		id.chainPEM,
		b64u(sess.ek), b64u(sess.ct), b64u(sess.sid),
		b64u(leafHash[:]), b64u(caHash[:]), b64u(sig),
	)

	ev, err := evidenceFromEndpointJSON([]byte(payload), nonce, sess.ek, "endpoint")
	if err != nil {
		t.Fatalf("real-shape endpoint payload should parse: %v", err)
	}
	if !ev.fresh {
		t.Error("expected fresh=true when the challenge echoes")
	}
	if ev.platform != "snp" {
		t.Errorf("platform = %q, want snp", ev.platform)
	}
	if !bytes.Equal(ev.erd, erd) {
		t.Error("erd does not match the identity transcript")
	}
	// The platform-specific evidence object is forwarded verbatim.
	if !bytes.Contains(ev.rawEvidence, []byte("attestation_report")) {
		t.Error("evidence object should be forwarded verbatim")
	}
}

// TestParseRealSNPEvidence drives a *real* captured {platform, evidence} object
// — a Genoa SEV-SNP report + VCEK, vendored from the c8s-verify-js reference
// impl's fixture (demo/fixtures/snp-evidence-genoa.json) — through the parser,
// so field/encoding drift between the JS and Go implementations fails here.
func TestParseRealSNPEvidence(t *testing.T) {
	fixture, err := os.ReadFile("testdata/snp-evidence-genoa.json")
	if err != nil {
		t.Fatal(err)
	}

	// The bare {platform, evidence} path consumes it directly.
	bare, err := evidenceFromBareJSON(fixture, make([]byte, 48), "fixture")
	if err != nil {
		t.Fatalf("evidenceFromBareJSON on the real fixture: %v", err)
	}
	if bare.platform != "snp" {
		t.Errorf("platform = %q, want snp", bare.platform)
	}
	if !bytes.Contains(bare.rawEvidence, []byte("attestation_report")) || !bytes.Contains(bare.rawEvidence, []byte("vcek")) {
		t.Error("real evidence (report + vcek) should be forwarded verbatim")
	}

	// The attestation endpoint wraps that same platform-specific evidence; parse
	// a real endpoint response built around it.
	var env struct {
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(fixture, &env); err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x5A}, nonceSize)
	sess := fakeSession(0xB2)
	id := mintEndpointIdentity(t)
	resp := buildEndpointJSONWithEvidence(t, id, nonce, env.Evidence, sess)

	ev, err := evidenceFromEndpointJSON(resp, nonce, sess.ek, "endpoint")
	if err != nil {
		t.Fatalf("evidenceFromEndpointJSON on the real-evidence response: %v", err)
	}
	if !ev.fresh {
		t.Error("expected fresh=true when the challenge echoes")
	}
	// json.Marshal compacts an embedded RawMessage, so compare against the
	// compacted fixture bytes: the value must round-trip unchanged.
	var wantEvidence bytes.Buffer
	if err := json.Compact(&wantEvidence, env.Evidence); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ev.rawEvidence, wantEvidence.Bytes()) {
		t.Error("real evidence object should round-trip unchanged through the endpoint parser")
	}
	if !bytes.Equal(ev.erd, id.transcript(t, nonce, sess)) {
		t.Error("erd binding mismatch")
	}
}

// TestVerifyRealAzSnpEvidence_UnpaddedAnchor drives real az-snp evidence (vTPM
// quote extraData = ASCII "challenge", VCEK inline; vendored from
// attestation-go's azsnp testdata) through the --from-file override path. The
// anchor must reach the verifier unpadded: the Azure vTPM verifiers compare it
// raw against the quote's extraData, so the historical zero-padding to 64
// bytes failed every az-snp target with "TPM nonce length mismatch".
func TestVerifyRealAzSnpEvidence_UnpaddedAnchor(t *testing.T) {
	fixture, err := os.ReadFile("testdata/azsnp-evidence-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := gatherFromFile(fixture, []byte("challenge"), "fixture", leafTrust{})
	if err != nil {
		t.Fatal(err)
	}
	if ev.platform != "az-snp" {
		t.Fatalf("platform = %q, want az-snp", ev.platform)
	}
	res, err := verifyInProcess(context.Background(), ev, &ratls.VerifyPolicy{}, nil, nil)
	if err != nil {
		t.Fatalf("az-snp evidence with its bound nonce must verify: %v", err)
	}
	if res.ReportDataMatch == nil || !*res.ReportDataMatch {
		t.Fatal("report_data_match must be affirmatively true")
	}

	// A different anchor fails closed, at the nonce gate specifically.
	ev.erd = []byte("not-the-nonce")
	if _, err := verifyInProcess(context.Background(), ev, &ratls.VerifyPolicy{}, nil, nil); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("wrong nonce must fail closed at the nonce check, got: %v", err)
	}
}

// TestNewOutcomeFromRealGenoaEvidence drives the vendored Genoa fixture
// through verifyInProcess + newOutcome and asserts the verdict carries the
// platform's real security state — the platform has SMT on, a value no
// hand-built PlatformData map can accidentally supply. The debug-off policy
// is pinned by the key's presence in the real claims: the fixture's value is
// the zero value, so value alone cannot catch a renamed key. Together these
// pin reportFlags against the engine's real claim keys: an attestation-go
// key rename fails here instead of silently reporting false. No TDX fixture
// verifies offline, so the TDX mapping keeps only the hand-built pin in
// TestRenderOutcome.
func TestNewOutcomeFromRealGenoaEvidence(t *testing.T) {
	fixture, err := os.ReadFile("testdata/snp-evidence-genoa.json")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := gatherFromFile(fixture, []byte("genoa-test-fixture"), "fixture", leafTrust{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := verifyInProcess(context.Background(), ev, &ratls.VerifyPolicy{}, nil, nil)
	if err != nil {
		t.Fatalf("the real fixture must verify: %v", err)
	}
	pol, ok := res.Claims.PlatformData["policy"].(map[string]any)
	if !ok {
		t.Fatalf("real claims carry no policy map, got %T", res.Claims.PlatformData["policy"])
	}
	if _, ok := pol["debug_allowed"].(bool); !ok {
		t.Fatalf("real claims lack a bool policy.debug_allowed — reportFlags would read a renamed key as false; policy = %v", pol)
	}
	oc := newOutcome(config{}, ev, res, nil, &verifyPlan{policy: &ratls.VerifyPolicy{}})
	if !oc.Verified || oc.Debug || !oc.SMT {
		t.Errorf("outcome = verified:%v debug:%v smt:%v, want verified:true debug:false smt:true", oc.Verified, oc.Debug, oc.SMT)
	}
	// The fixture binds ASCII "genoa-test-fixture", zero-padded to 64 bytes.
	wantRD := hex.EncodeToString([]byte("genoa-test-fixture")) + strings.Repeat("00", 64-len("genoa-test-fixture"))
	if oc.ReportData != wantRD {
		t.Errorf("report_data = %q, want the fixture's %q", oc.ReportData, wantRD)
	}
}

func TestGatherFromEndpoint_Integration(t *testing.T) {
	report := bytes.Repeat([]byte{0x01}, 64)
	id := mintEndpointIdentity(t)

	srv := httptest.NewTLSServer(attestPQHandler(t, id, report))
	defer srv.Close()

	ev, err := gatherFromEndpoint(context.Background(), srv.URL, "", 5*time.Second)
	if err != nil {
		t.Fatalf("gatherFromEndpoint: %v", err)
	}
	if !ev.fresh {
		t.Error("expected fresh evidence from live endpoint")
	}
	var inner map[string]any
	if err := json.Unmarshal(ev.rawEvidence, &inner); err != nil {
		t.Fatalf("rawEvidence not JSON: %v", err)
	}
	if inner["attestation_report"] != base64.StdEncoding.EncodeToString(report) {
		t.Error("evidence object not forwarded verbatim from the endpoint")
	}
}

func TestGatherFromEndpoint_HTTPErrorIsConnectError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := gatherFromEndpoint(context.Background(), srv.URL, "", 5*time.Second)
	if err == nil || !isConnectError(err) {
		t.Fatalf("expected connectError on HTTP 503, got %v", err)
	}
}

func TestRenderOutcome(t *testing.T) {
	ev := &evidence{
		platform:    "snp",
		source:      "test",
		bindingNote: "test binding",
		fresh:       true,
	}
	measHex := "ab" + strings.Repeat("00", 47) // 48-byte launch digest
	result := &teetypes.VerificationResult{SignatureValid: true, Claims: teetypes.Claims{LaunchDigest: measHex}}

	pinnedPlan := func(t *testing.T) *verifyPlan {
		t.Helper()
		m, err := refvalues.ParseHexMeasurementsList([]string{measHex})
		if err != nil {
			t.Fatal(err)
		}
		return &verifyPlan{policy: &ratls.VerifyPolicy{Policy: remote.Policy{Measurements: m}}}
	}
	emptyPlan := func() *verifyPlan { return &verifyPlan{policy: &ratls.VerifyPolicy{}} }

	t.Run("verified + pinned -> no UNSAFE warning", func(t *testing.T) {
		var out bytes.Buffer
		cfg := config{output: "text"}
		oc := newOutcome(cfg, ev, result, nil, pinnedPlan(t))
		render(cfg, oc, &out)
		if !oc.Verified {
			t.Fatalf("expected verified; oc=%+v", oc)
		}
		if !strings.Contains(out.String(), "VERIFIED") || strings.Contains(out.String(), "UNSAFE") {
			t.Errorf("unexpected output: %s", out.String())
		}
	})

	t.Run("unpinned warns UNSAFE", func(t *testing.T) {
		var out bytes.Buffer
		cfg := config{output: "text"}
		render(cfg, newOutcome(cfg, ev, result, nil, emptyPlan()), &out)
		if !strings.Contains(out.String(), "UNSAFE") {
			t.Errorf("expected UNSAFE warning when no measurements pinned: %s", out.String())
		}
	})

	t.Run("json output", func(t *testing.T) {
		var out bytes.Buffer
		cfg := config{output: "json"}
		render(cfg, newOutcome(cfg, ev, result, nil, emptyPlan()), &out)
		var oc Outcome
		if err := json.Unmarshal(out.Bytes(), &oc); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		if !oc.Verified || oc.Measurement != measHex {
			t.Errorf("unexpected outcome: %+v", oc)
		}
		// The security booleans must serialize even when false: a gate reading
		// an absent key cannot tell "reported false" from "never checked".
		var raw map[string]any
		if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"debug", "smt"} {
			v, present := raw[key]
			if !present {
				t.Errorf("json verdict omits %q — absent reads as false to a CI gate", key)
			} else if v != false {
				t.Errorf("json %q = %v, want false for these claims", key, v)
			}
		}
	})

	t.Run("debug/smt/report_data come from the verified claims", func(t *testing.T) {
		snpResult := &teetypes.VerificationResult{
			SignatureValid: true,
			Platform:       teetypes.PlatformSNP,
			Claims: teetypes.Claims{
				LaunchDigest: measHex,
				ReportData:   bytes.Repeat([]byte{0xAB}, 64),
				PlatformData: map[string]any{
					"policy":        map[string]any{"debug_allowed": true, "smt_allowed": true},
					"platform_info": map[string]any{"smt_enabled": false},
				},
			},
		}
		oc := newOutcome(config{}, ev, snpResult, nil, emptyPlan())
		if !oc.Debug {
			t.Error("SNP policy.debug_allowed=true must surface as debug=true")
		}
		if oc.SMT {
			t.Error("SMT must report platform_info.smt_enabled (false), not policy.smt_allowed")
		}
		if want := strings.Repeat("ab", 64); oc.ReportData != want {
			t.Errorf("report_data = %q, want the claims' report_data %q", oc.ReportData, want)
		}

		tdxResult := &teetypes.VerificationResult{
			SignatureValid: true,
			Platform:       teetypes.PlatformTDX,
			Claims: teetypes.Claims{
				LaunchDigest: measHex,
				PlatformData: map[string]any{
					"td_attributes_parsed": map[string]any{"debug": true},
				},
			},
		}
		oc = newOutcome(config{}, ev, tdxResult, nil, emptyPlan())
		if !oc.Debug || oc.SMT {
			t.Errorf("TDX td_attributes debug=true must surface as debug=true (smt unattested), got %+v", oc)
		}
	})

	t.Run("verdict error -> NOT VERIFIED", func(t *testing.T) {
		var out bytes.Buffer
		cfg := config{output: "text"}
		oc := newOutcome(cfg, ev, nil, &securityError{err: errors.New("rejected")}, emptyPlan())
		render(cfg, oc, &out)
		if oc.Verified || !strings.Contains(out.String(), "NOT VERIFIED") {
			t.Errorf("unexpected output: %s", out.String())
		}
	})

	t.Run("measurement not in allowlist -> not verified", func(t *testing.T) {
		// A genuine TEE whose launch digest isn't pinned must fail closed: the
		// allowlist is enforced here (the verifier has no --measurements input).
		other, err := refvalues.ParseHexMeasurementsList([]string{"00" + strings.Repeat("11", 47)})
		if err != nil {
			t.Fatal(err)
		}
		oc := newOutcome(config{}, ev, result, nil, &verifyPlan{policy: &ratls.VerifyPolicy{Policy: remote.Policy{Measurements: other}}})
		if oc.Verified || !strings.Contains(oc.Error, "not in --measurements allowlist") {
			t.Errorf("expected allowlist rejection, got %+v", oc)
		}
	})
}

func TestGatherFromFile_RejectsExpectedReportDataOnCert(t *testing.T) {
	// A certificate's binding is its key; an override would silently replace a
	// real binding while still reporting "binds the certificate public key".
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("does-not-matter")})
	if _, err := gatherFromFile(pemCert, make([]byte, 48), "file", leafTrust{}); err == nil {
		t.Fatal("expected --expected-report-data to be rejected for a certificate file")
	}
}

// A gather-time security failure is a verdict (exit 2), not an unavailability
// (exit 3). The exit codes are a CI contract: a gate that retries on 3 and
// pages on 2 must not quietly retry against an actively tampered certificate.
func TestRun_SecurityFailureDuringGatherExitsFailed(t *testing.T) {
	holder := testKey(t)
	forged := mintForgedIssuerLeaf(t, &holder.PublicKey, time.Now().Add(500000*time.Hour))
	path := filepath.Join(t.TempDir(), "leaf.pem")
	if err := os.WriteFile(path, certutil.EncodeCertPEM(forged.Raw), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := run(context.Background(), config{fromFile: path, output: "text"}, &out, &errOut)
	if code != exitFailed {
		t.Errorf("code = %d, want %d (evidence obtained, security check failed)", code, exitFailed)
	}
	if !strings.Contains(out.String(), "NOT VERIFIED") {
		t.Errorf("a security failure must render as a verdict, got:\n%s%s", out.String(), errOut.String())
	}
}

func TestRun_NoTarget(t *testing.T) {
	// No URL and no --from-file is a usage error.
	var out, errOut bytes.Buffer
	code := run(context.Background(), config{}, &out, &errOut)
	if code != exitUsage {
		t.Errorf("code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut.String(), "no target") {
		t.Errorf("missing 'no target' message: %s", errOut.String())
	}
}

// TestRunDiscoveryVerify_EndToEnd exercises run() through the discovery URL
// path: GET an unauthenticated discovery doc, then verify in-process. The stub
// evidence isn't a real SNP report, so verification fails closed — which proves
// the discovery → gather → verify → render → exit-code chain runs and the
// binding is extracted: a verification failure (exit 2), not a gather failure
// (exit 3).
func TestRunDiscoveryVerify_EndToEnd(t *testing.T) {
	certPEM, _ := selfSignedCertPEM(t)
	challenge := []byte("issuance-challenge")
	doc := discoveryDocWith(t, certPEM, challenge, `{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`)

	// The "router": serves the discovery doc unauthenticated at /v1/discovery.
	lb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != defaultDiscoveryPath {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Write(doc)
	}))
	defer lb.Close()

	var out, errOut bytes.Buffer
	code := run(context.Background(), config{
		url:    lb.URL,
		kind:   "lb",
		output: "text",
	}, &out, &errOut)
	output := out.String() + errOut.String()

	if code != exitFailed {
		t.Fatalf("code = %d, want %d (stub evidence must fail closed at verify, not gather); output:\n%s",
			code, exitFailed, output)
	}
	if !strings.Contains(out.String(), "NOT VERIFIED") {
		t.Errorf("expected NOT VERIFIED, got:\n%s", output)
	}
}

// TestResolveMode locks in kind→mode routing. The regression it guards: an
// explicit --kind must drive the evidence mode when --mode is left at its
// (auto) default, so `c8s cds verify --kind lb` resolves to discovery rather
// than dialing for the embedded RA-TLS extension the LB front door never
// serves. An explicit non-auto --mode always wins over kind.
func TestResolveMode(t *testing.T) {
	cases := []struct {
		name string
		kind string
		mode string
		want string
	}{
		{"lb kind, auto mode", "lb", "auto", "discovery"},
		{"lb kind, empty mode", "lb", "", "discovery"},
		{"cds kind, auto mode", "cds", "auto", "ratls-cert"},
		{"workload kind, auto mode", "workload", "auto", "ratls-cert"},
		{"auto kind, auto mode", "auto", "auto", "auto"},
		{"empty kind, empty mode", "", "", "auto"},
		{"explicit mode overrides lb kind", "lb", "ratls-cert", "ratls-cert"},
		{"explicit mode overrides cds kind", "cds", "attest-pq", "attest-pq"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveMode(config{kind: tc.kind, mode: tc.mode})
			if got != tc.want {
				t.Errorf("resolveMode(kind=%q, mode=%q) = %q, want %q", tc.kind, tc.mode, got, tc.want)
			}
		})
	}
}

func TestNewCmdDefaults(t *testing.T) {
	t.Run("generic", func(t *testing.T) {
		cmd := NewCmd(Defaults{})
		if cmd.Use != "verify [target]" {
			t.Errorf("Use = %q, want the generic default", cmd.Use)
		}
		if cmd.Short != "Verify a c8s component's TEE attestation" {
			t.Errorf("Short = %q, want the generic default", cmd.Short)
		}
		if !strings.HasPrefix(cmd.Long, cmd.Short+".") {
			t.Errorf("Long must open with Short, got %q...", cmd.Long[:60])
		}
		for flag, want := range map[string]string{
			"kind":    "auto",
			"mode":    "auto",
			"timeout": "15s",
		} {
			f := cmd.Flags().Lookup(flag)
			if f == nil || f.DefValue != want {
				t.Errorf("--%s default = %v, want %q", flag, f, want)
			}
		}
	})

	t.Run("preset", func(t *testing.T) {
		cmd := NewCmd(Defaults{Use: "verify", Short: "Verify the CDS", Kind: "cds", Mode: "ratls-cert"})
		if cmd.Use != "verify" || cmd.Short != "Verify the CDS" {
			t.Errorf("Use/Short = %q/%q, presets not applied", cmd.Use, cmd.Short)
		}
		if got := cmd.Flags().Lookup("kind").DefValue; got != "cds" {
			t.Errorf("--kind default = %q, want cds", got)
		}
		if got := cmd.Flags().Lookup("mode").DefValue; got != "ratls-cert" {
			t.Errorf("--mode default = %q, want ratls-cert", got)
		}
	})
}

func TestDefaultPort(t *testing.T) {
	cases := []struct {
		name string
		cfg  config
		want int
	}{
		{"preset wins over kind", config{defaults: Defaults{DefaultPort: 1234}, kind: "cds"}, 1234},
		{"cds", config{kind: "cds"}, 8443},
		{"lb", config{kind: "lb"}, 443},
		{"auto", config{}, 443},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultPort(tc.cfg); got != tc.want {
				t.Errorf("defaultPort = %d, want %d", got, tc.want)
			}
		})
	}
}

// The verifier-reported platform wins; the sent platform is only a fallback.
func TestNewOutcomePlatform(t *testing.T) {
	ev := &evidence{platform: "snp", source: "t", bindingNote: "b"}
	reported := &teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformType("az-snp")}
	if oc := newOutcome(config{}, ev, reported, nil, &verifyPlan{policy: &ratls.VerifyPolicy{}}); oc.Platform != "az-snp" {
		t.Errorf("Platform = %q, want the verifier-reported az-snp", oc.Platform)
	}
	unreported := &teetypes.VerificationResult{SignatureValid: true}
	if oc := newOutcome(config{}, ev, unreported, nil, &verifyPlan{policy: &ratls.VerifyPolicy{}}); oc.Platform != "snp" {
		t.Errorf("Platform = %q, want the fallback snp", oc.Platform)
	}
}

// A verifier verdict whose launch digest cannot be decoded must fail the
// --measurements pin closed: an unparseable digest can never count as allowed.
func TestNewOutcomeMalformedLaunchDigestFailsPin(t *testing.T) {
	ev := &evidence{platform: "snp", source: "t", bindingNote: "b"}
	plan := &verifyPlan{policy: &ratls.VerifyPolicy{Policy: remote.Policy{Measurements: [][]byte{bytes.Repeat([]byte{0xAB}, 48)}}}}
	for _, digest := range []string{"", "zz"} {
		result := &teetypes.VerificationResult{
			SignatureValid: true,
			Claims:         teetypes.Claims{LaunchDigest: digest},
		}
		oc := newOutcome(config{}, ev, result, nil, plan)
		if oc.Verified {
			t.Fatalf("launch digest %q verified despite being unenforceable", digest)
		}
		if !strings.Contains(oc.Error, "cannot enforce the measurement policy") {
			t.Fatalf("Error = %q, want the unenforceable-pin reason", oc.Error)
		}
	}
}

func TestFormatTCB(t *testing.T) {
	u8 := func(v uint8) *uint8 { return &v }
	cases := []struct {
		name string
		tcb  teetypes.TcbInfo
		want string
	}{
		{"snp all components", teetypes.TcbInfo{Type: "Snp", Bootloader: u8(1), Tee: u8(2), Snp: u8(3), Microcode: u8(4)}, "bootloader=1 tee=2 snp=3 microcode=4"},
		{"snp nil components render as zero", teetypes.TcbInfo{Type: "Snp"}, "bootloader=0 tee=0 snp=0 microcode=0"},
		{"snp with fmc", teetypes.TcbInfo{Type: "Snp", Bootloader: u8(1), Tee: u8(2), Snp: u8(3), Microcode: u8(4), FMC: u8(7)}, "bootloader=1 tee=2 snp=3 microcode=4 fmc=7"},
		{"tdx svn", teetypes.TcbInfo{Type: "Tdx", TCBSvn: []byte{0xAB, 0xCD}}, "svn=abcd"},
		{"tdx without svn", teetypes.TcbInfo{Type: "Tdx"}, ""},
		{"unknown type", teetypes.TcbInfo{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatTCB(tc.tcb); got != tc.want {
				t.Errorf("formatTCB = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRenderTextSections pins which optional sections the text verdict prints:
// each is emitted exactly when its datum is present.
func TestRenderTextSections(t *testing.T) {
	renderOut := func(oc Outcome) string {
		var out bytes.Buffer
		renderText(config{}, oc, &out)
		return out.String()
	}

	t.Run("all sections present", func(t *testing.T) {
		got := renderOut(Outcome{
			Verified:      true,
			Fresh:         true,
			Pinned:        true,
			CertSHA256:    "cert-digest-hex",
			SandboxID:     "sandbox-1",
			SandboxIDNote: "vouched by the mesh CA",
			OperatorKeys:  []string{"fp-one"},
		})
		for _, want := range []string{
			"cert sha256:  cert-digest-hex",
			"sandbox id:   sandbox-1",
			"vouched by the mesh CA",
			"operator keys (allowlist writes; CDS-reported config, NOT covered by the measurement):",
			"    sha256(SPKI DER):fp-one",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("output missing %q:\n%s", want, got)
			}
		}
	})

	t.Run("absent data prints nothing", func(t *testing.T) {
		got := renderOut(Outcome{Verified: true, Fresh: true, Pinned: true, OperatorKeysNote: "note-xyz"})
		if !strings.Contains(got, "operator keys: note-xyz") {
			t.Errorf("note not printed when no keys were fetched:\n%s", got)
		}
		for _, absent := range []string{
			"cert sha256",
			"sandbox id",
			"allowlist writes",
		} {
			if strings.Contains(got, absent) {
				t.Errorf("output has %q without the datum:\n%s", absent, got)
			}
		}
	})

	// The fingerprint list alone is identical whether or not --operator-keys was
	// supplied, so the verdict must be rendered beneath it — not dropped, as it
	// was when the note only ever printed for an empty list.
	t.Run("operator-keys verdict renders under the fingerprints", func(t *testing.T) {
		got := renderOut(Outcome{
			Verified:         true,
			Fresh:            true,
			Pinned:           true,
			OperatorKeys:     []string{"fp-one", "fp-two"},
			OperatorKeysNote: "matched: the set served over the attested cert equals --operator-keys",
		})
		want := "    sha256(SPKI DER):fp-one\n    sha256(SPKI DER):fp-two\n    matched: the set served over the attested cert equals --operator-keys\n"
		if !strings.Contains(got, want) {
			t.Errorf("verdict not rendered under the fingerprint list, want\n%s\ngot\n%s", want, got)
		}
	})

	t.Run("workload section carries the stamp and its provenance note", func(t *testing.T) {
		got := renderOut(Outcome{
			Verified:                 true,
			Fresh:                    true,
			Pinned:                   true,
			Workload:                 "web",
			WorkloadAllowlistVersion: "7",
			WorkloadAllowlistDigest:  "abcd",
			WorkloadNote:             "workload_verified: pinned policy satisfied",
		})
		for _, want := range []string{
			"workload:     web  (allowlist version 7, digest abcd)",
			"workload_verified: pinned policy satisfied",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("output missing %q:\n%s", want, got)
			}
		}
	})

	t.Run("non-fresh and unpinned verdicts carry their warnings", func(t *testing.T) {
		got := renderOut(Outcome{Verified: true})
		if !strings.Contains(got, "freshness NOT proven") {
			t.Errorf("missing the non-freshness note:\n%s", got)
		}
		if !strings.Contains(got, "no --measurements pinned") {
			t.Errorf("missing the unpinned warning:\n%s", got)
		}
	})

	// The security section is only truthful if it comes from the verified
	// claims: drive it through newOutcome with a debug=true SNP report.
	t.Run("show-evidence prints the claims' security state", func(t *testing.T) {
		ev := &evidence{platform: "snp", source: "test", bindingNote: "test binding", fresh: true}
		result := &teetypes.VerificationResult{
			SignatureValid: true,
			Platform:       teetypes.PlatformSNP,
			Claims: teetypes.Claims{
				LaunchDigest: "ab" + strings.Repeat("00", 47),
				ReportData:   bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 16),
				PlatformData: map[string]any{
					"policy":        map[string]any{"debug_allowed": true, "smt_allowed": true},
					"platform_info": map[string]any{"smt_enabled": true},
				},
			},
		}
		oc := newOutcome(config{}, ev, result, nil, &verifyPlan{policy: &ratls.VerifyPolicy{}})
		if !oc.Verified || !oc.Debug || !oc.SMT {
			t.Fatalf("newOutcome = %+v, want verified with debug=true smt=true", oc)
		}
		var out bytes.Buffer
		renderText(config{showEvidence: true}, oc, &out)
		got := out.String()
		if !strings.Contains(got, "report_data:  "+strings.Repeat("deadbeef", 16)) {
			t.Errorf("missing the claims' report_data with --show-evidence:\n%s", got)
		}
		if !strings.Contains(got, "debug=true smt=true") {
			t.Errorf("debug/smt state not rendered from the claims:\n%s", got)
		}
	})
}

// TestGatherEvidence_AutoPrefersDiscovery proves auto mode (no --kind) detects
// an LB by fetching its discovery doc first — the bare `c8s verify <lb>` path.
func TestGatherEvidence_AutoPrefersDiscovery(t *testing.T) {
	certPEM, _ := selfSignedCertPEM(t)
	doc := discoveryDocWith(t, certPEM, []byte("challenge"), `{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`)
	lb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != defaultDiscoveryPath {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Write(doc)
	}))
	defer lb.Close()

	ev, err := gatherEvidence(context.Background(), config{url: lb.URL, kind: "auto"}, &verifyPlan{policy: &ratls.VerifyPolicy{}}, nil)
	if err != nil {
		t.Fatalf("auto mode should reach the discovery doc, got: %v", err)
	}
	if !strings.Contains(ev.source, "discovery document") {
		t.Errorf("source = %q, want the discovery-doc path", ev.source)
	}
}

// TestGatherEvidence_AutoFallsBackToServingCert proves auto mode falls through
// to the RA-TLS serving cert when discovery is absent (a non-LB TLS endpoint):
// the surfaced error is the cert-path verdict, not the discovery 404.
func TestGatherEvidence_AutoFallsBackToServingCert(t *testing.T) {
	// 404s every path (no /v1/discovery) and presents httptest's plain serving
	// cert, which carries no RA-TLS extension.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := gatherEvidence(context.Background(), config{url: srv.URL, kind: "auto"}, &verifyPlan{policy: &ratls.VerifyPolicy{}}, nil)
	if !errors.Is(err, ratls.ErrNoAttestation) {
		t.Fatalf("want fall-through to the serving-cert path (ErrNoAttestation), got: %v", err)
	}
}

func TestNormalizeTarget_Errors(t *testing.T) {
	if _, _, err := normalizeTarget("https://\x7f", 443); err == nil {
		t.Error("control character URL should fail to parse")
	}
	if _, _, err := normalizeTarget("https:///path-only", 443); err == nil {
		t.Error("URL without a host should be rejected")
	}
}

func TestMinTCBFromCfg(t *testing.T) {
	if got := minTCBFromCfg(config{}); got != nil {
		t.Errorf("all-zero flags should yield nil, got %+v", got)
	}
	got := minTCBFromCfg(config{minTCBBootloader: 1, minTCBTEE: 2, minTCBSNP: 3, minTCBMicrocode: 4})
	if got == nil || got.Bootloader != 1 || got.Tee != 2 || got.Snp != 3 || got.Microcode != 4 {
		t.Errorf("minTCBFromCfg = %+v, want 1/2/3/4", got)
	}
}

func TestBuildPolicy_FileInputs(t *testing.T) {
	dir := t.TempDir()
	measHex := strings.Repeat("ab", 48)

	t.Run("measurements file", func(t *testing.T) {
		path := filepath.Join(dir, "measurements.txt")
		if err := os.WriteFile(path, []byte(measHex+"\n\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		plan, err := buildPolicy(config{measurementsFile: path})
		if err != nil {
			t.Fatalf("buildPolicy: %v", err)
		}
		if len(plan.policy.Policy.Measurements) != 1 || hex.EncodeToString(plan.policy.Policy.Measurements[0]) != measHex {
			t.Errorf("measurements = %v", plan.policy.Policy.Measurements)
		}
	})

	t.Run("measurements file missing", func(t *testing.T) {
		if _, err := buildPolicy(config{measurementsFile: filepath.Join(dir, "absent")}); err == nil {
			t.Error("missing --measurements-file must fail")
		}
	})

	t.Run("bad measurement hex", func(t *testing.T) {
		if _, err := buildPolicy(config{measurements: []string{"zz"}}); err == nil {
			t.Error("non-hex measurement must fail")
		}
	})

	t.Run("operator keys PEM", func(t *testing.T) {
		pubPEM, _ := operatorPubPEM(t)
		path := filepath.Join(dir, "op.pub")
		if err := os.WriteFile(path, pubPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := buildPolicy(config{operatorKeys: path}); err != nil {
			t.Fatalf("buildPolicy: %v", err)
		}
		digest, err := expectedOperatorKeysDigest(config{operatorKeys: path})
		if err != nil {
			t.Fatalf("expectedOperatorKeysDigest: %v", err)
		}
		if len(digest) == 0 {
			t.Error("expected digest not derived from --operator-keys")
		}
	})

	t.Run("operator keys missing file", func(t *testing.T) {
		if _, err := buildPolicy(config{operatorKeys: filepath.Join(dir, "absent")}); err == nil {
			t.Error("missing --operator-keys must fail")
		}
	})

	t.Run("operator keys bad PEM", func(t *testing.T) {
		path := filepath.Join(dir, "bad.pub")
		if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := buildPolicy(config{operatorKeys: path}); err == nil {
			t.Error("unparseable --operator-keys must fail")
		}
	})

}

func TestGatherEvidence_ModesAndErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("ratls-cert mode", func(t *testing.T) {
		srv := attestedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		ev, err := gatherEvidence(ctx, config{url: srv.URL, mode: "ratls-cert", timeout: 5 * time.Second}, &verifyPlan{policy: &ratls.VerifyPolicy{}}, nil)
		if err != nil {
			t.Fatalf("ratls-cert mode: %v", err)
		}
		if !strings.Contains(ev.source, "RA-TLS serving certificate") {
			t.Errorf("source = %q, want the cert path", ev.source)
		}
	})

	t.Run("attest-pq mode", func(t *testing.T) {
		report := bytes.Repeat([]byte{0x01}, 64)
		id := mintEndpointIdentity(t)
		// attestPQHandler 404s every other path: the path is the binding
		// selector now, so the retired ?pq=/?binding= query form must not be
		// what routes this.
		srv := httptest.NewTLSServer(attestPQHandler(t, id, report))
		defer srv.Close()
		ev, err := gatherEvidence(ctx, config{url: srv.URL, mode: "attest-pq", timeout: 5 * time.Second}, &verifyPlan{policy: &ratls.VerifyPolicy{}}, nil)
		if err != nil {
			t.Fatalf("attest-pq mode: %v", err)
		}
		if !ev.fresh {
			t.Error("endpoint evidence should be fresh")
		}
	})

	t.Run("no target at all is an error", func(t *testing.T) {
		if _, err := gatherEvidence(ctx, config{}, &verifyPlan{policy: &ratls.VerifyPolicy{}}, nil); err == nil || !strings.Contains(err.Error(), "no target") {
			t.Fatalf("err = %v, want the no-target refusal", err)
		}
	})

	t.Run("unparseable target is an error", func(t *testing.T) {
		if _, err := gatherEvidence(ctx, config{url: "https://\x7f"}, &verifyPlan{policy: &ratls.VerifyPolicy{}}, nil); err == nil {
			t.Fatal("control-character target should fail to normalize")
		}
	})

	t.Run("attest-pq mode surfaces a dial failure as a connect error", func(t *testing.T) {
		// Port 1 refuses fast: an unreachable endpoint is exit-3 territory, not
		// a verification verdict.
		_, err := gatherEvidence(ctx, config{url: "https://127.0.0.1:1", mode: "attest-pq", timeout: 2 * time.Second}, &verifyPlan{policy: &ratls.VerifyPolicy{}}, nil)
		if err == nil || !isConnectError(err) {
			t.Fatalf("err = %v, want a connectError", err)
		}
	})

	t.Run("auto falls through to the cert path on discovery parse failure", func(t *testing.T) {
		// auto tries discovery first; serve a discovery doc that is not JSON so
		// parsing fails. That failure is not a security error, so auto must fall
		// through to the cert path (which then errors on the self-signed test
		// cert) rather than aborting with a security verdict.
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("not json"))
		}))
		defer srv.Close()
		_, err := gatherEvidence(ctx, config{url: srv.URL, kind: "auto", timeout: 5 * time.Second}, &verifyPlan{policy: &ratls.VerifyPolicy{}}, nil)
		if err == nil || isSecurityError(err) {
			t.Fatalf("parse failure should fall through to the cert path, got %v", err)
		}
	})
}

func TestRun_UsageAndGatherFailures(t *testing.T) {
	t.Run("retired attestation-endpoint mode is a usage error, not an alias", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := run(context.Background(), config{url: "x", mode: "attestation-endpoint"}, &out, &errOut)
		if code != exitUsage || !strings.Contains(errOut.String(), "attest-pq") {
			t.Errorf("code = %d, want %d with the valid mode list; stderr: %s", code, exitUsage, errOut.String())
		}
	})

	t.Run("unknown mode is a usage error", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), config{url: "x", mode: "bogus"}, &out, &errOut); code != exitUsage {
			t.Errorf("code = %d, want %d; stderr: %s", code, exitUsage, errOut.String())
		}
	})

	t.Run("policy error", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), config{minTCBSNP: 256, url: "x"}, &out, &errOut); code != exitUsage {
			t.Errorf("code = %d, want %d; stderr: %s", code, exitUsage, errOut.String())
		}
	})

	t.Run("bad expected-report-data", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := run(context.Background(), config{fromFile: "whatever", expectedRDHex: "zz"}, &out, &errOut)
		if code != exitUsage || !strings.Contains(errOut.String(), "expected-report-data") {
			t.Errorf("code = %d, stderr: %s", code, errOut.String())
		}
	})

	t.Run("missing from-file exits no-evidence", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := run(context.Background(), config{fromFile: filepath.Join(t.TempDir(), "absent")}, &out, &errOut)
		if code != exitNoEvidence || !strings.Contains(errOut.String(), "could not obtain evidence") {
			t.Errorf("code = %d, stderr: %s", code, errOut.String())
		}
	})

	t.Run("unreadable allowlist file is a usage error", func(t *testing.T) {
		meshCA := writeMeshCAFile(t)
		var out, errOut bytes.Buffer
		code := run(context.Background(), config{
			url:           "x",
			meshCA:        meshCA,
			allowlistFile: filepath.Join(t.TempDir(), "absent"),
		}, &out, &errOut)
		if code != exitUsage || !strings.Contains(errOut.String(), "--allowlist") {
			t.Errorf("code = %d, want %d with an --allowlist error; stderr: %s", code, exitUsage, errOut.String())
		}
	})
}
