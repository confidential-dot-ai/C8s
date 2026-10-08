package cdsattest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// capturingProvider records the report_data it was asked to bind, so a test can
// assert what the server committed to the hardware report.
type capturingProvider struct {
	lastReportData []byte
}

func (p *capturingProvider) Evidence(_ context.Context, reportData []byte) (json.RawMessage, string, string, error) {
	p.lastReportData = append([]byte(nil), reportData...)
	return json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`), "snp", "genoa", nil
}

// writeTestServingLeaf writes a self-signed leaf PEM to a temp file and
// returns the path plus the cert's exact DER.
func writeTestServingLeaf(t *testing.T) (path string, der []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "c8s-router.c8s-system.svc"},
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "cert.pem")
	writeTestPEM(t, path, "CERTIFICATE", der)
	return path, der
}

func newAttestLBServer(t *testing.T, identity testMeshIdentity, servingCertFile string) (*httptest.Server, *capturingProvider) {
	t.Helper()
	prov := &capturingProvider{}
	srv := NewServer(Config{
		Evidence:             prov,
		FrontDoorMode:        types.FrontDoorModeCDS,
		ServingCertFile:      servingCertFile,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, prov
}

func TestAttestLBBindsServingLeafAndMeshIdentity(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	certPath, servingDER := writeTestServingLeaf(t)
	ts, prov := newAttestLBServer(t, identity, certPath)

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
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, body)
	}
	var b types.AttestationBundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}

	if b.Version != types.BindingAttestLB {
		t.Errorf("version = %q, want %q", b.Version, types.BindingAttestLB)
	}
	if b.XWingCT != "" || b.SessionID != "" {
		t.Errorf("attest-lb must mint no session, got ct %q id %q", b.XWingCT, b.SessionID)
	}
	if b.Nonce != b64url(nonce) {
		t.Errorf("nonce not echoed: got %q", b.Nonce)
	}
	servingHash := sha256.Sum256(servingDER)
	if b.ServingLeafSHA256 != b64url(servingHash[:]) {
		t.Errorf("serving_leaf_sha256 = %q, want hash of the served leaf", b.ServingLeafSHA256)
	}

	// Recompute the transcript the way a client does — from the leaf observed
	// on the connection plus the served mesh chain — and require the hardware
	// report_data and the ECDSA proof to verify against it.
	if b.FrontDoorMode != types.FrontDoorModeCDS {
		t.Errorf("front_door_mode = %q, want %q", b.FrontDoorMode, types.FrontDoorModeCDS)
	}
	want, err := overenc.LBTranscriptHash(b.FrontDoorMode, nonce, servingDER, identity.leaf.Raw, identity.ca.Raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prov.lastReportData, want) {
		t.Fatalf("report_data = %x, want lb transcript %x", prov.lastReportData, want)
	}
	if b.IdentityProof == nil {
		t.Fatal("bundle carries no identity proof")
	}
	leafHash := sha256.Sum256(identity.leaf.Raw)
	caHash := sha256.Sum256(identity.ca.Raw)
	if b.IdentityProof.LeafSHA256 != b64url(leafHash[:]) || b.IdentityProof.MeshCASHA256 != b64url(caHash[:]) {
		t.Fatalf("identity fingerprints do not match committed certificates: %+v", b.IdentityProof)
	}
	signature, err := base64.RawURLEncoding.DecodeString(b.IdentityProof.Signature)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384(want)
	if !ecdsa.VerifyASN1(&identity.key.PublicKey, digest[:], signature) {
		t.Fatal("mesh identity proof signature did not verify over the lb transcript")
	}
	if !strings.Contains(b.CDSCertPEM, "CERTIFICATE") {
		t.Fatalf("bundle carries no mesh chain: %q", b.CDSCertPEM)
	}
}

// A pq-transcript signature must never verify against the lb transcript for
// the same nonce and identity: the domain tags separate the two endpoints.
func TestAttestLBTranscriptDiffersFromPQ(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	_, servingDER := writeTestServingLeaf(t)
	nonce := make([]byte, 32)
	pq, err := overenc.IdentityTranscriptHash(types.FrontDoorModeCDS,
		make([]byte, overenc.XWingEKBytes), make([]byte, overenc.XWingCTBytes),
		make([]byte, overenc.SessionIDBytes), nonce, identity.leaf.Raw, identity.ca.Raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := overenc.LBTranscriptHash(types.FrontDoorModeCDS, nonce, servingDER, identity.leaf.Raw, identity.ca.Raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pq, lb) {
		t.Fatal("pq and lb transcripts collide")
	}
}

func TestAttestLBRefusedOnWebPKIFrontDoor(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	certPath, _ := writeTestServingLeaf(t)
	srv := NewServer(Config{
		Evidence:             &capturingProvider{},
		FrontDoorMode:        types.FrontDoorModeWebPKI,
		ServingCertFile:      certPath,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/c8s/attest-lb?nonce=" + b64url(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		resp.Body.Close()
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if e := decodeErr(t, resp); e.Error != types.ErrorCodeExternalTLS {
		t.Fatalf("error code = %q, want %q", e.Error, types.ErrorCodeExternalTLS)
	}

	// attest-pq stays available on the same front door.
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
	pqResp := postAttestPQ(t, ts.URL, body)
	pqResp.Body.Close()
	if pqResp.StatusCode != http.StatusOK {
		t.Fatalf("attest-pq on a webpki front door: status = %d, want 200", pqResp.StatusCode)
	}
}

func TestAttestLBMissingServingCertFailsClosed(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	// No ServingCertFile: attest-lb must fail closed rather than silently
	// bind something else.
	ts, _ := newAttestLBServer(t, identity, "")

	resp, err := http.Get(ts.URL + "/.well-known/c8s/attest-lb?nonce=" + b64url(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		resp.Body.Close()
		t.Fatalf("status = %d, want 503 when serving cert is not configured", resp.StatusCode)
	}
	if e := decodeErr(t, resp); e.Error != types.ErrorCodeBindingUnavailable {
		t.Fatalf("error code = %q, want %q", e.Error, types.ErrorCodeBindingUnavailable)
	}
}

func TestAttestLBMeshIdentityUnavailableFailsClosed(t *testing.T) {
	// The serving leaf alone is not enough: without a loadable mesh identity
	// there is nothing to sign the transcript, so the endpoint must 503 rather
	// than serve an unsigned binding.
	identity := writeTestMeshIdentity(t)
	certPath, _ := writeTestServingLeaf(t)
	if err := os.Remove(identity.certFile); err != nil {
		t.Fatal(err)
	}
	ts, _ := newAttestLBServer(t, identity, certPath)

	resp, err := http.Get(ts.URL + "/.well-known/c8s/attest-lb?nonce=" + b64url(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		resp.Body.Close()
		t.Fatalf("status = %d, want 503 when the mesh identity cannot load", resp.StatusCode)
	}
	if e := decodeErr(t, resp); e.Error != types.ErrorCodeBindingUnavailable {
		t.Fatalf("error code = %q, want %q", e.Error, types.ErrorCodeBindingUnavailable)
	}
}

func TestAttestLBWrongSizeNonce(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	certPath, _ := writeTestServingLeaf(t)
	ts, _ := newAttestLBServer(t, identity, certPath)
	for _, size := range []int{16, 31, 33} {
		resp, err := http.Get(ts.URL + "/.well-known/c8s/attest-lb?nonce=" + b64url(make([]byte, size)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%d-byte nonce status = %d, want 400", size, resp.StatusCode)
		}
	}
}

// matchedWorkloadExtension builds a matched-workload stamp for name with the
// same marshal helper CDS issuance uses.
func matchedWorkloadExtension(t *testing.T, name string) pkix.Extension {
	t.Helper()
	ext, err := ratls.MarshalMatchedWorkloadExtension(&ratls.MatchedWorkload{
		Name:             name,
		AllowlistVersion: "7",
		AllowlistDigest:  bytes.Repeat([]byte{0x42}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	return ext
}

// writeStampedMeshIdentity mints a mesh identity whose leaf carries a
// matched-workload stamp for name.
func writeStampedMeshIdentity(t *testing.T, name string) testMeshIdentity {
	t.Helper()
	return writeTestMeshIdentityWithLeafExtensions(t, matchedWorkloadExtension(t, name))
}

// pkixExtensionWithGarbage returns a matched-workload extension whose value
// is not valid DER, to exercise the fail-closed readyz path.
func pkixExtensionWithGarbage() pkix.Extension {
	return pkix.Extension{Id: ratls.OIDMatchedWorkload, Value: []byte{0x30, 0x01}}
}

func getReadyz(t *testing.T, base string) (int, string) {
	t.Helper()
	resp, err := http.Get(base + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestReadyzGatesOnMatchedWorkloadStamp(t *testing.T) {
	newReadyzServer := func(t *testing.T, identity testMeshIdentity, expected string) *httptest.Server {
		t.Helper()
		srv := NewServer(Config{
			Evidence:             &capturingProvider{},
			MeshIdentityCertFile: identity.certFile,
			MeshIdentityKeyFile:  identity.keyFile,
			MeshIdentityCAFile:   identity.caFile,
			ExpectedWorkload:     expected,
		})
		ts := httptest.NewServer(srv.Handler())
		t.Cleanup(ts.Close)
		return ts
	}

	t.Run("no expected workload keeps always-ready", func(t *testing.T) {
		ts := newReadyzServer(t, writeTestMeshIdentity(t), "")
		if status, _ := getReadyz(t, ts.URL); status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
	})

	t.Run("unnamed leaf is not ready", func(t *testing.T) {
		ts := newReadyzServer(t, writeTestMeshIdentity(t), "web")
		status, body := getReadyz(t, ts.URL)
		if status != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", status)
		}
		if !strings.Contains(body, "no matched-workload stamp") {
			t.Fatalf("body = %q, want an unnamed-leaf reason", body)
		}
	})

	t.Run("wrong name is not ready without naming either workload", func(t *testing.T) {
		// nginx proxies /readyz from the public front door, so the body must
		// not disclose the configured or the stamped workload name.
		ts := newReadyzServer(t, writeStampedMeshIdentity(t, "other"), "web")
		status, body := getReadyz(t, ts.URL)
		if status != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", status)
		}
		if !strings.Contains(body, "stamped for a different workload") {
			t.Fatalf("body = %q, want a name-mismatch reason", body)
		}
		if strings.Contains(body, "other") || strings.Contains(body, "web") {
			t.Fatalf("body = %q leaks a workload name", body)
		}
	})

	t.Run("matching stamped leaf is ready", func(t *testing.T) {
		ts := newReadyzServer(t, writeStampedMeshIdentity(t, "web"), "web")
		if status, body := getReadyz(t, ts.URL); status != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", status, body)
		}
	})

	t.Run("malformed stamp fails closed", func(t *testing.T) {
		// A damaged extension must read as not-ready, never as absence.
		ext := pkixExtensionWithGarbage()
		ts := newReadyzServer(t, writeTestMeshIdentityWithLeafExtensions(t, ext), "web")
		status, body := getReadyz(t, ts.URL)
		if status != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", status)
		}
		if !strings.Contains(body, "malformed") {
			t.Fatalf("body = %q, want a malformed-stamp reason", body)
		}
	})

	t.Run("unreadable mesh leaf fails closed", func(t *testing.T) {
		identity := writeTestMeshIdentity(t)
		if err := os.Remove(identity.certFile); err != nil {
			t.Fatal(err)
		}
		ts := newReadyzServer(t, identity, "web")
		if status, _ := getReadyz(t, ts.URL); status != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", status)
		}
	})

	// The gate must agree with the endpoints it fronts: a correctly stamped
	// leaf that loadMeshIdentity refuses is not a servable front door, and
	// reporting it ready routes traffic to a 503-ing attest-pq. The expiry case
	// is the one that happens on its own — stamped leaves carry a short TTL
	// (issuer.MaxNamedLeafTTL) and a stalled renewal walks straight into it.
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T) testMeshIdentity
	}{
		{
			name: "expired stamped leaf",
			mutate: func(t *testing.T) testMeshIdentity {
				now := time.Now()
				return writeTestMeshIdentityFull(t, now.Add(-2*time.Hour), now.Add(-time.Hour),
					[]pkix.Extension{matchedWorkloadExtension(t, "web")})
			},
		},
		{
			name: "stamped leaf whose private key does not match",
			mutate: func(t *testing.T) testMeshIdentity {
				identity := writeStampedMeshIdentity(t, "web")
				other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				otherDER, err := x509.MarshalECPrivateKey(other)
				if err != nil {
					t.Fatal(err)
				}
				writeTestPEM(t, identity.keyFile, "EC PRIVATE KEY", otherDER)
				return identity
			},
		},
		{
			name: "stamped leaf under a foreign CA bundle",
			mutate: func(t *testing.T) testMeshIdentity {
				identity := writeStampedMeshIdentity(t, "web")
				foreign := writeTestMeshIdentity(t)
				writeTestPEM(t, identity.caFile, "CERTIFICATE", foreign.ca.Raw)
				return identity
			},
		},
	} {
		t.Run(tc.name+" is not ready", func(t *testing.T) {
			ts := newReadyzServer(t, tc.mutate(t), "web")
			status, body := getReadyz(t, ts.URL)
			if status != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503: %s", status, body)
			}
			if !strings.Contains(body, "unusable") {
				t.Fatalf("body = %q, want an unusable-credential reason", body)
			}
		})
	}
}
