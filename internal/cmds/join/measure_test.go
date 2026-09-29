package join

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

var (
	digestA      = strings.Repeat("ad", 48)
	digestB      = strings.Repeat("bd", 48)
	rtmr1A       = strings.Repeat("a1", 48)
	rtmr2A       = strings.Repeat("a2", 48)
	rtmr1B       = strings.Repeat("b1", 48)
	testOperator = []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaaBz1ISIaMWDuPRjgg152EBIYRab\nILbNz0VOO47mubLnNsK8igqlET/44vuAzyC+Zw4aha2ag3HgzfBWZxbuog==\n-----END PUBLIC KEY-----\n")
	testCA       = "K10" + strings.Repeat("ca", 32)
	testToken    = testCA + "::node:agent-secret"
)

const tdxEnvelope = `{"platform":"tdx","evidence":{"quote":"ZmFrZS1xdW90ZQ=="}}`

// The service is the verification trust boundary. Fake evidence is deliberately
// unsigned; these tests exercise the caller's enforcement of service verdicts,
// expected key bindings, and image/operator tuples, not hardware verification.
type fakeAPI struct {
	URL         string
	platform    teetypes.PlatformType
	verifyCalls atomic.Int32
}

func newFakeAPI(t *testing.T, verifyFn func(int, remote.VerifyRequest) remote.VerifyResponse) *fakeAPI {
	t.Helper()
	f := &fakeAPI{platform: teetypes.PlatformTDX}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/attest":
			var req remote.AttestRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
				http.Error(w, "decode", 400)
				return
			}
			evidence := mockapi.FakeSNPEvidence(req.ReportData)
			if f.platform == teetypes.PlatformTDX {
				evidence, _ = json.Marshal(map[string]string{"quote": base64.StdEncoding.EncodeToString(req.ReportData)})
			}
			_ = json.NewEncoder(w).Encode(remote.AttestResponse{Platform: f.platform, Evidence: evidence})
		case "/verify":
			var req remote.VerifyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
				http.Error(w, "decode", 400)
				return
			}
			_ = json.NewEncoder(w).Encode(verifyFn(int(f.verifyCalls.Add(1)), req))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	f.URL = srv.URL
	return f
}
func verifyResp(platform teetypes.PlatformType, key []byte) remote.VerifyResponse {
	v := mockapi.PassingVerdict(digestA)
	v.Claims.PlatformData = map[string]any{"rtmr_1": rtmr1A, "rtmr_2": rtmr2A}
	if platform == teetypes.PlatformTDX {
		seed := runtimemeasure.Seed(key)
		v.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(seed[:])
	} else {
		hd := runtimemeasure.HostData(key)
		v.Claims.InitData = hd[:]
	}
	return remote.VerifyResponse{Result: teetypes.VerificationResult{Platform: platform, SignatureValid: true, ReportDataMatch: teetypes.Ptr(true), Claims: v.Claims}}
}
func staticVerify(resp remote.VerifyResponse) func(int, remote.VerifyRequest) remote.VerifyResponse {
	return func(int, remote.VerifyRequest) remote.VerifyResponse { return resp }
}
func operatorKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
func policyEntry(t *testing.T, platform teetypes.PlatformType, key []byte) remote.ImagePin {
	t.Helper()
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	e := remote.ImagePin{Name: "authorized", Digest: decode(digestA), Anchor: key}
	if platform == teetypes.PlatformTDX {
		e.Registers = map[int][]byte{1: decode(rtmr1A), 2: decode(rtmr2A)}
	}
	return e
}
func policyFile(t *testing.T, platform teetypes.PlatformType, entries ...remote.ImagePin) string {
	t.Helper()
	data, err := refvalues.Format(refvalues.ReferenceValues{Family: platform.Family(), Images: entries})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func testPolicy(t *testing.T, platform teetypes.PlatformType, key []byte, url string) peerPolicy {
	t.Helper()
	p, err := loadPeerPolicy(policyFile(t, platform, policyEntry(t, platform, key)), string(platform), url, 5*time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func attestedLeaf(t *testing.T, envelope string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := ratls.CreateAttestedCert(key, &ratls.Attestation{Family: ratls.TEETypeTDX, Report: []byte(envelope)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
func leafForPlatform(t *testing.T, p teetypes.PlatformType) *x509.Certificate {
	t.Helper()
	if p == teetypes.PlatformTDX {
		return attestedLeaf(t, tdxEnvelope)
	}
	key, rd, err := ratls.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	der, err := ratls.CreateAttestedCert(key, &ratls.Attestation{Family: ratls.TEETypeSEVSNP, Report: mockapi.FakeSNPReport(rd[:])}, nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}
func selfSigned(t *testing.T, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
func plainLeaf(t *testing.T) *x509.Certificate {
	return selfSigned(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "plain"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)})
}
func TestLoadPeerPolicy(t *testing.T) {
	key := operatorKey(t)
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformTDX, teetypes.PlatformSNP} {
		t.Run(string(platform), func(t *testing.T) {
			valid := policyEntry(t, platform, key)
			for _, tc := range []struct {
				name          string
				edit          func(*remote.ImagePin)
				otherPlatform string
				server        bool
				second        bool
			}{
				{name: "image only", edit: func(e *remote.ImagePin) { e.Anchor = nil }},
				{name: "wrong family", otherPlatform: map[teetypes.PlatformType]string{teetypes.PlatformTDX: "snp", teetypes.PlatformSNP: "tdx"}[platform]},
				{name: "multiple servers", server: true, second: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					e := valid
					if tc.edit != nil {
						tc.edit(&e)
					}
					entries := []remote.ImagePin{e}
					if tc.second {
						e.Name = "second"
						e.Anchor = operatorKey(t)
						entries = append(entries, e)
					}
					p := string(platform)
					if tc.otherPlatform != "" {
						p = tc.otherPlatform
					}
					if _, err := loadPeerPolicy(policyFile(t, platform, entries...), p, "http://127.0.0.1:1", time.Second, tc.server); err == nil {
						t.Fatal("unsafe policy accepted")
					}
				})
			}
		})
	}
	for _, raw := range []string{`{"schema_version":"1","tee":"tdx","measurements":[]}`, `{}`} {
		p := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPeerPolicy(p, "tdx", "", time.Second, false); err == nil {
			t.Fatal("empty policy accepted")
		}
	}
	if _, err := loadPeerPolicy("", "tdx", "", time.Second, false); err == nil {
		t.Fatal("missing policy accepted")
	}
	for _, idx := range []int{1, 2} {
		e := policyEntry(t, teetypes.PlatformTDX, key)
		delete(e.Registers, idx)
		if _, err := loadPeerPolicy(policyFile(t, teetypes.PlatformTDX, e), "tdx", "", time.Second, false); err == nil {
			t.Fatalf("missing RTMR[%d] accepted", idx)
		}
	}
}
func TestVerifyPeerIdentity(t *testing.T) {
	key, other := operatorKey(t), operatorKey(t)
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformTDX, teetypes.PlatformSNP} {
		t.Run(string(platform), func(t *testing.T) {
			leaf := leafForPlatform(t, platform)
			wantRD, err := ratls.ReportDataForKey(leaf.PublicKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				name   string
				change func(*remote.VerifyResponse)
				want   error
			}{
				{name: "authorized"},
				{"wrong image", func(r *remote.VerifyResponse) { r.Result.Claims.LaunchDigest = digestB }, ratls.ErrPolicyViolation},
				{"same image wrong operator", func(r *remote.VerifyResponse) { *r = verifyResp(platform, other) }, ratls.ErrPolicyViolation},
				{"missing operator", func(r *remote.VerifyResponse) {
					r.Result.Claims.InitData = nil
					delete(r.Result.Claims.PlatformData, "rtmr_3")
				}, ratls.ErrPolicyViolation},
				{"replayed evidence wrong key", func(r *remote.VerifyResponse) { r.Result.ReportDataMatch = teetypes.Ptr(false) }, ratls.ErrKeyBinding},
				{"signature invalid", func(r *remote.VerifyResponse) { r.Result.SignatureValid = false }, ratls.ErrSignatureInvalid},
				{"verified family mismatch", func(r *remote.VerifyResponse) { r.Result.Platform = "unexpected" }, remote.ErrPlatformMismatch},
			} {
				t.Run(tc.name, func(t *testing.T) {
					resp := verifyResp(platform, key)
					if tc.change != nil {
						tc.change(&resp)
					}
					api := newFakeAPI(t, func(_ int, req remote.VerifyRequest) remote.VerifyResponse {
						if req.Params == nil || !bytes.Equal(req.Params.ExpectedReportData, wantRD[:48]) {
							t.Error("peer verification not anchored to leaf key")
						}
						return resp
					})
					err := verifyPeer(context.Background(), leaf, testPolicy(t, platform, key, api.URL))
					if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
						t.Fatalf("err=%v want=%v", err, tc.want)
					}
				})
			}
			wrongFamily := teetypes.PlatformSNP
			if platform == teetypes.PlatformSNP {
				wrongFamily = teetypes.PlatformTDX
			}
			if err := verifyPeer(context.Background(), leafForPlatform(t, wrongFamily), testPolicy(t, platform, key, "http://127.0.0.1:1")); !errors.Is(err, ratls.ErrPolicyViolation) {
				t.Fatalf("wrong TEE accepted: %v", err)
			}
		})
	}
	for _, register := range []string{"rtmr_1", "rtmr_2"} {
		t.Run(register, func(t *testing.T) {
			resp := verifyResp(teetypes.PlatformTDX, key)
			resp.Result.Claims.PlatformData[register] = rtmr1B
			api := newFakeAPI(t, staticVerify(resp))
			if err := verifyPeer(context.Background(), attestedLeaf(t, tdxEnvelope), testPolicy(t, teetypes.PlatformTDX, key, api.URL)); !errors.Is(err, ratls.ErrPolicyViolation) {
				t.Fatalf("wrong RTMR accepted: %v", err)
			}
		})
	}
}
func TestVerifyPeerCertificateValidity(t *testing.T) {
	key := operatorKey(t)
	for _, tc := range []struct {
		name       string
		start, end time.Time
		accept     bool
	}{
		{"current", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), true},
		{"expired within former skew", time.Now().Add(-time.Hour), time.Now().Add(-time.Minute), false},
		{"future", time.Now().Add(time.Hour), time.Now().Add(2 * time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPI(t, staticVerify(verifyResp(teetypes.PlatformTDX, key)))
			ext, err := ratls.MarshalExtension(&ratls.Attestation{Family: ratls.TEETypeTDX, Report: []byte(tdxEnvelope)})
			if err != nil {
				t.Fatal(err)
			}
			leaf := selfSigned(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "window"}, NotBefore: tc.start, NotAfter: tc.end, ExtraExtensions: []pkix.Extension{ext}})
			err = verifyPeer(context.Background(), leaf, testPolicy(t, teetypes.PlatformTDX, key, api.URL))
			if (err == nil) != tc.accept {
				t.Fatalf("err=%v", err)
			}
			if !tc.accept && api.verifyCalls.Load() != 0 {
				t.Fatal("expired certificate reached verifier")
			}
		})
	}
}

func TestVerifyPeerDoesNotMixAuthorizedEntries(t *testing.T) {
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformTDX, teetypes.PlatformSNP} {
		t.Run(string(platform), func(t *testing.T) {
			keyA, keyB := operatorKey(t), operatorKey(t)
			a, b := policyEntry(t, platform, keyA), policyEntry(t, platform, keyB)
			b.Name = "other image"
			var err error
			b.Digest, err = hex.DecodeString(digestB)
			if err != nil {
				t.Fatal(err)
			}
			// This peer matches a's image and b's operator, but neither complete tuple.
			api := newFakeAPI(t, staticVerify(verifyResp(platform, keyB)))
			policy, err := loadPeerPolicy(policyFile(t, platform, a, b), string(platform), api.URL, time.Second, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyPeer(context.Background(), leafForPlatform(t, platform), policy); !errors.Is(err, ratls.ErrPolicyViolation) {
				t.Fatalf("crossed image/operator tuple accepted: %v", err)
			}
		})
	}
}
