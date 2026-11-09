package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/secretbroker"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const podSecretValue = "plaintext-agent-secret"

// fakeKMS verifies every request as a KMS must and answers with decide.
type fakeKMS struct {
	server   *httptest.Server
	verifier secretbroker.Verifier
	decide   func(secretbroker.Statement) (int, string)
	seen     []secretbroker.Statement
}

func newFakeKMS(t *testing.T, mesh *issuer.MeshCA) *fakeKMS {
	k := &fakeKMS{
		verifier: secretbroker.Verifier{MeshCAKey: sha256.Sum256(mesh.Current().CA.Cert.RawSubjectPublicKeyInfo)},
		decide:   func(secretbroker.Statement) (int, string) { return http.StatusOK, "" },
	}
	k.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req secretbroker.ReleaseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s, err := k.verifier.Verify(req)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(secretbroker.Refusal{Error: err.Error()})
			return
		}
		k.seen = append(k.seen, s)
		status, reason := k.decide(s)
		w.WriteHeader(status)
		if status != http.StatusOK {
			_ = json.NewEncoder(w).Encode(secretbroker.Refusal{Error: reason})
			return
		}
		_ = json.NewEncoder(w).Encode(secretbroker.ReleaseResponse{Version: secretbroker.ReleaseVersion, Value: []byte(podSecretValue)})
	}))
	t.Cleanup(k.server.Close)
	return k
}

func (k *fakeKMS) config() *cdsconfig.KMS {
	return &cdsconfig.KMS{URL: k.server.URL + "/release", TLSKey: sha256.Sum256(k.server.Certificate().RawSubjectPublicKeyInfo)}
}

// podLeaf is a CDS-issued pod CVM leaf carrying the pod instance and, unless
// digest is nil, a client document digest.
func podLeaf(t *testing.T, mesh *issuer.MeshCA, digest []byte, extra ...pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := certutil.NewLeafTemplate("", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := armtls.MarshalSandboxIDExtension("pcvm-0123")
	if err != nil {
		t.Fatal(err)
	}
	tmpl.ExtraExtensions = append(append(tmpl.ExtraExtensions, instance), extra...)
	if digest != nil {
		ext, err := armtls.MarshalClientDocumentDigestExtension(digest)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	}
	ca := mesh.Current().CA
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

type podSecretFixture struct {
	mesh    *issuer.MeshCA
	kms     *fakeKMS
	handler PodSecretHandler
	doc     []byte
}

func newPodSecretFixture(t *testing.T) podSecretFixture {
	t.Helper()
	mesh, err := issuer.NewMeshCA("c8s Mesh CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := newSecretBroker(ownCA{mesh})
	if err != nil {
		t.Fatal(err)
	}
	kms := newFakeKMS(t, mesh)
	return podSecretFixture{
		mesh: mesh, kms: kms, handler: PodSecretHandler{Broker: broker, KMS: newKMSClient(kms.config())},
		doc: []byte(`{"client_key":"k","agent_id":"a","signature":"s"}`),
	}
}

func (f podSecretFixture) ask(t *testing.T, leaf *x509.Certificate, secret string, doc []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(secretbroker.PodRequest{Secret: secret, ClientDocument: doc})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, secretbroker.PodRoute, bytes.NewReader(body))
	if leaf != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, f.mesh.Current().CA.Cert}}}
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

func podSecretError(t *testing.T, w *httptest.ResponseRecorder) types.ErrorResponse {
	t.Helper()
	var e types.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	return e
}

func TestPodSecretBrokeredToTheKMS(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	f := newPodSecretFixture(t)
	digest := sha256.Sum256(f.doc)
	w := f.ask(t, podLeaf(t, f.mesh, digest[:]), "agent-token", f.doc)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp secretbroker.PodResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || string(resp.Value) != podSecretValue {
		t.Fatalf("response %q: %v", w.Body, err)
	}
	if len(f.kms.seen) != 1 {
		t.Fatalf("KMS saw %d statements", len(f.kms.seen))
	}
	s := f.kms.seen[0]
	if s.Pod != "pcvm-0123" || s.Secret != "agent-token" || s.Workload != nil {
		t.Fatalf("statement = %+v", s)
	}
	// Passing through is all CDS does with a value: it is never logged.
	if strings.Contains(logs.String(), podSecretValue) || !strings.Contains(logs.String(), "pod secret released") {
		t.Fatalf("log: %s", logs.String())
	}
}

func TestPodSecretRefusesADocumentOtherThanTheLeafs(t *testing.T) {
	f := newPodSecretFixture(t)
	digest := sha256.Sum256(f.doc)
	w := f.ask(t, podLeaf(t, f.mesh, digest[:]), "agent-token", []byte(`{"client_key":"other"}`))
	if w.Code != http.StatusForbidden || podSecretError(t, w).Error != types.ErrorCodeSecretRefused {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if len(f.kms.seen) != 0 {
		t.Fatal("a mismatched document reached the KMS")
	}
}

func TestPodSecretNeedsAPodLeafWithAClientDocument(t *testing.T) {
	f := newPodSecretFixture(t)
	for name, leaf := range map[string]*x509.Certificate{
		"no certificate":     nil,
		"no client document": podLeaf(t, f.mesh, nil),
	} {
		t.Run(name, func(t *testing.T) {
			if w := f.ask(t, leaf, "agent-token", f.doc); w.Code != http.StatusForbidden {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
		})
	}
	if len(f.kms.seen) != 0 {
		t.Fatal("an unauthenticated request reached the KMS")
	}
}

func TestPodSecretRelaysTheKMSRefusal(t *testing.T) {
	f := newPodSecretFixture(t)
	f.kms.decide = func(secretbroker.Statement) (int, string) {
		return http.StatusForbidden, "client key may not read agent-token"
	}
	digest := sha256.Sum256(f.doc)
	w := f.ask(t, podLeaf(t, f.mesh, digest[:]), "agent-token", f.doc)
	e := podSecretError(t, w)
	if w.Code != http.StatusForbidden || e.Error != types.ErrorCodeSecretRefused || !strings.Contains(e.Message, "client key may not read agent-token") {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
}

func TestPodSecretHoldsTheKMSToItsPinnedKey(t *testing.T) {
	f := newPodSecretFixture(t)
	cfg := f.kms.config()
	cfg.TLSKey = sha256.Sum256([]byte("another key"))
	f.handler.KMS = newKMSClient(cfg)
	digest := sha256.Sum256(f.doc)
	w := f.ask(t, podLeaf(t, f.mesh, digest[:]), "agent-token", f.doc)
	if w.Code != http.StatusBadGateway || podSecretError(t, w).Error != types.ErrorCodeKMSUnavailable || len(f.kms.seen) != 0 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
}

// A renewed mesh CA certificate gets a broker certificate issued under it.
func TestBrokerChainFollowsTheMeshCA(t *testing.T) {
	f := newPodSecretFixture(t)
	_, first, err := f.handler.Broker.sign([]byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := f.mesh.RenewCertificate()
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := f.handler.Broker.sign([]byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first[0], second[0]) || !bytes.Equal(second[1], renewed.CA.Cert.Raw) {
		t.Fatal("broker chain did not follow the renewed mesh CA certificate")
	}
}

// A named pod leaf's workload reaches the KMS as the leaf states it.
func TestPodSecretStatesTheLeafsWorkload(t *testing.T) {
	f := newPodSecretFixture(t)
	named, err := armtls.MarshalMatchedWorkloadExtension(&armtls.MatchedWorkload{Name: "agent", AllowlistVersion: "7", AllowlistDigest: bytes.Repeat([]byte{0xab}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(f.doc)
	if w := f.ask(t, podLeaf(t, f.mesh, digest[:], named), "agent-token", f.doc); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	got := f.kms.seen[0].Workload
	if got == nil || *got != (secretbroker.Workload{Name: "agent", AllowlistVersion: "7", AllowlistDigest: strings.Repeat("ab", 32)}) {
		t.Fatalf("workload = %+v", got)
	}
}

// meshLeaf is a mesh CA leaf carrying exactly exts.
func meshLeaf(t *testing.T, mesh *issuer.MeshCA, exts ...pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := certutil.NewLeafTemplate("", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, exts...)
	ca := mesh.Current().CA
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestPodSecretRefusesALeafItCannotAttribute(t *testing.T) {
	f := newPodSecretFixture(t)
	digest := sha256.Sum256(f.doc)
	docExt, err := armtls.MarshalClientDocumentDigestExtension(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	for name, leaf := range map[string]*x509.Certificate{
		"no pod":             meshLeaf(t, f.mesh, docExt),
		"malformed workload": podLeaf(t, f.mesh, digest[:], pkix.Extension{Id: armtls.OIDMatchedWorkload, Value: []byte{0x01}}),
	} {
		t.Run(name, func(t *testing.T) {
			w := f.ask(t, leaf, "agent-token", f.doc)
			if w.Code != http.StatusForbidden || podSecretError(t, w).Error != types.ErrorCodeSecretRefused {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
		})
	}
	if len(f.kms.seen) != 0 {
		t.Fatal("an unattributed request reached the KMS")
	}
}

func TestPodSecretRejectsAnInvalidRequest(t *testing.T) {
	f := newPodSecretFixture(t)
	digest := sha256.Sum256(f.doc)
	w := f.ask(t, podLeaf(t, f.mesh, digest[:]), "../agent-token", f.doc)
	if w.Code != http.StatusUnprocessableEntity || podSecretError(t, w).Error != types.ErrorCodeInvalidRequest {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestDecodePodRequest(t *testing.T) {
	req, err := decodePodRequest(strings.NewReader(`{"secret":"agent-token","client_document":"e30="}`))
	if err != nil || req.Secret != "agent-token" || string(req.ClientDocument) != "{}" {
		t.Fatalf("%+v %v", req, err)
	}
	for name, body := range map[string]io.Reader{
		"unreadable":    failingReader{},
		"not JSON":      strings.NewReader(`{"secret":`),
		"duplicate key": strings.NewReader(`{"secret":"a","secret":"b"}`),
		"unknown field": strings.NewReader(`{"secret":"a","value":"x"}`),
		"bad name":      strings.NewReader(`{"secret":"a/b"}`),
	} {
		if _, err := decodePodRequest(body); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

type fixedMeshCA struct {
	current issuer.CurrentCA
	issuing bool
}

func (m fixedMeshCA) Current() (issuer.CurrentCA, bool) { return m.current, m.issuing }

func TestPodSecretUnavailableWithoutAnIssuingMeshCA(t *testing.T) {
	f := newPodSecretFixture(t)
	broker, err := newSecretBroker(fixedMeshCA{current: f.mesh.Current()})
	if err != nil {
		t.Fatal(err)
	}
	f.handler.Broker = broker
	digest := sha256.Sum256(f.doc)
	w := f.ask(t, podLeaf(t, f.mesh, digest[:]), "agent-token", f.doc)
	if w.Code != http.StatusServiceUnavailable || podSecretError(t, w).Error != types.ErrorCodeInternal || len(f.kms.seen) != 0 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
}

func TestBrokerSignFailsWithoutACAKey(t *testing.T) {
	broker, err := newSecretBroker(fixedMeshCA{current: issuer.CurrentCA{CA: &issuer.CA{}}, issuing: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := broker.sign([]byte("{}")); err == nil || !strings.Contains(err.Error(), "CA bundle not loaded") {
		t.Fatalf("got %v", err)
	}
}

func TestBrokerChainIsReusedUntilRenewal(t *testing.T) {
	f := newPodSecretFixture(t)
	_, first, err := f.handler.Broker.sign([]byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := f.handler.Broker.sign([]byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first[0], second[0]) {
		t.Fatal("broker certificate reissued before renewal was due")
	}
}

func TestKMSClientRelease(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		want    string
		refusal string
	}{
		{name: "too large", handler: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(bytes.Repeat([]byte{' '}, maxKMSResponse+1))
		}, want: "too large"},
		{name: "malformed", handler: func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(secretbroker.ReleaseResponse{Version: "v0", Value: []byte("v")})
		}, want: "malformed KMS release response"},
		{name: "server error", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}, want: "KMS answered 500"},
		{name: "truncated", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte("{"))
		}, want: "unexpected EOF"},
		{name: "refusal without reason", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}, refusal: "no reason given"},
		{name: "long refusal", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(secretbroker.Refusal{Error: strings.Repeat("x", 300)})
		}, refusal: strings.Repeat("x", 256)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kms := httptest.NewTLSServer(tc.handler)
			defer kms.Close()
			client := newKMSClient(&cdsconfig.KMS{URL: kms.URL, TLSKey: sha256.Sum256(kms.Certificate().RawSubjectPublicKeyInfo)})
			_, err := client.Release(t.Context(), secretbroker.ReleaseRequest{Version: secretbroker.ReleaseVersion})
			if tc.refusal != "" {
				var refusal *kmsRefusal
				if !errors.As(err, &refusal) || refusal.reason != tc.refusal || refusal.status != http.StatusForbidden {
					t.Fatalf("got %v", err)
				}
				if !strings.Contains(err.Error(), "KMS refused (403)") {
					t.Fatalf("error text %q", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestKMSClientRejectsAMalformedURL(t *testing.T) {
	client := newKMSClient(&cdsconfig.KMS{URL: "https://kms\x7f"})
	if _, err := client.Release(t.Context(), secretbroker.ReleaseRequest{}); err == nil || !strings.Contains(err.Error(), "invalid control character") {
		t.Fatalf("got %v", err)
	}
}

func TestKMSCertificateMustBeCurrent(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if err := checkValidity(cert, now); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{now.Add(-2 * time.Hour), now.Add(2 * time.Hour)} {
		if err := checkValidity(cert, at); err == nil || !strings.Contains(err.Error(), "validity period") {
			t.Fatalf("at %v: %v", at, err)
		}
	}
}
