package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/secretbroker"
)

type mapSource map[string]string

func (m mapSource) Get(_ context.Context, name string) ([]byte, error) {
	v, ok := m[name]
	if !ok {
		return nil, errors.New("no such secret")
	}
	return []byte(v), nil
}

// cds stands in for one CDS replica: its mesh CA and a broker certificate.
type cds struct {
	mesh  *issuer.MeshCA
	key   *ecdsa.PrivateKey
	chain [][]byte
}

func newCDS(t *testing.T) cds {
	t.Helper()
	mesh, err := issuer.NewMeshCA("c8s Mesh CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := mesh.Current().CA
	broker, err := ca.SignBroker(&key.PublicKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return cds{mesh: mesh, key: key, chain: [][]byte{broker, ca.Cert.Raw}}
}

func (c cds) pin() string {
	h := sha256.Sum256(c.mesh.Current().CA.Cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}

func (c cds) request(t *testing.T, doc []byte, secret string) secretbroker.ReleaseRequest {
	t.Helper()
	digest := sha256.Sum256(doc)
	statement, err := secretbroker.NewStatement("pcvm-0123", nil, digest[:], secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := secretbroker.SignStatement(c.key, statement)
	if err != nil {
		t.Fatal(err)
	}
	return secretbroker.ReleaseRequest{Version: secretbroker.ReleaseVersion, Statement: statement, Signature: sig, BrokerChain: c.chain, ClientDocument: doc}
}

func newClient(t *testing.T) (ed25519.PrivateKey, string, []byte) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	doc, err := newClientDocument(priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, base64.StdEncoding.EncodeToString(pub), doc
}

func testPolicy(clientKey string, secrets ...string) policy {
	var p policy
	p.Clients = append(p.Clients, struct {
		ClientKey string   `json:"client_key"`
		Secrets   []string `json:"secrets"`
	}{clientKey, secrets})
	return p
}

func post(t *testing.T, h http.Handler, req secretbroker.ReleaseRequest) (int, string) {
	t.Helper()
	body, _ := json.Marshal(req)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	if w.Code == http.StatusOK {
		var resp secretbroker.ReleaseResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Version != secretbroker.ReleaseVersion {
			t.Fatalf("response %s: %v", w.Body, err)
		}
		return w.Code, string(resp.Value)
	}
	var refusal secretbroker.Refusal
	_ = json.Unmarshal(w.Body.Bytes(), &refusal)
	return w.Code, refusal.Error
}

func TestReleasePolicy(t *testing.T) {
	c := newCDS(t)
	_, clientKey, doc := newClient(t)
	verifier, err := newVerifier(c.pin())
	if err != nil {
		t.Fatal(err)
	}
	h := &handler{verifier: verifier, policy: testPolicy(clientKey, "agent-token", "gone"), secrets: mapSource{"agent-token": "s3cret"}, nonces: newNonceCache()}

	if status, value := post(t, h, c.request(t, doc, "agent-token")); status != http.StatusOK || value != "s3cret" {
		t.Fatalf("good path: %d %q", status, value)
	}

	other := newCDS(t)
	_, _, strangerDoc := newClient(t)
	priv, _, _ := newClient(t)
	var forged clientDoc
	_ = json.Unmarshal(doc, &forged)
	forged.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, clientDocMessage(nil, forged.AgentID)))
	forgedDoc, _ := json.Marshal(forged)
	replayed := c.request(t, doc, "agent-token")
	post(t, h, replayed)
	for _, tc := range []struct {
		name   string
		req    secretbroker.ReleaseRequest
		status int
		want   string
	}{
		{"another CDS", other.request(t, doc, "agent-token"), http.StatusForbidden, "pinned"},
		{"document unlike the statement", func() secretbroker.ReleaseRequest {
			r := c.request(t, doc, "agent-token")
			r.ClientDocument = strangerDoc
			return r
		}(), http.StatusForbidden, "stated digest"},
		{"forged client signature", c.request(t, forgedDoc, "agent-token"), http.StatusForbidden, "signature"},
		{"not a reference document", c.request(t, []byte(`{"agent":"x"}`), "agent-token"), http.StatusForbidden, "reference client document"},
		{"client key not in policy", c.request(t, strangerDoc, "agent-token"), http.StatusForbidden, "may not read"},
		{"secret not granted", c.request(t, doc, "db-password"), http.StatusForbidden, "may not read"},
		{"replay", replayed, http.StatusForbidden, "replayed"},
		{"store failure", c.request(t, doc, "gone"), http.StatusBadGateway, "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, reason := post(t, h, tc.req)
			if status != tc.status || !strings.Contains(reason, tc.want) {
				t.Fatalf("got %d %q, want %d %q", status, reason, tc.status, tc.want)
			}
		})
	}
}

// The release request is one document: a request with another after it, or one
// padded past maxRequest, is refused rather than read as a prefix.
func TestReleaseRequestMustBeOneDocument(t *testing.T) {
	c := newCDS(t)
	_, clientKey, doc := newClient(t)
	verifier, err := newVerifier(c.pin())
	if err != nil {
		t.Fatal(err)
	}
	h := &handler{verifier: verifier, policy: testPolicy(clientKey, "agent-token"), secrets: mapSource{"agent-token": "s3cret"}, nonces: newNonceCache()}
	request, err := json.Marshal(c.request(t, doc, "agent-token"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"request then a second one", append(bytes.Clone(request), request...)},
		{"request padded past maxRequest", append(bytes.Clone(request), bytes.Repeat([]byte(" "), maxRequest)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(tc.body)))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
			}
		})
	}
}

// TestLiveKeyVault runs the release against a real Azure Key Vault holding a
// secret named agent-token. KMS_LIVE_KEY_VAULT_URL selects the vault; the
// credential is the Azure CLI login.
func TestLiveKeyVault(t *testing.T) {
	url := os.Getenv("KMS_LIVE_KEY_VAULT_URL")
	if url == "" {
		t.Skip("KMS_LIVE_KEY_VAULT_URL not set")
	}
	cred, err := azidentity.NewAzureCLICredential(nil)
	if err != nil {
		t.Fatal(err)
	}
	vault, err := azsecrets.NewClient(url, cred, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := newCDS(t)
	_, clientKey, doc := newClient(t)
	verifier, _ := newVerifier(c.pin())
	h := &handler{verifier: verifier, policy: testPolicy(clientKey, "agent-token"), secrets: keyVault{vault}, nonces: newNonceCache()}
	status, value := post(t, h, c.request(t, doc, "agent-token"))
	if status != http.StatusOK || value == "" {
		t.Fatalf("live release: %d %q", status, value)
	}
	t.Logf("released %d bytes from %s", len(value), url)
}
