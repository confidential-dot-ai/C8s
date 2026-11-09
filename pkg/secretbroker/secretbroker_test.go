package secretbroker_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/secretbroker"
)

type fixture struct {
	mesh     *issuer.MeshCA
	key      *ecdsa.PrivateKey
	chain    [][]byte
	verifier secretbroker.Verifier
	doc      []byte
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	mesh, err := issuer.NewMeshCA("c8s Mesh CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := mesh.Current().CA
	broker, err := ca.SignBroker(&key.PublicKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{
		mesh: mesh, key: key, chain: [][]byte{broker, ca.Cert.Raw},
		verifier: secretbroker.Verifier{MeshCAKey: sha256.Sum256(ca.Cert.RawSubjectPublicKeyInfo)},
		doc:      []byte(`{"client_key":"k","agent_id":"a","signature":"s"}`),
	}
}

func (f fixture) request(t *testing.T, secret string) secretbroker.ReleaseRequest {
	t.Helper()
	digest := sha256.Sum256(f.doc)
	statement, err := secretbroker.NewStatement("pcvm-1", nil, digest[:], secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := secretbroker.SignStatement(f.key, statement)
	if err != nil {
		t.Fatal(err)
	}
	return secretbroker.ReleaseRequest{Version: secretbroker.ReleaseVersion, Statement: statement, Signature: sig, BrokerChain: f.chain, ClientDocument: f.doc}
}

func TestVerifyAcceptsABrokerStatement(t *testing.T) {
	f := newFixture(t)
	s, err := f.verifier.Verify(f.request(t, "agent-token"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(f.doc)
	if s.Secret != "agent-token" || s.Pod != "pcvm-1" || len(s.Nonce) != secretbroker.NonceSize || s.ClientDocumentDigest != hex.EncodeToString(digest[:]) {
		t.Fatalf("statement = %+v", s)
	}
}

func TestVerifyRefuses(t *testing.T) {
	f := newFixture(t)
	other := newFixture(t)
	// A mesh leaf under the same CA authenticates TLS peers, not statements.
	podKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl, _ := certutil.NewLeafTemplate("pod", time.Hour)
	ca := f.mesh.Current().CA
	podLeaf, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &podKey.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*secretbroker.ReleaseRequest)
		now    time.Time
		want   string
	}{
		{name: "version", change: func(r *secretbroker.ReleaseRequest) { r.Version = "c8s-secret-release/v0" }, want: "version"},
		{name: "another CDS", change: func(r *secretbroker.ReleaseRequest) { r.BrokerChain = other.chain }, want: "pinned"},
		{name: "chain without CA", change: func(r *secretbroker.ReleaseRequest) { r.BrokerChain = r.BrokerChain[:1] }, want: "chain"},
		{name: "mesh leaf is no broker", change: func(r *secretbroker.ReleaseRequest) {
			r.BrokerChain = [][]byte{podLeaf, r.BrokerChain[1]}
			r.Signature, _ = secretbroker.SignStatement(podKey, r.Statement)
		}, want: "broker certificate"},
		{name: "signature", change: func(r *secretbroker.ReleaseRequest) {
			r.Signature, _ = secretbroker.SignStatement(other.key, r.Statement)
		}, want: "signature"},
		{name: "edited statement", change: func(r *secretbroker.ReleaseRequest) {
			r.Statement = []byte(strings.Replace(string(r.Statement), "agent-token", "other-token", 1))
		}, want: "signature"},
		{name: "client document", change: func(r *secretbroker.ReleaseRequest) { r.ClientDocument = []byte("{}") }, want: "client document"},
		{name: "stale", now: time.Now().Add(secretbroker.MaxStatementAge + time.Minute), want: "current"},
		{name: "broker expired", now: time.Now().Add(2 * time.Hour), want: "broker certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := f.request(t, "agent-token")
			if tc.change != nil {
				tc.change(&req)
			}
			v := f.verifier
			if !tc.now.IsZero() {
				v.Now = func() time.Time { return tc.now }
			}
			if _, err := v.Verify(req); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestStatementWire(t *testing.T) {
	f := newFixture(t)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(f.request(t, "x").Statement, &fields); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "pod", "client_document_digest", "secret", "issued_at", "nonce"} {
		if fields[k] == nil {
			t.Fatalf("statement lacks %s: %s", k, fields)
		}
	}
	if _, ok := fields["workload"]; ok {
		t.Fatal("a pod without a matched workload states one")
	}
}

func TestValidSecretName(t *testing.T) {
	for _, ok := range []string{"a", "agent-token", "db.password_2"} {
		if secretbroker.ValidSecretName(ok) != nil {
			t.Fatalf("refused %q", ok)
		}
	}
	for _, bad := range []string{"", ".", "..", "a/b", "a b", strings.Repeat("a", 129)} {
		if secretbroker.ValidSecretName(bad) == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestVerifyRefusesASignedButInvalidStatement(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
		raw  string
		want string
	}{
		{name: "trailing data", raw: "{} {}", want: "malformed"},
		{name: "unknown field", edit: func(s map[string]any) { s["extra"] = 1 }, want: "malformed"},
		{name: "statement version", edit: func(s map[string]any) { s["version"] = "v0" }, want: "statement version"},
		{name: "secret name", edit: func(s map[string]any) { s["secret"] = "a/b" }, want: "secret"},
		{name: "no nonce", edit: func(s map[string]any) { delete(s, "nonce") }, want: "nonce"},
		{name: "no pod", edit: func(s map[string]any) { s["pod"] = "" }, want: "pod"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := f.request(t, "agent-token")
			if tc.raw != "" {
				req.Statement = []byte(tc.raw)
			} else {
				var fields map[string]any
				if err := json.Unmarshal(req.Statement, &fields); err != nil {
					t.Fatal(err)
				}
				tc.edit(fields)
				var err error
				if req.Statement, err = json.Marshal(fields); err != nil {
					t.Fatal(err)
				}
			}
			var err error
			if req.Signature, err = secretbroker.SignStatement(f.key, req.Statement); err != nil {
				t.Fatal(err)
			}
			if _, err := f.verifier.Verify(req); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyRefusesAnUnparsableChain(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name  string
		chain [][]byte
		want  string
	}{
		{"broker", [][]byte{[]byte("x"), f.chain[1]}, "broker certificate"},
		{"mesh CA", [][]byte{f.chain[0], []byte("x")}, "mesh CA certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := f.request(t, "agent-token")
			req.BrokerChain = tc.chain
			if _, err := f.verifier.Verify(req); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNewStatementRefusesBadInput(t *testing.T) {
	digest := sha256.Sum256([]byte("doc"))
	if _, err := secretbroker.NewStatement("pcvm-1", nil, digest[:], "a/b", time.Now()); err == nil {
		t.Fatal("accepted a bad secret name")
	}
	if _, err := secretbroker.NewStatement("pcvm-1", nil, digest[:16], "a", time.Now()); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("short digest: %v", err)
	}
}
