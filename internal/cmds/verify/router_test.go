package verify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsattest"
	"github.com/confidential-dot-ai/c8s/internal/routing"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// recordingProvider stands in for the TEE: it records the report_data the
// production handler asks it to attest.
type recordingProvider struct {
	mu         sync.Mutex
	reportData []byte
}

func (p *recordingProvider) Evidence(_ context.Context, reportData []byte) (json.RawMessage, string, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reportData = bytes.Clone(reportData)
	return json.RawMessage(`{"attestation_report":"AAAA"}`), "snp", "", nil
}

func (p *recordingProvider) last() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reportData
}

func writePEM(t *testing.T, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// servingCert is a self-signed TLS credential and the PEM file of its leaf.
func servingCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "c8s-router.c8s-system.svc"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, writePEM(t, "serving.pem", "CERTIFICATE", der)
}

// productionRouter serves the production cds-attest handler over TLS with the
// manifest at revision 1 applied and published. afterResponse, when set, runs
// after each response.
func productionRouter(t *testing.T, operator operatorSigner, afterResponse func(*routing.State)) (string, *recordingProvider, []byte) {
	t.Helper()
	state := routing.NewState(routing.StateConfig{MeshCAs: func() ([]*x509.Certificate, error) { return nil, nil }})
	body, digest := operator.publish(t, 1)
	var env routes.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Accept(env, operator.keys); err != nil {
		t.Fatal(err)
	}

	id := mintEndpointIdentity(t)
	keyDER, err := x509.MarshalECPrivateKey(id.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, certFile := servingCert(t)
	prov := &recordingProvider{}
	handler := cdsattest.NewServer(cdsattest.Config{
		Evidence:             prov,
		FrontDoorMode:        types.FrontDoorModeCDS,
		ServingCertFile:      certFile,
		MeshIdentityCertFile: writePEM(t, "mesh.pem", "CERTIFICATE", id.leaf.Raw),
		MeshIdentityKeyFile:  writePEM(t, "mesh-key.pem", "EC PRIVATE KEY", keyDER),
		MeshIdentityCAFile:   writePEM(t, "mesh-ca.pem", "CERTIFICATE", id.ca.Raw),
		Routes:               routing.NewProxy(routing.ProxyConfig{State: state}),
		PublishRoutes:        true,
	}).Handler()
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		if afterResponse != nil {
			afterResponse(state)
		}
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts.URL, prov, digest
}

// TestProductionRouterAgainstVerifier runs the verifier's gather path against
// the production cds-attest handler: the report_data the verifier expects
// must be what the handler asked the TEE to attest.
func TestProductionRouterAgainstVerifier(t *testing.T) {
	operator := newOperatorSigner(t)
	otherKey := newOperatorSigner(t).keyFile
	for _, mode := range []string{"attest-pq", "attest-lb"} {
		for _, tc := range []struct {
			name string
			// check sets the route check flags from the applied digest.
			check func(cfg *config, digest []byte)
			// updates is how many responses the router follows with the
			// next revision: the publication fetch, then the handshake.
			updates int
			wantErr bool
		}{
			{name: "pin matches", check: func(cfg *config, digest []byte) { cfg.routeDigests = []string{hex.EncodeToString(digest)} }},
			{name: "operator keys match", check: func(cfg *config, _ []byte) { cfg.operatorKeys = operator.keyFile }},
			{name: "wrong pin", check: func(cfg *config, _ []byte) {
				cfg.routeDigests = []string{hex.EncodeToString(bytes.Repeat([]byte{0x6b}, 32))}
			}, wantErr: true},
			{name: "untrusted publication signature", check: func(cfg *config, _ []byte) { cfg.operatorKeys = otherKey }, wantErr: true},
			{name: "route update between publication and admission", check: func(cfg *config, _ []byte) { cfg.operatorKeys = operator.keyFile }, updates: 1},
			{name: "route updates after the publication fetch and the handshake", check: func(cfg *config, _ []byte) { cfg.operatorKeys = operator.keyFile }, updates: 2, wantErr: true},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				var fetches atomic.Int32
				afterResponse := func(state *routing.State) {
					n := int(fetches.Add(1))
					if n > tc.updates {
						return
					}
					body, _ := operator.publish(t, 1+n)
					var env routes.Envelope
					if err := json.Unmarshal(body, &env); err != nil {
						t.Error(err)
					}
					if _, err := state.Accept(env, operator.keys); err != nil {
						t.Error(err)
					}
				}
				url, prov, digest := productionRouter(t, operator, afterResponse)
				cfg := config{url: url, mode: mode, timeout: 5 * time.Second}
				tc.check(&cfg, digest)
				rc, err := parseRouteCheck(cfg)
				if err != nil {
					t.Fatal(err)
				}
				ev, err := gatherEvidence(context.Background(), cfg, &verifyPlan{routes: rc}, nil)
				if tc.wantErr {
					if !isSecurityError(err) {
						t.Fatalf("gatherEvidence = %v, want a security error", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(ev.erd, prov.last()) {
					t.Fatalf("verifier expects report_data %x, handler attested %x", ev.erd, prov.last())
				}
				if tc.updates > 0 {
					_, digest = operator.publish(t, 2)
				}
				if !bytes.Equal(ev.route.digest, digest) {
					t.Fatalf("bound route digest %x, want %x", ev.route.digest, digest)
				}
			})
		}
	}
}
