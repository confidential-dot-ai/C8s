package cdsconn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/routerdiscovery"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// routerServer stands in for a router front door: a TLS server with no armTLS
// extension on its serving cert, serving only its discovery document.
func routerServer(t *testing.T) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "router"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(types.DiscoveryDocument{
		Version: "1",
		CDSTLS: types.CDSTLSDiscovery{
			CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		},
		Attestation: types.AttestationDiscovery{
			Challenge: base64.StdEncoding.EncodeToString([]byte("issuance-challenge")),
			Platform:  string(teetypes.PlatformAzSNP),
			Evidence:  json.RawMessage(`{"hcl_report":"fake"}`),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+routerdiscovery.DefaultPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(doc)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestHTTPClientRouterFrontDoor(t *testing.T) {
	router := routerServer(t)
	for _, tc := range []struct {
		name      string
		directCDS bool
		wantErr   string
	}{
		{name: "allowlist", directCDS: false},
		{name: "direct CDS", directCDS: true, wantErr: "https://<node>:30808"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := Options{
				URL:          router.URL,
				Measurements: []string{testutil.TestMeasurement},
				Timeout:      5 * time.Second,
				Verifier:     testutil.ApproveAll(),
				DirectCDS:    tc.directCDS,
			}
			hc, err := o.HTTPClient(context.Background())
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("HTTPClient(%s) = %v, want a client", router.URL, err)
				}
				hc.CloseIdleConnections()
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("HTTPClient(%s) = %v, want an error containing %q", router.URL, err, tc.wantErr)
			}
		})
	}
}
