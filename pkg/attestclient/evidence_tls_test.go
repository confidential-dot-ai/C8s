package attestclient

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// An attestation-api with a certificate the system roots trust verifies even
// though the client reaches CDS over armTLS, as cdsclient and get-cert build
// it: the CDS verification refuses any ordinary certificate. The system roots
// are read once per process, so the check runs in a child whose SSL_CERT_FILE
// holds the test server's CA; httptest serves the same certificate in both.
func TestGenerateEvidenceVerifiesSystemRootsBesideArmTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"platform":"snp","evidence":{"q":1}}`))
	}))
	defer srv.Close()

	if os.Getenv("ATTESTCLIENT_SYSTEM_ROOTS_CHILD") == "" {
		roots := filepath.Join(t.TempDir(), "roots.pem")
		if err := os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
		cmd.Env = append(os.Environ(), "ATTESTCLIENT_SYSTEM_ROOTS_CHILD=1", "SSL_CERT_FILE="+roots, "SSL_CERT_DIR="+t.TempDir())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}
		return
	}

	tlsCfg, _, err := armtls.NewClientTLSConfig(&armtls.ClientConfig{Policy: &armtls.VerifyPolicy{Policy: remote.Policy{Measurements: [][]byte{make([]byte, 48)}}, AttestationApiURL: srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	cds := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	if _, err := cds.Get(srv.URL); err == nil {
		t.Fatal("the armTLS client accepted an ordinary certificate; the test proves nothing")
	}
	c := NewClientWithHTTP("https://cds.invalid", cds)
	if _, err := c.GenerateEvidence(srv.URL, []byte("report-data")); err != nil {
		t.Fatalf("GenerateEvidence beside an armTLS CDS client: %v", err)
	}
}
