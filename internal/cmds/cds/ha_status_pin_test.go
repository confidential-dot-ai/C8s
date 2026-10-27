package cds

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// This uses the established --insecure local CLI harness to check output wiring,
// not hardware attestation. Production instructions still require armTLS.
func TestHAStatusRecoveryPinRoundTrip(t *testing.T) {
	k, _ := testKeyPEM(t)
	cert, err := issuer.SelfSignCA(k, "recovery-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pin := certutil.CertFingerprint(cert.Raw)
	body := testSnapshot(t, map[string]any{
		"format": cdsha.Format, "index": 5,
		"core": cdsha.Core{ClusterID: "c1", Epoch: 1, RootCert: cert.Raw,
			Policy: cdsha.FSMPolicy{Version: 1, LedgerTTLNS: int64(time.Hour), LedgerMax: 100, SecretsMaxPaths: 64, SecretsMaxPerHolder: 8, SecretsMaxValue: 4096}},
		"key": key,
	})
	digests, err := cdsha.ContentDigests(body)
	if err != nil {
		t.Fatal(err)
	}
	meta := cdsha.BackupMeta{ClusterID: "c1", Epoch: 1, Index: 5, CAFingerprint: pin, StateDigest: digests.State}
	backup, err := cdsha.SealAuthenticatedBackup(&k.PublicKey, meta, body, cert.Raw, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ha/status" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(cdsha.Status{ClusterID: "c1", Epoch: 1, AppliedIndex: 5, Serving: true, CAFingerprint: pin})
	}))
	defer srv.Close()
	out, err := runHA(t, "status", "--insecure", srv.URL)
	if err != nil {
		t.Fatalf("status: %v %q", err, out)
	}
	var retained string
	for _, field := range strings.Fields(out) {
		if strings.HasPrefix(field, "ca=") {
			retained = strings.TrimPrefix(field, "ca=")
		}
	}
	decoded, err := hex.DecodeString(retained)
	if err != nil || len(retained) != 64 || len(decoded) != 32 || retained != pin {
		t.Fatalf("documented status output loses recovery pin: retained=%q want=%q output=%q", retained, pin, out)
	}
	if err := cdsha.VerifyBackupSource(backup, retained); err != nil {
		t.Fatal(err)
	}
	plain, err := cdsha.OpenBackup(k, backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := cdsha.ValidateRecoverySnapshot(plain, meta, 1, 5); err != nil {
		t.Fatal(err)
	}
}
