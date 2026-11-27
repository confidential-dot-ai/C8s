package localverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/sitecollateral"
)

func TestSelectedSiteChecksIntelSignaturesAndStatus(t *testing.T) {
	online := pcsGetter
	pcsGetter = func() tdxtrust.HTTPSGetter {
		t.Fatal("site verification consulted public Intel PCS")
		return nil
	}
	t.Cleanup(func() { pcsGetter = online })
	platform, evidence := envelopeFixture(t, "tdx-evidence.json")
	policy := Params{TDXCollateralProfile: serveIntelSnapshot(t, loadRecordedPCS(t), recordedPCSTime, "")}
	_, _, err := VerifyWithCollateralExpiry(t.Context(), platform, evidence, policy)
	if err == nil || !strings.Contains(err.Error(), "OutOfDate is not accepted") {
		t.Fatalf("want the recorded platform rejected under the default site policy, got %v", err)
	}
	policy.TDXCollateralProfile = serveIntelSnapshot(t, loadRecordedPCS(t), recordedPCSTime, pcs.TcbInfoURL("b0c06f000000"))
	_, _, err = VerifyWithCollateralExpiry(t.Context(), platform, evidence, policy)
	var unavailable *CollateralError
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") || errors.As(err, &unavailable) {
		t.Fatalf("corrupted snapshot object must fail verification, got %v", err)
	}
	policy.TDXTCBStatuses = []teetypes.TdxTcbStatus{teetypes.TdxOutOfDate}
	if _, _, err := VerifyWithCollateralExpiry(t.Context(), platform, evidence, policy); err == nil || !strings.Contains(err.Error(), "cannot accept OutOfDate") {
		t.Fatalf("site policy accepted relaxed Intel status: %v", err)
	}
}

func serveIntelSnapshot(t *testing.T, pcs *recordedPCS, at time.Time, corruptObject string) string {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	m := sitecollateral.Manifest{
		Generation: 1,
		Target:     "tdx-worker",
		ExpiresAt:  at.Add(time.Hour),
		Objects:    make(map[string]sitecollateral.Object),
	}
	bodies := make(map[string][]byte)
	for name, response := range pcs.responses {
		digest := fmt.Sprintf("%x", sha256.Sum256(response.Body))
		m.Objects[name] = sitecollateral.Object{SHA256: digest, Header: response.Header}
		object := "/objects/" + digest
		bodies[object] = response.Body
		if name == corruptObject {
			bodies[object] = []byte("corrupt")
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	bodies["/snapshots/"+digest+".json"] = raw
	bodies["/snapshots/"+digest+".sig"] = ed25519.Sign(key, raw)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/active" {
			w.Header().Set("X-C8s-Challenge", r.Header.Get("X-C8s-Challenge"))
			w.Header().Set("X-C8s-Time", at.Format(time.RFC3339Nano))
			_ = json.NewEncoder(w).Encode(sitecollateral.Selection{Generation: m.Generation, SHA256: digest})
			return
		}
		body, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	p := sitecollateral.Profile{
		Origin:         server.URL,
		TLSCertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})),
		MediaPublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
		Target:         m.Target,
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(t.TempDir(), "site.json")
	if err := os.WriteFile(profile, data, 0600); err != nil {
		t.Fatal(err)
	}
	return profile
}

func TestSelectedSiteAcceptsCurrentIntelStatus(t *testing.T) {
	raw, err := os.ReadFile("testdata/uptodate/quote.bin")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := json.Marshal(map[string]string{"quote": base64.StdEncoding.EncodeToString(raw)})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/uptodate/pcs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture recordedPCS
	if err := json.Unmarshal(data, &fixture.responses); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	policy := Params{TDXCollateralProfile: serveIntelSnapshot(t, &fixture, at, "")}
	res, expires, err := VerifyWithCollateralExpiry(t.Context(), "tdx", evidence, policy)
	if err != nil {
		t.Fatal(err)
	}
	if res.TCBStatus == nil || res.TCBStatus.TCBStatus != teetypes.TdxUpToDate || expires == nil || !expires.Equal(at.Add(time.Hour)) {
		t.Fatalf("unexpected verified TCB %v or selection expiry %v", res.TCBStatus, expires)
	}
}
