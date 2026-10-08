package verify

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// savedReceipt fetches an attest-lb response from ts with nonce and writes it
// beside the leaf ts presented, as a client saving a receipt would.
func savedReceipt(t *testing.T, ts *httptest.Server, nonce []byte) (receiptPath, leafPath string) {
	t.Helper()
	resp, err := ts.Client().Get(ts.URL + "/.well-known/c8s/attest-lb?nonce=" + base64.RawURLEncoding.EncodeToString(nonce))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	receiptPath = filepath.Join(dir, "receipt.json")
	leafPath = filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(receiptPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(leafPath, leafPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return receiptPath, leafPath
}

func TestGatherFromAttestLBFile(t *testing.T) {
	id := mintEndpointIdentity(t)
	ts := attestLBServer(t, id, nil)
	defer ts.Close()
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	receiptPath, leafPath := savedReceipt(t, ts, nonce)
	nonceB64 := base64.RawURLEncoding.EncodeToString(nonce)

	cfg := config{kind: "workload", mode: "attest-lb", fromFile: receiptPath, observedServingCert: leafPath, attestationNonce: nonceB64, timeout: 5 * time.Second}
	ev, err := gatherEvidence(context.Background(), cfg, &verifyPlan{}, nil)
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if ev.fresh || ev.leaf == nil || ev.servingLeafSHA256 != servingLeafDigest(ts.Certificate().Raw) {
		t.Errorf("evidence = fresh %v, leaf %v, serving leaf %q; want a non-fresh verdict on the committed mesh leaf and the observed leaf's digest", ev.fresh, ev.leaf != nil, ev.servingLeafSHA256)
	}

	otherLeaf := filepath.Join(t.TempDir(), "other.der")
	if err := os.WriteFile(otherLeaf, id.ca.Raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*config){
		"other nonce":        func(c *config) { c.attestationNonce = base64.RawURLEncoding.EncodeToString(make([]byte, nonceSize)) },
		"other serving leaf": func(c *config) { c.observedServingCert = otherLeaf },
	} {
		t.Run(name, func(t *testing.T) {
			c := cfg
			change(&c)
			if _, err := gatherEvidence(context.Background(), c, &verifyPlan{}, nil); err == nil || !isSecurityError(err) {
				t.Fatalf("gather = %v, want a security error", err)
			}
		})
	}
	for name, change := range map[string]func(*config){
		"padded nonce": func(c *config) { c.attestationNonce = nonceB64 + "=" },
		"short nonce":  func(c *config) { c.attestationNonce = "AA" },
		"missing leaf": func(c *config) { c.observedServingCert = filepath.Join(t.TempDir(), "none") },
	} {
		t.Run(name, func(t *testing.T) {
			c := cfg
			change(&c)
			if _, err := gatherEvidence(context.Background(), c, &verifyPlan{}, nil); err == nil || isSecurityError(err) {
				t.Fatalf("gather = %v, want a usage error", err)
			}
		})
	}
}

func TestReceiptFlagsRequireEachOther(t *testing.T) {
	for name, cfg := range map[string]config{
		"receipt without nonce": {fromFile: "r.json", mode: "attest-lb", observedServingCert: "leaf.pem"},
		"receipt without leaf":  {fromFile: "r.json", mode: "attest-lb", attestationNonce: "AA"},
		"nonce without receipt": {url: "https://lb.example", mode: "attest-lb", attestationNonce: "AA"},
		"leaf in another mode":  {fromFile: "r.json", mode: "attest-pq", observedServingCert: "leaf.pem"},
	} {
		t.Run(name, func(t *testing.T) {
			var errOut strings.Builder
			if code := run(context.Background(), cfg, io.Discard, &errOut); code != exitUsage || !strings.Contains(errOut.String(), "--observed-serving-cert") {
				t.Fatalf("run() = %d, %q; want a usage error naming the flags", code, errOut.String())
			}
		})
	}
	if err := validateReceiptFlags(config{fromFile: "r.json", mode: "attest-lb", observedServingCert: "leaf.pem", attestationNonce: "AA"}); err != nil {
		t.Fatalf("complete receipt flags rejected: %v", err)
	}
}
