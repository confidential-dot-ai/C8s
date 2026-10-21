package sidecar

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func testDecreeKey(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestPinSource(t *testing.T) {
	policy, err := os.ReadFile("../../testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	c := Config{CDSURL: "https://cds:8443", MeasurementsConfigJSON: string(policy)}
	if src, err := c.pinSource(); src != nil || err != nil {
		t.Fatalf("off: %v %v", src, err)
	}
	c.CDSPins.ClusterID, c.CDSPins.DecreeKey = "c1", testDecreeKey(t)
	if src, err := c.pinSource(); src == nil || err != nil {
		t.Fatalf("on: %v %v", src, err)
	}
	c.MeasurementsConfigJSON = ""
	if _, err := c.pinSource(); err == nil {
		t.Fatal("decrees without a CDS image policy accepted")
	}
	c.MeasurementsConfigJSON, c.CDSPins.DecreeKey = string(policy), "junk"
	if _, err := c.pinSource(); err == nil {
		t.Fatal("junk decree key accepted")
	}
}

// With pin decrees on, the client verifies CDS through a refreshing
// transport; a bad decree key fails the client, not the first request.
func TestNewClientFollowsPinDecrees(t *testing.T) {
	policy, err := os.ReadFile("../../testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, _ := testutil.WriteLeaf(t, t.TempDir())
	cfg := testConfig("https://cds.example")
	cfg.CertPath, cfg.KeyPath, cfg.MeasurementsConfigJSON = certPath, keyPath, string(policy)
	cfg.CDSPins.ClusterID, cfg.CDSPins.DecreeKey = "c1", testDecreeKey(t)
	client, _, err := NewClient(cfg, armtls.Pins{})
	if err != nil || client == nil {
		t.Fatalf("client: %v", err)
	}
	if _, ok := client.Transport.(*http.Transport); ok {
		t.Fatal("pin decrees on, but the transport is static")
	}
	cfg.CDSPins.DecreeKey = "junk"
	if _, _, err := NewClient(cfg, armtls.Pins{}); err == nil {
		t.Fatal("junk decree key accepted")
	}
}
