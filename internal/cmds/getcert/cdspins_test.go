package getcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
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

// get-cert follows signed CDS pin decrees only on top of a complete CDS
// image policy.
func TestCDSPinSource(t *testing.T) {
	policy, err := os.ReadFile("../../testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{CDSURL: "https://cds:8443", AttestationApiURL: "http://127.0.0.1:1", MeasurementsConfigJSON: string(policy)}
	if src, err := cdsPinSource(cfg); src != nil || err != nil {
		t.Fatalf("off: %v %v", src, err)
	}
	cfg.CDSPins.ClusterID, cfg.CDSPins.DecreeKey = "c1", testDecreeKey(t)
	src, err := cdsPinSource(cfg)
	if err != nil || src == nil {
		t.Fatalf("on: %v %v", src, err)
	}
	if hc, err := cdsHTTPClient(cfg); err != nil || hc == nil {
		t.Fatalf("client: %v", err)
	}
	cfg.MeasurementsConfigJSON = ""
	if _, err := cdsPinSource(cfg); err == nil {
		t.Fatal("decrees without a CDS image policy accepted")
	}
	cfg.MeasurementsConfigJSON, cfg.CDSPins.DecreeKey = string(policy), "junk"
	if _, err := cdsHTTPClient(cfg); err == nil {
		t.Fatal("a junk decree key accepted")
	}
}
