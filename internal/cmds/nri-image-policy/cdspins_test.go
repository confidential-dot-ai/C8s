package nriimagepolicy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// The plugin follows signed CDS pin decrees only with the node's cds-pins
// file and a complete CDS policy, and builds both the pull client and the
// digests endpoint's verifier from the same source.
func TestCDSPinSource(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	info, _ := json.Marshal(map[string]string{"cluster_id": "c1", "decree_key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	dir := t.TempDir()
	pins := filepath.Join(dir, "cds-pins.json")
	if err := os.WriteFile(pins, info, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := pullConfig{URL: "https://cds:30808", AttestationApiURL: "http://127.0.0.1:1", CDSMeasurementsConfig: "../../testdata/node-identities.json"}
	if src, err := cfg.cdsPinSource(); src != nil || err != nil {
		t.Fatalf("off: %v %v", src, err)
	}
	cfg.CDSPinsFile, cfg.CDSPinsState = pins, filepath.Join(dir, "state.json")
	src, err := cfg.cdsPinSource()
	if err != nil || src == nil {
		t.Fatalf("on: %v %v", src, err)
	}
	cfg.pinSource = src
	if hc, err := allowlistPullHTTPClient(cfg); err != nil || hc == nil {
		t.Fatalf("pull client: %v", err)
	}
	cfg.CDSPinsFile = filepath.Join(dir, "absent.json")
	if src, err := cfg.cdsPinSource(); src != nil || err != nil {
		t.Fatalf("a cluster without HA CDS: %v %v", src, err)
	}
	cfg.CDSPinsFile, cfg.CDSMeasurementsConfig = pins, ""
	if _, err := cfg.cdsPinSource(); err == nil {
		t.Fatal("pin decrees without a CDS policy accepted")
	}
}
