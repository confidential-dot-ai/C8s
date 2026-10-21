package cmdsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

func TestCDSPinsFlags(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "cds-pins.json")
	if _, on, err := (CDSPinsFlags{File: file}).Info(); on || err != nil {
		t.Fatalf("missing file (cluster without HA CDS): %v %v", on, err)
	}
	if err := os.WriteFile(file, []byte(`{"cluster_id":"c1","decree_key":"-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----\n"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	info, on, err := (CDSPinsFlags{File: file}).Info()
	if !on || err != nil || info.ClusterID != "c1" {
		t.Fatalf("file: %+v %v %v", info, on, err)
	}
	args := info.Args()
	back, on, err := (CDSPinsFlags{ClusterID: args[0][len("--cds-cluster-id="):], DecreeKey: args[1][len("--cds-decree-key="):]}).Info()
	if !on || err != nil || back.ClusterID != "c1" {
		t.Fatalf("flags round trip: %+v %v %v", back, on, err)
	}
	for name, f := range map[string]CDSPinsFlags{
		"file and flags": {File: file, ClusterID: "c1"},
		"id only":        {ClusterID: "c1"},
		"key only":       {DecreeKey: "k"},
	} {
		if _, _, err := f.Info(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := decreeKeyDER("not pem"); err == nil {
		t.Fatal("a non-PEM decree key was accepted")
	}
}

func testDecreeKeyPEM(t *testing.T) string {
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

func TestCDSPinsSource(t *testing.T) {
	bootstrap, err := refvalues.Load("../../testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	if src, err := (CDSPinsFlags{}).Source(bootstrap, "https://cds"); src != nil || err != nil {
		t.Fatalf("off: %v %v", src, err)
	}
	f := CDSPinsFlags{ClusterID: "c1", DecreeKey: testDecreeKeyPEM(t), StateFile: filepath.Join(t.TempDir(), "s.json")}
	src, err := f.Source(bootstrap, "https://cds/")
	if err != nil || src == nil || len(src.Current().Images) != len(bootstrap.Images) {
		t.Fatalf("on: %v %v", src, err)
	}
	if _, err := (CDSPinsFlags{ClusterID: "c1", DecreeKey: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"}).Source(bootstrap, "https://cds"); err == nil {
		t.Fatal("a non-key PEM accepted")
	}
	if _, err := (CDSPinsFlags{ClusterID: "c1", DecreeKey: "-----BEGIN NOT A KEY"}).Source(bootstrap, "https://cds"); err == nil {
		t.Fatal("a broken PEM accepted")
	}
	dir := t.TempDir()
	for name, body := range map[string]string{"bad.json": "{", "empty.json": "{}"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := (CDSPinsFlags{File: p}).Info(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, _, err := (CDSPinsFlags{File: dir}).Info(); err == nil {
		t.Fatal("a directory accepted")
	}
}
