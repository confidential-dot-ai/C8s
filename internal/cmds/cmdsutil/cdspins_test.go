package cmdsutil

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

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

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

func TestCDSDecreesInfoAndSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cds-decrees.json")
	if _, ok, err := LoadCDSDecreesInfo(path); ok || err != nil {
		t.Fatalf("absent (no HA CDS): %v %v", ok, err)
	}
	for name, body := range map[string]string{"bad": "{", "empty": "{}"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadCDSDecreesInfo(path); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, _, err := LoadCDSDecreesInfo(dir); err == nil {
		t.Fatal("a directory accepted")
	}
	raw, _ := json.Marshal(CDSDecreesInfo{ClusterID: "c1", DecreeKey: testDecreeKeyPEM(t)})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	info, ok, err := LoadCDSDecreesInfo(path)
	if !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	bootstrap, err := refvalues.Load("../../testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	src, err := CDSDecreeSource(info, bootstrap, "https://cds/", filepath.Join(dir, "state.json"))
	if err != nil || len(src.Current().Images) != len(bootstrap.Images) {
		t.Fatalf("source: %v", err)
	}
	for _, key := range []string{"junk", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"} {
		if _, err := CDSDecreeSource(CDSDecreesInfo{ClusterID: "c1", DecreeKey: key}, bootstrap, "https://cds", ""); err == nil {
			t.Fatalf("decree key %q accepted", key)
		}
	}
}

// A credential client follows the policy the enforcer rewrites in place; a
// half-written document leaves its set as it was.
func TestNodePinsFollowsTheMountedPolicy(t *testing.T) {
	src, err := os.ReadFile("../../testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	set, err := refvalues.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cds-pins.json")
	if _, err := NewNodePins(path); err == nil {
		t.Fatal("absent policy accepted")
	}
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := NewNodePins(path)
	if err != nil || n.Generation() != 1 || len(n.Current().Images) != len(set.Images) {
		t.Fatalf("start: %v", err)
	}
	if changed, err := n.Refresh(t.Context()); changed || err != nil {
		t.Fatalf("unchanged file: %v %v", changed, err)
	}
	if err := os.WriteFile(path, src[:len(src)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := n.Refresh(t.Context()); changed || err == nil || n.Generation() != 1 {
		t.Fatalf("half-written: %v %v", changed, err)
	}
	fewer := set
	fewer.Images = set.Images[:1]
	doc, err := refvalues.Format(fewer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := n.Refresh(t.Context()); !changed || err != nil || n.Generation() != 2 || len(n.Current().Images) != 1 {
		t.Fatalf("rewritten: %v %v", changed, err)
	}
	if ok, err := NodeMountsPins(path); !ok || err != nil {
		t.Fatalf("mounted: %v %v", ok, err)
	}
}
