package nodeservices

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

func pubPEM(t *testing.T) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// cdsOutputs carries the HA inputs, recovery key included, and refuses a
// document without cdsHA or with a bad operator key.
func TestCDSOutputs(t *testing.T) {
	d := &launchconfig.Document{ClusterID: "c1", TLSSAN: "cds.example",
		Server: launchconfig.ServerConfig{OperatorPublicKey: pubPEM(t)},
		CDSHA:  &launchconfig.CDSHA{DecreeKey: pubPEM(t), Replicas: 3, RecoveryKey: pubPEM(t)}}
	seed := []byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`)
	out, err := cdsOutputs(d, seed)
	if err != nil {
		t.Fatal(err)
	}
	var c CDSHAConfig
	if err := json.Unmarshal(out[cdsHAFile], &c); err != nil || c.RecoveryKey != d.CDSHA.RecoveryKey || c.Replicas != 3 || c.ClusterID != "c1" {
		t.Fatalf("cds-ha.json %+v: %v", c, err)
	}
	if string(out["tls-san"]) != "cds.example\n" || string(out["operator-pubkey"]) != d.Server.OperatorPublicKey {
		t.Fatal("cds node outputs")
	}
	noHA := *d
	noHA.CDSHA = nil
	if _, err := cdsOutputs(&noHA, seed); err == nil {
		t.Fatal("cds role without cdsHA")
	}
	badKey := *d
	badKey.Server.OperatorPublicKey = "junk"
	if _, err := cdsOutputs(&badKey, seed); err == nil {
		t.Fatal("bad operator key accepted")
	}
	if _, err := cdsOutputs(d, []byte("{")); err == nil {
		t.Fatal("bad baked seed accepted")
	}
}
