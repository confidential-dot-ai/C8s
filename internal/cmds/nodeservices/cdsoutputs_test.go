package nodeservices

import (
	"encoding/json"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

// cdsOutputs carries the HA inputs, recovery key included, and refuses a
// bad operator key or seed.
func TestCDSOutputs(t *testing.T) {
	pins := testPins(t)
	d := &launchconfig.Document{ClusterID: "c1", TLSSAN: "cds.example",
		Server: launchconfig.ServerConfig{OperatorPublicKey: string(pins.Images[0].Anchor)},
		CDSHA:  &launchconfig.CDSHA{DecreeKey: string(pins.Images[0].Anchor), Replicas: 3, RecoveryKey: string(pins.Images[1].Anchor)}}
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
	badKey := *d
	badKey.Server.OperatorPublicKey = "junk"
	if _, err := cdsOutputs(&badKey, seed); err == nil {
		t.Fatal("bad operator key accepted")
	}
	if _, err := cdsOutputs(d, []byte("{")); err == nil {
		t.Fatal("bad baked seed accepted")
	}
}
