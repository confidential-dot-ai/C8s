package podprovider

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// The CDS operator, node launch key and Pod launch key remain separate. Use
// the production config and decree renderers, not a test verifier.
func providerCDSDecreeFixture(t *testing.T, cfg *Config) (*ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := operatorauth.ParseKeyBundle(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := refvalues.Format(refvalues.ReferenceValues{Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{Name: "server", Digest: bytes.Repeat([]byte{0x11}, 48), Anchor: []byte(cfg.serverPub)}}})
	if err != nil {
		t.Fatal(err)
	}
	workloads, err := allowlist.ParseJSON([]byte(cfg.workloads))
	if err != nil {
		t.Fatal(err)
	}
	launch, err := cdsconfig.Format(cdsconfig.Document{ClusterID: cfg.ClusterID, OperatorKeys: keys,
		Workloads: workloads, Nodes: nodes, NodeCIDRs: []string{"10.0.0.0/24"},
		HA: cdsconfig.HA{Replicas: []string{"cds.example.test"}, Voters: 1}})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := providerCDSPolicy(t, launch)
	rolled, err := refvalues.Format(refvalues.ReferenceValues{Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{
			{Name: "rolled-a", Digest: bytes.Repeat([]byte{0x99}, 48), LaunchFile: launch},
			{Name: "rolled-b", Digest: bytes.Repeat([]byte{0xaa}, 48), LaunchFile: launch},
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.CDSImagePolicyFile, bootstrap, 0o600); err != nil {
		t.Fatal(err)
	}
	return key, bootstrap, rolled
}

func writeProviderPinDecree(t *testing.T, key *ecdsa.PrivateKey, cluster string, policy []byte, version uint64) (string, cdsdecree.Signed) {
	t.Helper()
	pins, err := cdsdecree.NewPinDocument(policy)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cdsdecree.Sign(cdsdecree.Decree{ClusterID: cluster, IntentID: cdsdecree.NewIntentID(),
		Kind: cdsdecree.UpdateMeasurements, BaseVersion: version, CDSPins: pins,
		ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second)}, key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pin-decree.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, signed
}

func writeProviderConfig(t *testing.T, cfg *Config, dir string) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProviderRejectsInvalidOrUnboundPinDecree(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "malformed", "oversized", "wrong-signer", "wrong-launch-file"} {
		t.Run(kind, func(t *testing.T) {
			cfg := fixtureConfig(t)
			key, _, rolled := providerCDSDecreeFixture(t, cfg)
			if kind == "wrong-signer" {
				key = cfg.key // A Pod launch key cannot authorize a CDS pin roll.
			}
			if kind == "wrong-launch-file" {
				rolled = providerCDSPolicy(t, []byte("another launch file"))
			}
			path, _ := writeProviderPinDecree(t, key, cfg.ClusterID, rolled, 7)
			switch kind {
			case "missing":
				path += ".missing"
			case "empty", "malformed", "oversized":
				data := []byte{}
				switch kind {
				case "malformed":
					data = []byte("{")
				case "oversized":
					data = bytes.Repeat([]byte(" "), launchconfig.MaxDocumentSize+1)
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg.CDSPinDecreeFile = path
			if loaded, err := LoadConfig(writeProviderConfig(t, cfg, t.TempDir())); err == nil || loaded != nil || !strings.Contains(err.Error(), "CDS pin decree") {
				t.Fatalf("invalid decree reached provider registration: %v", err)
			}
		})
	}
}
