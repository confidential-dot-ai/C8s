package podprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdspins"
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

func TestProviderDecreeFloorSurvivesSigningAndAssignment(t *testing.T) {
	cfg := fixtureConfig(t)
	key, bootstrap, rolled := providerCDSDecreeFixture(t, cfg)
	path, current := writeProviderPinDecree(t, key, cfg.ClusterID, rolled, 7)
	_, older := writeProviderPinDecree(t, key, cfg.ClusterID, bootstrap, 6)
	cfg.CDSPinDecreeFile = filepath.Base(path)
	loaded, err := LoadConfig(writeProviderConfig(t, cfg, filepath.Dir(path)))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CDSPinDecreeFile != path {
		t.Fatal("optional decree path was not resolved beside the provider config")
	}
	// Config inputs are frozen at startup; subsequent signing never rereads them.
	if err := os.WriteFile(path, []byte("changed after startup"), 0o600); err != nil {
		t.Fatal(err)
	}
	pod := fixturePod()
	static, err := loaded.launch(pod)
	if err != nil {
		t.Fatal(err)
	}
	generic, err := loaded.genericLaunch(identityKey(loaded.ProviderID, "decree-check"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := refvalues.Parse(rolled)
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []createRequest{static, generic} {
		doc, err := signedDocument(req.Trust)
		if err != nil {
			t.Fatal(err)
		}
		pins, err := refvalues.Parse([]byte(doc.CDS.Measurements))
		if err != nil {
			t.Fatal(err)
		}
		if doc.CDS.PinFloor != current.Decree.AppliesAt() || doc.CDS.Address != cfg.CDSAddress || !reflect.DeepEqual(pins, want) {
			t.Fatal("signed launch lost the complete replacement pin set, endpoint or floor")
		}
		if doc.Pod == nil {
			rec := &record{Request: static, UID: pod.UID, Namespace: pod.Namespace, Name: pod.Name, Key: static.Name}
			manifest, entries, peers, err := assignmentPayload(rec)
			if err != nil {
				t.Fatal(err)
			}
			assigned, err := launchconfig.AssignedPod(doc, manifest, entries, peers)
			if err != nil {
				t.Fatal(err)
			}
			if assigned.CDS != doc.CDS || doc.Pod != nil || doc.Workloads != "" {
				t.Fatal("assignment rewrote immutable CDS trust or generic boot authority")
			}
		}
		for _, attested := range []bool{false, true} {
			for _, floor := range []uint64{doc.CDS.PinFloor, 0} {
				source, err := cdspins.New(cdspins.Config{Bootstrap: pins, Floor: floor,
					StateFile: filepath.Join(t.TempDir(), "pins.json"),
					Attested: func(context.Context, refvalues.ReferenceValues) (*cdsdecree.Signed, error) {
						if attested {
							return &older, nil
						}
						return nil, errors.New("pinned replica unavailable")
					},
					Fetch: func(context.Context) (*cdsdecree.Signed, error) { return &older, nil },
				})
				if err != nil {
					t.Fatal(err)
				}
				err = source.Refresh()
				version, held := source.Version()
				if floor != 0 {
					if err == nil || !strings.Contains(err.Error(), "below this node's floor") || held || !reflect.DeepEqual(source.Current(), pins) {
						t.Fatalf("provider floor allowed older CDS pins (attested=%t): %v", attested, err)
					}
				} else if err != nil || !held || version != older.Decree.AppliesAt() || reflect.DeepEqual(source.Current(), pins) {
					t.Fatalf("zero-floor control failed to accept the valid older decree (attested=%t): %v", attested, err)
				}
			}
		}
	}
	data, err := os.ReadFile(cfg.CDSImagePolicyFile)
	if err != nil || !bytes.Equal(data, bootstrap) {
		t.Fatal("provider changed the mounted bootstrap policy")
	}
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
