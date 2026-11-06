package launchconfig

import (
	"bytes"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
)

func podTrustPolicy(t *testing.T, key string) string {
	t.Helper()
	data, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilyTDX,
		Images: []remote.ImagePin{{Name: "pod", Digest: bytes.Repeat([]byte{0x44}, 48),
			Registers: map[int][]byte{1: bytes.Repeat([]byte{0x55}, 48), 2: bytes.Repeat([]byte{0x66}, 48)},
			Anchor:    []byte(key)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Pod authority lives in the measured CDS
// configuration, and a Pod launch key must differ from the node launch keys.
func TestPodPolicyCannotGrantNodeAuthority(t *testing.T) {
	doc, _, _ := testDocument(t, "tdx", Server)
	_, podKey := testKey(t)
	pins, err := doc.referenceValues()
	if err != nil {
		t.Fatal(err)
	}
	peers, err := refvalues.Format(pins)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, key, want string }{
		{"pod", podKey, ""},
		{"server", doc.Server.OperatorPublicKey, "must differ"},
		{"agent", doc.AgentOperatorPublicKeys[0], "must differ"},
		{"server alternate PEM whitespace", doc.Server.OperatorPublicKey + "\n", "must differ"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := BundleOptions{ClusterID: "pod-trust", TLSSAN: defaultTLSSAN,
				PodImagePolicyPath: writeFile(t, "pods.json", podTrustPolicy(t, tc.key)),
				CDS: CDSOptions{Platform: "tdx", ManifestPath: writeCDSManifest(t), NodeCIDRs: []string{"10.0.0.0/24"},
					AllowlistSeedPath: writeFile(t, "seed.json", componentSeed)}}
			config, _, err := clusterCDS(opts, doc.Server.OperatorPublicKey, peers)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("wanted %q, got %v", tc.want, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := cdsconfig.Parse(config)
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.PodImages) != 1 || string(cfg.PodImages[0].Anchor) != podKey {
				t.Fatal("Pod policy was not measured in CDS configuration")
			}
			for _, pin := range cfg.Nodes.Images {
				if bytes.Equal(pin.Anchor, []byte(podKey)) {
					t.Fatal("Pod key became a node peer")
				}
			}
		})
	}
}
