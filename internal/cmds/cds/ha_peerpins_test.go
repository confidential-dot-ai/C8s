package cds

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
)

// The launch document's peer images become the replica's PeerPins, in the
// same form as its own image pin; one that is no image pin is refused.
func TestLoadHAConfigFilePeerImages(t *testing.T) {
	img := func(b string) launchconfig.Image {
		return launchconfig.Image{Platform: "tdx", Measurement: strings.Repeat(b, 48), RTMRs: map[int]string{1: strings.Repeat("22", 48), 2: strings.Repeat("33", 48)}}
	}
	load := func(peers ...launchconfig.Image) (haConfig, error) {
		raw, _ := json.Marshal(nodeservices.CDSHAConfig{ClusterID: "c1", DecreeKey: "PEM", Replicas: 3, Image: img("11"), PeerImages: peers})
		p := filepath.Join(t.TempDir(), "cds-ha.json")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		h := haConfig{configFile: p}
		return h, loadHAConfigFile(&h)
	}
	h, err := load(img("44"))
	if err != nil {
		t.Fatal(err)
	}
	old := img("44")
	want, _ := cdsha.ImagePin(old.Platform, old.Measurement, old.RTMRs)
	if len(h.peerPins) != 1 || h.peerPins[0] != want || len(h.pins) != 1 || h.pins[0] == want {
		t.Fatalf("pins %v, peer pins %v", h.pins, h.peerPins)
	}
	if _, err := load(launchconfig.Image{Platform: "tdx", Measurement: strings.Repeat("44", 48)}); err == nil {
		t.Fatal("a TDX peer image without RTMR1/2 accepted")
	}
}
