package launchconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// appliedPinVersion is the version the pin decree below applies at.
const appliedPinVersion = 7

// Another TDX image of the same CDS, for a roll to move the cluster onto.
func writeRolledCDSManifest(t *testing.T) string {
	t.Helper()
	body := `{"version":1,"build":{"platform":"tdx"},"tdx":{"mrtd":"` + strings.Repeat("d1", 48) +
		`","rtmr1":"` + strings.Repeat("d2", 48) + `","rtmr2":"` + strings.Repeat("d3", 48) + `"}}`
	return writeFile(t, "cds-rolled-manifest.json", body)
}

// Signed over the images these manifests name, as `ha pin-policy
// --decree-out` writes it.
func writePinDecree(t *testing.T, bundle, clusterID string, key *ecdsa.PrivateKey, manifests ...string) string {
	t.Helper()
	launchFile, err := os.ReadFile(filepath.Join(bundle, cdsconfig.ConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	set := refvalues.ReferenceValues{Family: teetypes.FamilyTDX}
	for _, manifest := range manifests {
		document, err := cdsconfig.Pin(manifest, teetypes.FamilyTDX, nil, launchFile)
		if err != nil {
			t.Fatal(err)
		}
		images, err := refvalues.Parse(document)
		if err != nil {
			t.Fatal(err)
		}
		for i := range images.Images {
			images.Images[i].Name = fmt.Sprintf("cds-%d", len(set.Images)+i)
		}
		set.Images = append(set.Images, images.Images...)
	}
	document, err := refvalues.Format(set)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := cdsdecree.NewPinDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cdsdecree.Sign(cdsdecree.Decree{
		ClusterID:   clusterID,
		IntentID:    cdsdecree.NewIntentID(),
		Kind:        cdsdecree.UpdateMeasurements,
		BaseVersion: appliedPinVersion,
		ExpiresAt:   time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		CDSPins:     pins,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	object, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, "pin-decree.json", string(object))
}

// The key the bundle's CDS configuration pins.
func bundleOperatorKey(t *testing.T, bundle string) *ecdsa.PrivateKey {
	t.Helper()
	key, err := certutil.LoadECPrivateKeyFile(filepath.Join(bundle, serverKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestAddAgentTakesItsCDSPinFromTheAppliedDecree(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := runBundleCmd(t, append(bundleArgs(t, dir, "tdx"), "--server-address", "10.0.0.10")...); err != nil {
		t.Fatal(err)
	}
	decree := writePinDecree(t, dir, "demo", bundleOperatorKey(t, dir), writeCDSManifest(t), writeRolledCDSManifest(t))

	if err := runBundleCmd(t, "add-agent", "--bundle", dir, "--name", "rolled", "--pin-decree", decree); err != nil {
		t.Fatal(err)
	}

	agent, _ := readBundleDocument(t, dir, "rolled")
	pinned, err := refvalues.Parse([]byte(agent.CDS.Measurements))
	if err != nil {
		t.Fatal(err)
	}
	if len(pinned.Images) != 2 {
		t.Fatalf("the agent pins %d CDS images, want the two the decree names", len(pinned.Images))
	}
	launchFile, err := os.ReadFile(filepath.Join(dir, cdsconfig.ConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, image := range pinned.Images {
		if string(image.LaunchFile) != string(launchFile) {
			t.Errorf("entry %q binds another launch file than the cluster's CDS configuration", image.Name)
		}
	}
	server, _ := readBundleDocument(t, dir, serverDir)
	if server.CDS.Measurements == agent.CDS.Measurements {
		t.Error("the server document changed; nothing it booted with may change")
	}
	stageBundleNode(t, dir, "rolled")
}

func TestAddAgentRefusesAPinDecreeTheBundleDoesNotAnswerFor(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := runBundleCmd(t, append(bundleArgs(t, dir, "tdx"), "--server-address", "10.0.0.10")...); err != nil {
		t.Fatal(err)
	}
	key := bundleOperatorKey(t, dir)
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	refused := map[string]struct {
		decree string
		says   string
	}{
		"another key": {
			decree: writePinDecree(t, dir, "demo", stranger, writeCDSManifest(t)),
			says:   "signature",
		},
		"another cluster": {
			decree: writePinDecree(t, dir, "elsewhere", key, writeCDSManifest(t)),
			says:   "cluster",
		},
	}
	for name, want := range refused {
		t.Run(name, func(t *testing.T) {
			err := runBundleCmd(t, "add-agent", "--bundle", dir, "--name", "late", "--pin-decree", want.decree)
			if err == nil || !strings.Contains(err.Error(), want.says) {
				t.Fatalf("add-agent took a decree of %s = %v", name, err)
			}
			if _, err := os.Stat(filepath.Join(dir, "late")); err == nil {
				t.Error("a refused decree left a node document behind")
			}
		})
	}
}

// A node added after an image was retired must not take a decree that still
// named it, so its document carries the applied decree's version as its floor.
func TestAddAgentTakesItsPinFloorFromTheAppliedDecree(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := runBundleCmd(t, append(bundleArgs(t, dir, "tdx"), "--server-address", "10.0.0.10")...); err != nil {
		t.Fatal(err)
	}
	decree := writePinDecree(t, dir, "demo", bundleOperatorKey(t, dir), writeRolledCDSManifest(t))

	if err := runBundleCmd(t, "add-agent", "--bundle", dir, "--name", "retired", "--pin-decree", decree); err != nil {
		t.Fatal(err)
	}

	agent, _ := readBundleDocument(t, dir, "retired")
	if agent.CDS.PinFloor != appliedPinVersion {
		t.Fatalf("pin floor = %d, want the version the decree applies at", agent.CDS.PinFloor)
	}
	server, _ := readBundleDocument(t, dir, serverDir)
	if server.CDS.PinFloor != 0 {
		t.Fatalf("the server document's pin floor = %d; nothing it booted with may change", server.CDS.PinFloor)
	}
}
