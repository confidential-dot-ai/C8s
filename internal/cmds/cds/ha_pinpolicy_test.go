package cds

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// Signed with the key this cluster's configuration pins.
func (c operatorCluster) signedDecree(t *testing.T, d cdsdecree.Decree) cdsdecree.Signed {
	t.Helper()
	key, err := certutil.LoadECPrivateKeyFile(c.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	d.ClusterID = c.clusterID
	d.IntentID = cdsdecree.NewIntentID()
	d.ExpiresAt = time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	signed, err := cdsdecree.Sign(d, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// Both CDS images a cluster accepts while it rolls.
func (c operatorCluster) rollPins(t *testing.T) *cdsdecree.PinDocument {
	t.Helper()
	pins, err := pinFlags{
		platform:  "sev-snp",
		vcpus:     []int{2, 4},
		manifests: []string{snpManifest(t, smp2Digest, smp4Digest)},
	}.document(c.config)
	if err != nil {
		t.Fatal(err)
	}
	return pins
}

func TestPinPolicyWritesThePinDocumentTheDecreeMakes(t *testing.T) {
	c := newReplicatedCluster(t)
	decreed := c.signedDecree(t, cdsdecree.Decree{
		Kind:        cdsdecree.UpdateMeasurements,
		BaseVersion: 3,
		CDSPins:     c.rollPins(t),
	})
	out := filepath.Join(t.TempDir(), "cds-pin.json")
	decreeOut := filepath.Join(t.TempDir(), "pin-decree.json")
	o := pinPolicyOptions{
		out:       out,
		decreeOut: decreeOut,
	}
	replicas := c.replicasServing(t, map[string]any{pinDecreePath: decreed})

	printed, err := reading(t, func(cmd *cobra.Command) error { return o.report(cmd, c.decreed(t), replicas) })
	if err != nil {
		t.Fatalf("pin-policy on the decree the cluster applied: %v", err)
	}
	if !strings.Contains(printed, "base_version=3 images=2") {
		t.Errorf("pin-policy reports %q, want the version the decree applied on and its images", strings.TrimSpace(printed))
	}
	pins, err := refvalues.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(pins.Images) != 2 {
		t.Fatalf("the pin document names %d images, want the two the decree does", len(pins.Images))
	}
	for _, image := range pins.Images {
		if string(image.LaunchFile) != string(c.config) {
			t.Errorf("entry %q binds another launch file than the one the replicas boot", image.Name)
		}
	}
	handed, err := os.ReadFile(decreeOut)
	if err != nil {
		t.Fatal(err)
	}
	written, err := cdsdecree.Parse(handed)
	if err != nil {
		t.Fatal(err)
	}
	if written.Signature != decreed.Signature {
		t.Error("the decree handed on is not the one the operator signed")
	}
}

func TestPinPolicyRefusesADecreeTheConfigurationDoesNotAnswerFor(t *testing.T) {
	c := newReplicatedCluster(t)
	elsewhere := newReplicatedCluster(t)
	otherLaunchFile, err := pinFlags{
		platform:  "sev-snp",
		vcpus:     []int{2},
		manifests: []string{snpManifest(t, smp2Digest)},
	}.document([]byte("a launch file no replica of this cluster boots"))
	if err != nil {
		t.Fatal(err)
	}
	for name, served := range map[string]any{
		"a key the configuration does not pin": elsewhere.signedDecree(t, cdsdecree.Decree{
			Kind:        cdsdecree.UpdateMeasurements,
			BaseVersion: 3,
			CDSPins:     elsewhere.rollPins(t),
		}),
		"another launch file": c.signedDecree(t, cdsdecree.Decree{
			Kind:        cdsdecree.UpdateMeasurements,
			BaseVersion: 3,
			CDSPins:     otherLaunchFile,
		}),
		"no CDS image": c.signedDecree(t, cdsdecree.Decree{
			Kind:        cdsdecree.RotateKey,
			BaseVersion: 3,
		}),
	} {
		t.Run(name, func(t *testing.T) {
			replicas := c.replicasServing(t, map[string]any{pinDecreePath: served})
			report := func(cmd *cobra.Command) error { return pinPolicyOptions{}.report(cmd, c.decreed(t), replicas) }
			if _, err := reading(t, report); err == nil {
				t.Fatalf("pin-policy took a decree carrying %s as this cluster's", name)
			}
		})
	}
}
