package cdsdecree

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// A decree carries the pins without the launch file, which every reader fills
// in from the file it already holds, so one decree stays small whatever the
// configuration's size.
func TestPinsTravelWithoutTheLaunchFileAndComeBackWithIt(t *testing.T) {
	document := cdsImages(t, 0x11)
	pins, err := NewPinDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(pins.Images.json, []byte("launch_file")) {
		t.Fatalf("the decree carries the launch file: %s", pins.Images.json)
	}
	digest := sha256.Sum256([]byte(launchFile))
	if pins.LaunchFileSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("launch_file_sha256 = %q", pins.LaunchFileSHA256)
	}
	filled, err := pins.WithLaunchFile([]byte(launchFile))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := refvalues.Parse(document)
	if err != nil {
		t.Fatal(err)
	}
	if !equalImages(filled, signed) {
		t.Fatalf("filled pins %+v, want %+v", filled.Images, signed.Images)
	}
}

// A reader holding another configuration is not the cluster the operator
// signed these images for.
func TestPinsRefuseAnotherLaunchFile(t *testing.T) {
	pins, err := NewPinDocument(cdsImages(t, 0x11))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pins.WithLaunchFile([]byte(launchFile + "\n")); err == nil {
		t.Fatal("pins bound to another launch file were filled in")
	}
}

// One CDS pin names one cluster's CDS, so every entry binds the same launch
// file and the digest names it.
func TestPinsBindOneLaunchFile(t *testing.T) {
	for _, tc := range []struct {
		name   string
		images []remote.ImagePin
	}{
		{"no launch file", []remote.ImagePin{{Name: "cds", Digest: register(0x11)}}},
		{"two launch files", []remote.ImagePin{
			{Name: "cds-smp2", Digest: register(0x11), LaunchFile: []byte(launchFile)},
			{Name: "cds-smp4", Digest: register(0x22), LaunchFile: []byte("other")},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document, err := refvalues.Format(refvalues.ReferenceValues{Family: teetypes.FamilySNP, Images: tc.images})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewPinDocument(document); err == nil {
				t.Fatal("a pin document naming no one CDS was carried into a decree")
			}
		})
	}
}

// launch_file_sha256 is the only launch binding a decree's pins carry, so an
// entry carrying one of its own is refused rather than silently kept.
func TestDecreePinsCarryNoLaunchBindingOfTheirOwn(t *testing.T) {
	key, keys := operatorKey(t)
	d := complete(t, UpdateMeasurements)
	d.CDSPins = &PinDocument{
		Images:           ElidedImages{document{json: cdsImages(t, 0x11)}},
		LaunchFileSHA256: d.CDSPins.LaunchFileSHA256,
	}
	if err := verifySigned(t, key, keys, d); err == nil {
		t.Fatal("a decree whose entries bind their own launch file verified")
	}
}

func TestDecreePinsNameTheirLaunchFileAsADigest(t *testing.T) {
	key, keys := operatorKey(t)
	for _, tc := range []struct {
		name   string
		digest string
	}{
		{"empty", ""},
		{"short", strings.Repeat("ab", 16)},
		{"not hex", strings.Repeat("zz", 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := complete(t, UpdateMeasurements)
			d.CDSPins.LaunchFileSHA256 = tc.digest
			if err := verifySigned(t, key, keys, d); err == nil {
				t.Fatalf("a decree naming launch file %q verified", tc.digest)
			}
		})
	}
}

// A node pin set is a document of its own, which the cluster certifies nodes
// by, so only a document its parser reads reaches a decree.
func TestDecreeNodePinsAreADocument(t *testing.T) {
	if _, err := NewNodeImages([]byte(`{"schema_version":"1","tee":"sev-snp","measurements":[]}`)); err == nil {
		t.Fatal("a document pinning no node image was carried into a decree")
	}
	key, keys := operatorKey(t)
	d := complete(t, Genesis)
	d.NodePins = &NodeImages{document{json: []byte(`{"tee":"nothing"}`)}}
	if err := verifySigned(t, key, keys, d); err == nil {
		t.Fatal("a decree carrying no node pin document verified")
	}
}

// A node entry certifies its image only as launched with what it binds. A new
// set must bind every entry, and a decree carrying one that does not still
// verifies, so a cluster replays a log that already holds it.
func TestRequireLaunchBindingsCoversEveryEntry(t *testing.T) {
	key, keys := operatorKey(t)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	launchKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	launched := []byte("schemaVersion: c8s-worker/v1\n")
	digest := sha256.Sum256(launched)
	bound := []remote.ImagePin{
		{Name: "anchor", Digest: register(0x21), Anchor: launchKey},
		{Name: "launch file", Digest: register(0x22), LaunchFile: launched},
		{Name: "launch file digest", Digest: register(0x23), LaunchFileDigest: digest[:]},
	}
	unbound := remote.ImagePin{Name: "unbound", Digest: register(0x24)}
	for _, tc := range []struct {
		name    string
		images  []remote.ImagePin
		wantErr bool
	}{
		{"every binding", bound, false},
		{"an entry binding nothing", append(slices.Clone(bound), unbound), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			measurements, err := refvalues.Format(refvalues.ReferenceValues{Family: teetypes.FamilySNP, Images: tc.images})
			if err != nil {
				t.Fatal(err)
			}
			images, err := NewNodeImages(measurements)
			if err != nil {
				t.Fatal(err)
			}
			if err := images.RequireLaunchBindings(); (err != nil) != tc.wantErr {
				t.Errorf("RequireLaunchBindings = %v, want error %v", err, tc.wantErr)
			}
			d := complete(t, SetNodeImages)
			d.NodePins = images
			if err := verifySigned(t, key, keys, d); err != nil {
				t.Errorf("Verify = %v, want a decree a cluster already logged to verify", err)
			}
		})
	}
}

func register(b byte) []byte {
	return bytes.Repeat([]byte{b}, refvalues.DigestSize)
}

func equalImages(got, want refvalues.ReferenceValues) bool {
	if got.Family != want.Family || len(got.Images) != len(want.Images) {
		return false
	}
	for i, image := range got.Images {
		other := want.Images[i]
		if image.Name != other.Name || !bytes.Equal(image.Digest, other.Digest) || !bytes.Equal(image.LaunchFile, other.LaunchFile) {
			return false
		}
	}
	return true
}
