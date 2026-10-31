package cdsdecree

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
