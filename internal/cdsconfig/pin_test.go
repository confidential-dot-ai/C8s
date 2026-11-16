package cdsconfig

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

const (
	smp2Digest = "e7df3a8f1dbe619607154ce994c1f4d7299c539b120b5560e137f7787e4ece304f270c1444b47c863fde54bc863291d7"
	smp4Digest = "e0615da999afd20375d64ec9aaf0c480d6854198c01ed3e4157f881a96f635e532f7ad528ef69b408ef10319be5db106"
)

func snpManifest(t *testing.T) string {
	t.Helper()
	variant := func(smp int, digest string) string {
		return fmt.Sprintf(`{"smp":%d,"measurement":{"algorithm":"sha384","snp_launch_digest":%q}}`, smp, digest)
	}
	return writeManifest(t, fmt.Sprintf(`{"version":3,"build":{"platform":"snp"},"snp_variants":[%s,%s]}`,
		variant(2, smp2Digest), variant(4, smp4Digest)))
}

func tdxManifest(t *testing.T) string {
	t.Helper()
	register := strings.Repeat("ab", refvalues.DigestSize)
	return writeManifest(t, fmt.Sprintf(`{"version":3,"build":{"platform":"tdx"},"tdx":{"mrtd":%q,"rtmr1":%q,"rtmr2":%q}}`,
		register, register, register))
}

func writeManifest(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func parsePin(t *testing.T, document []byte) refvalues.ReferenceValues {
	t.Helper()
	pin, err := refvalues.Parse(document)
	if err != nil {
		t.Fatalf("Pin wrote a document refvalues refuses: %v", err)
	}
	return pin
}

// Every entry binds the launch file, so no vCPU shape of the image is pinned
// without the configuration it must have booted on.
func TestPinBindsTheLaunchFileToEachVCPUCount(t *testing.T) {
	config := []byte("schemaVersion: c8s-cds/v1\n")
	document, err := Pin(snpManifest(t), teetypes.FamilySNP, []int{2, 4}, config)
	if err != nil {
		t.Fatal(err)
	}
	pin := parsePin(t, document)
	if pin.Family != teetypes.FamilySNP || len(pin.Images) != 2 {
		t.Fatalf("pin = %+v", pin)
	}
	for i, want := range []string{smp2Digest, smp4Digest} {
		image := pin.Images[i]
		if fmt.Sprintf("%x", image.Digest) != want {
			t.Fatalf("images[%d] digest = %x", i, image.Digest)
		}
		if !bytes.Equal(image.LaunchFile, config) {
			t.Fatalf("images[%d] launch file = %q", i, image.LaunchFile)
		}
		if image.Anchor != nil {
			t.Fatalf("images[%d] also pins a launch key", i)
		}
	}
}

func TestPinRefusesWhatItCannotBind(t *testing.T) {
	snp, tdx := snpManifest(t), tdxManifest(t)
	config := []byte("schemaVersion: c8s-cds/v1\n")
	tests := []struct {
		name     string
		manifest string
		family   teetypes.Family
		vcpus    []int
		config   []byte
	}{
		{"no configuration to bind", snp, teetypes.FamilySNP, []int{2}, nil},
		{"a vCPU count the image lacks", snp, teetypes.FamilySNP, []int{2, 6}, config},
		{"no vCPU count on SEV-SNP", snp, teetypes.FamilySNP, nil, config},
		{"a vCPU count named twice", snp, teetypes.FamilySNP, []int{2, 2}, config},
		{"a vCPU count on TDX", tdx, teetypes.FamilyTDX, []int{4}, config},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Pin(tc.manifest, tc.family, tc.vcpus, tc.config); err == nil {
				t.Fatal("Pin wrote a document for an input it cannot bind")
			}
		})
	}
}

// RTMR[3] carries the launch-file binding and comes from no manifest, so a TDX
// entry pins the build's RTMR[1] and RTMR[2] only.
func TestPinOnTDXPinsTheBuildRegistersOnly(t *testing.T) {
	config := []byte("schemaVersion: c8s-cds/v1\n")
	document, err := Pin(tdxManifest(t), teetypes.FamilyTDX, nil, config)
	if err != nil {
		t.Fatal(err)
	}
	pin := parsePin(t, document)
	if pin.Family != teetypes.FamilyTDX || len(pin.Images) != 1 {
		t.Fatalf("pin = %+v", pin)
	}
	image := pin.Images[0]
	if !bytes.Equal(image.LaunchFile, config) {
		t.Fatalf("launch file = %q", image.LaunchFile)
	}
	if len(image.Registers) != 2 || image.Registers[1] == nil || image.Registers[2] == nil {
		t.Fatalf("registers = %v", image.Registers)
	}
}
