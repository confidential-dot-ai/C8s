package cdsconfig

import (
	"errors"
	"fmt"
	"slices"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// pinName names the CDS image in the pin document; entries are matched on
// their measurements, never on the name.
const pinName = "cds"

// ParsePlatform accepts a bare TEE family only: a cloud paravisor's launch
// binding carries no file for a pin to bind.
func ParsePlatform(platform string) (teetypes.Family, error) {
	switch platform {
	case string(teetypes.FamilySNP):
		return teetypes.FamilySNP, nil
	case string(teetypes.FamilyTDX):
		return teetypes.FamilyTDX, nil
	default:
		return "", fmt.Errorf("%q, want %s or %s", platform, teetypes.FamilySNP, teetypes.FamilyTDX)
	}
}

// Pin renders the measurements document a client verifies a CDS with: the
// image the CDS VM boots, bound to the launch file it boots on. One document
// covers one TEE family, the one the operator runs the CDS VM on. Only an SNP
// launch digest varies with the vCPU count; a TDX tuple holds for every VM
// shape and takes no count.
func Pin(manifestPath string, family teetypes.Family, vcpus []int, config []byte) ([]byte, error) {
	if len(config) == 0 {
		return nil, errors.New("a CDS pin binds a launch file: the configuration is empty")
	}
	images, err := refvalues.FromImageManifest(manifestPath, pinName, family)
	if err != nil {
		return nil, fmt.Errorf("CDS image manifest: %w", err)
	}
	if family == teetypes.FamilySNP {
		if images, err = snpVariants(images, vcpus); err != nil {
			return nil, err
		}
	} else if len(vcpus) > 0 {
		return nil, fmt.Errorf("vCPU counts select a launch digest on %s only, not on %s", teetypes.FamilySNP, family)
	}
	for i := range images {
		images[i].LaunchFile = slices.Clone(config)
	}
	return refvalues.Format(refvalues.ReferenceValues{
		Family: family,
		Images: images,
	})
}

// snpVariants takes one entry per vCPU count the CDS VM may boot with. A count
// the image was not built for is refused: the VM would boot and measure a
// digest nothing pins.
func snpVariants(images []remote.ImagePin, vcpus []int) ([]remote.ImagePin, error) {
	if len(vcpus) == 0 {
		return nil, fmt.Errorf("%s pins one launch digest per vCPU count: name the counts the CDS VM may boot with", teetypes.FamilySNP)
	}
	byName := make(map[string]remote.ImagePin, len(images))
	for _, image := range images {
		byName[image.Name] = image
	}
	out := make([]remote.ImagePin, 0, len(vcpus))
	taken := make(map[int]bool, len(vcpus))
	for _, count := range vcpus {
		if taken[count] {
			return nil, fmt.Errorf("vCPU count %d is named twice", count)
		}
		taken[count] = true
		image, built := byName[variantName(count)]
		if !built {
			return nil, fmt.Errorf("the CDS image manifest has no %s launch digest for %d vCPUs", teetypes.FamilySNP, count)
		}
		out = append(out, image)
	}
	return out, nil
}

// variantName is the name refvalues.FromImageManifest gives an SNP variant,
// which is the only place a manifest's vCPU count survives into a pin.
func variantName(vcpus int) string {
	return fmt.Sprintf("%s-smp%d", pinName, vcpus)
}
