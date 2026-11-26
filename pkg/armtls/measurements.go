package armtls

import (
	"fmt"
	"slices"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// Pins carries the shared evidence policy to C8s peer verifiers.
type Pins remote.Policy

// requirePins refuses a policy that names no guest. An empty set proves only
// that the peer is some TEE; registers and a TCB floor narrow a guest that a
// launch measurement or image pin already names.
func requirePins(p remote.Policy) error {
	if len(p.Measurements) == 0 && len(p.Images) == 0 {
		return ErrUnpinned
	}
	return nil
}

// VerifyPolicy adds the local attestation service to the shared policy.
func (p Pins) VerifyPolicy(url string) *VerifyPolicy {
	return &VerifyPolicy{
		Policy:            remote.Policy(p),
		AttestationApiURL: url,
	}
}

var imageRegisters = map[teetypes.Family][]int{
	teetypes.FamilySNP: {},
	teetypes.FamilyTDX: {1, 2},
}

// ImageRegisters are the registers that identify a guest image beyond its
// launch digest, and whether family measures a guest image at all. An SEV-SNP
// launch digest covers the guest image itself; a TDX MRTD covers the firmware
// and the guest measures into RTMR[1] and RTMR[2].
func ImageRegisters(family teetypes.Family) ([]int, bool) {
	registers, identified := imageRegisters[family]
	return registers, identified
}

// RequireImageRegisters refuses pins that leave a guest on family
// unidentified: every image must pin each register ImageRegisters names, since
// a launch digest alone admits any guest booted under the same firmware.
func RequireImageRegisters(family teetypes.Family, images []remote.ImagePin) error {
	registers, identified := ImageRegisters(family)
	if !identified {
		return fmt.Errorf("family %q has no guest image identity to pin", family)
	}
	for _, image := range images {
		if index, unpinned := firstUnpinned(image, registers); unpinned {
			return fmt.Errorf("pin %q leaves RTMR[%d] unpinned, and a %s launch digest covers the firmware alone", image.Name, index, family)
		}
	}
	return nil
}

func firstUnpinned(image remote.ImagePin, registers []int) (int, bool) {
	for _, index := range registers {
		if _, pinned := image.Registers[index]; !pinned {
			return index, true
		}
	}
	return 0, false
}

// EnforceImages is [remote.EnforceImagesWithRuntimeLog] with every Anchor or
// LaunchFileDigest pin accepting any runtime extension that replays. It does
// not judge which digests the peer measured: that is an external verifier's
// job (c8s verify --pin-policy, --trust-operator), and docs/armtls.md says why
// it is a non-goal here. claimed is the peer's list, nil for none, and is refused
// beyond [MaxRuntimeExtensions] entries since each costs a hash.
func EnforceImages(resp remote.VerifyResponse, images []remote.ImagePin, platform teetypes.PlatformType, claimed []string) error {
	if len(claimed) > MaxRuntimeExtensions {
		return fmt.Errorf("%w: %d runtime extensions, at most %d allowed", remote.ErrAnchorNotAllowed, len(claimed), MaxRuntimeExtensions)
	}
	return remote.EnforceImagesWithRuntimeLog(resp, acceptReplayed(images), platform, claimed)
}

// acceptReplayed returns a copy of images whose Anchor and LaunchFileDigest
// pins without an AcceptExtension hook accept every extension.
func acceptReplayed(images []remote.ImagePin) []remote.ImagePin {
	out := slices.Clone(images)
	for i := range out {
		// A pin read from MRCONFIGID replays nothing, and the matcher refuses a
		// hook on one.
		replays := out[i].Anchor != nil || (out[i].LaunchFileDigest != nil && !out[i].LaunchFileInInitData)
		if replays && out[i].AcceptExtension == nil {
			out[i].AcceptExtension = func(string) error { return nil }
		}
	}
	return out
}
