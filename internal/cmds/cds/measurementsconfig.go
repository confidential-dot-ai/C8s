package cds

import (
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// servedFamily names the platform the served document declares. The flat flags
// carry no platform of their own, so it comes from the one CDS attests on.
func servedFamily(armtlsPlatform string) teetypes.Family {
	if fam, err := teetypes.ParseFamily(armtlsPlatform); err == nil {
		return fam
	}
	return teetypes.FamilySNP
}

// pinsGuestCode reports whether every guest these pins name also pins a
// runtime measurement register. On TDX the launch measurement is the MRTD,
// which covers TDVF firmware alone: the guest kernel measures into RTMR[1] and
// the command line carrying the dm-verity root hash into RTMR[2]. A TDX pin set
// naming no register therefore names firmware, and a host may boot the pinned
// MRTD with substituted guest software.
//
// Image pins replace the flat register map at verification
// (remote.EnforcePins), so each image answers for its own registers.
func pinsGuestCode(pins armtls.Pins) bool {
	if len(pins.Images) == 0 {
		return len(pins.Registers) > 0
	}
	for _, image := range pins.Images {
		if len(image.Registers) == 0 {
			return false
		}
	}
	return true
}
