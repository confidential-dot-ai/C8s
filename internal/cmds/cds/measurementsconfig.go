package cds

import (
	"encoding/hex"
	"sort"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// servedFamily names the platform the served document declares. The flat flags
// carry no platform of their own, so it comes from the one CDS attests on.
func servedFamily(armtlsPlatform string) teetypes.Family {
	if fam, err := teetypes.ParseFamily(armtlsPlatform); err == nil {
		return fam
	}
	return teetypes.FamilySNP
}

// measurementBytes decodes the flat allowlist back into digests for the
// served document. Images that are not hex never reached a gate either.
func measurementBytes(allowed map[string]bool) [][]byte {
	out := make([][]byte, 0, len(allowed))
	for m := range allowed {
		if b, err := hex.DecodeString(m); err == nil {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out
}
