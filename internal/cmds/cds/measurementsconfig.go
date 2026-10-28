package cds

import (
	"encoding/hex"
	"sort"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
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

// loadNodePins is the node launch identities CDS admits on /attest and serves
// on /measurements: the measured configuration's document, else the one the
// flags name. A flagged document must declare the platform flag's family,
// while a CDS VM reads its own family from its hardware and the nodes it
// serves need not share it.
func loadNodePins(cfg config) (refvalues.ReferenceValues, error) {
	if cfg.measured != nil {
		return cfg.measured.Nodes, nil
	}
	return cmdsutil.LoadImagePolicyValues(cmdsutil.ImagePolicyValuesConfig{
		Source: cmdsutil.ImagePolicySource{File: cfg.measurementsConfig},
		Pins: cmdsutil.MeasurementPins{
			Measurements: cfg.measurements,
			Registers:    cfg.rtmrs,
		},
		Platform:     cfg.armtlsPlatform,
		PlatformFlag: "--armtls-platform",
	})
}
