//go:build linux

package armtlsmesh

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// resolveMeasurementsConfig loads whole peer identities. Without a separate
// CDS config the same set is accepted for both purposes.
func resolveMeasurementsConfig(c *proxyConfig) (refvalues.ReferenceValues, error) {
	if c.measurementsConfig == "" && c.cdsMeasurementsConfig == "" {
		return refvalues.ReferenceValues{}, nil
	}
	if c.cdsMeasurements != "" || c.cdsRTMRs != "" {
		return refvalues.ReferenceValues{}, fmt.Errorf("measurements configs cannot be combined with --cds-measurements or --cds-rtmrs")
	}
	var peers refvalues.ReferenceValues
	if c.measurementsConfig != "" {
		var err error
		peers, err = (cmdsutil.ImagePolicySource{File: c.measurementsConfig}).LoadValues(
			cmdsutil.MeasurementPinsFromStrings(c.measurements, c.rtmrs, ""))
		if err != nil {
			return refvalues.ReferenceValues{}, err
		}
	}
	cds := peers
	if c.cdsMeasurementsConfig != "" {
		var err error
		cds, err = (cmdsutil.ImagePolicySource{File: c.cdsMeasurementsConfig}).LoadValues(cmdsutil.MeasurementPins{})
		if err != nil {
			return refvalues.ReferenceValues{}, fmt.Errorf("--cds-image-policy-file: %w", err)
		}
		if !peers.Empty() && peers.Family != cds.Family {
			return refvalues.ReferenceValues{}, fmt.Errorf("peer and CDS measurements configs declare different TEEs")
		}
	}
	if !peers.Empty() {
		c.measurements, c.rtmrs = flatPins(peers)
	}
	c.cdsMeasurements, c.cdsRTMRs = flatPins(cds)
	c.cdsPins = cds
	slog.Info("measurements configs loaded", "peer_identities", len(peers.Images), "cds_identities", len(cds.Images))
	return peers, nil
}

// flatPins supplies digest/register diagnostics; verification keeps the entries.
func flatPins(set refvalues.ReferenceValues) (string, string) {
	digests, common, _ := set.Flatten()
	return strings.Join(digests, ","), strings.Join(refvalues.FormatRegisterPins(common), ",")
}

// checkTEEMatchesPlatform reports a config written for the other platform. It
// runs after --platform=auto has probed the guest devices, so the comparison
// is against the platform this proxy actually attests on.
func checkTEEMatchesPlatform(set refvalues.ReferenceValues, teeType armtls.TEEType) error {
	if set.Empty() {
		return nil
	}
	var platform teetypes.Family
	switch teeType {
	case armtls.TEETypeSEVSNP:
		platform = teetypes.FamilySNP
	case armtls.TEETypeTDX:
		platform = teetypes.FamilyTDX
	default:
		return nil
	}
	if set.Family != platform {
		return fmt.Errorf("--image-policy-file declares tee %q but this node attests as %q", set.Family, platform)
	}
	return nil
}
