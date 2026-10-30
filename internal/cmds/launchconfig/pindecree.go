// A node document's CDS pin after a CDS image roll: the images of the pin
// decree the cluster's replicas applied. The decree carries the operator's
// signature over the image set and the digest of the launch file those images
// boot, so this check stands on its own against the bundle's CDS
// configuration.

package launchconfig

import (
	"fmt"
	"path/filepath"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// decreedCDS holds a node's CDS to the images the applied pin decree names,
// from the version it applies at, so a decree below that never replaces this
// set. The bundle's configuration names the cluster and the keys a decree for
// it is signed with, so another cluster's decree is refused here, not at a
// node.
func decreedCDS(dir, decreePath, address string) (CDS, error) {
	launchFile, err := readBounded(filepath.Join(dir, cdsconfig.ConfigFile), MaxDocumentSize)
	if err != nil {
		return CDS{}, fmt.Errorf("bundle CDS configuration: %w", err)
	}
	cluster, err := cdsconfig.Parse(launchFile)
	if err != nil {
		return CDS{}, fmt.Errorf("bundle CDS configuration: %w", err)
	}
	object, err := readBounded(decreePath, MaxDocumentSize)
	if err != nil {
		return CDS{}, fmt.Errorf("pin decree: %w", err)
	}
	applied, err := cdsdecree.Parse(object)
	if err != nil {
		return CDS{}, fmt.Errorf("pin decree: %w", err)
	}
	if err := cdsdecree.Verify(applied, cluster.OperatorKeys.Keys(), cluster.ClusterID); err != nil {
		return CDS{}, fmt.Errorf("pin decree: %w", err)
	}
	if applied.Decree.CDSPins == nil {
		return CDS{}, fmt.Errorf("pin decree: a %s decree pins no CDS image", applied.Decree.Kind)
	}
	pins, err := applied.Decree.CDSPins.WithLaunchFile(launchFile)
	if err != nil {
		return CDS{}, fmt.Errorf("pin decree: %w", err)
	}
	document, err := refvalues.Format(pins)
	if err != nil {
		return CDS{}, err
	}
	return CDS{
		Address:      address,
		Measurements: string(document),
		PinFloor:     applied.Decree.AppliesAt(),
	}, nil
}
