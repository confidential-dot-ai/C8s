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

// The bundle's CDS configuration names the cluster and the operator keys a
// decree for it is signed with, so a decree of another cluster, or signed
// with another key, is refused here rather than at a node.
func decreedCDSPin(dir, decreePath string) ([]byte, error) {
	launchFile, err := readBounded(filepath.Join(dir, cdsconfig.ConfigFile), MaxDocumentSize)
	if err != nil {
		return nil, fmt.Errorf("bundle CDS configuration: %w", err)
	}
	cluster, err := cdsconfig.Parse(launchFile)
	if err != nil {
		return nil, fmt.Errorf("bundle CDS configuration: %w", err)
	}
	object, err := readBounded(decreePath, MaxDocumentSize)
	if err != nil {
		return nil, fmt.Errorf("pin decree: %w", err)
	}
	applied, err := cdsdecree.Parse(object)
	if err != nil {
		return nil, fmt.Errorf("pin decree: %w", err)
	}
	if err := cdsdecree.Verify(applied, cluster.OperatorKeys.Keys(), cluster.ClusterID); err != nil {
		return nil, fmt.Errorf("pin decree: %w", err)
	}
	if applied.Decree.CDSPins == nil {
		return nil, fmt.Errorf("pin decree: a %s decree pins no CDS image", applied.Decree.Kind)
	}
	pins, err := applied.Decree.CDSPins.WithLaunchFile(launchFile)
	if err != nil {
		return nil, fmt.Errorf("pin decree: %w", err)
	}
	return refvalues.Format(pins)
}
