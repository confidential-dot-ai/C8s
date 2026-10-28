package launchconfig

import (
	"fmt"
	"net/netip"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// CDS is the confidential data service a node's clients reach: where it
// listens and the measurements that authenticate it. It runs on a
// confidential VM of its own, so its TEE family is that VM's, not the
// family of the node reading the document.
type CDS struct {
	// Address is an IPv4 address and port, the one destination a pod
	// ruleset admits for this cluster's credential clients.
	Address string `yaml:"address" json:"address"`
	// Measurements is one measurements JSON document, as `launch-config new`
	// and `c8s cds config new` write it: every entry binds the CDS image to
	// its launch file.
	Measurements string `yaml:"measurements" json:"measurements"`
}

// CDSEndpoint is this cluster's CDS endpoint, which is what a pod ruleset
// names as a destination.
func (d *Document) CDSEndpoint() (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(d.CDS.Address)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("cds.address must be an IPv4 address and port: %w", err)
	}
	return endpoint, nil
}

// CDSPolicy is the measurements document a node's clients verify this
// cluster's CDS with.
func (d *Document) CDSPolicy() ([]byte, error) {
	pins, err := refvalues.Parse([]byte(d.CDS.Measurements))
	if err != nil {
		return nil, err
	}
	return refvalues.Format(pins)
}

// validateCDS requires the endpoint a ruleset admits and a pin that is an
// identity for one VM: every entry bound to the exact launch file it boots.
func (d *Document) validateCDS() error {
	endpoint, err := d.CDSEndpoint()
	if err != nil {
		return err
	}
	if err := ValidateRoutableIPv4(endpoint.Addr()); err != nil {
		return fmt.Errorf("cds.address: %w", err)
	}
	if endpoint.Port() == 0 {
		return fmt.Errorf("cds.address must name a port")
	}
	pins, err := refvalues.Parse([]byte(d.CDS.Measurements))
	if err != nil {
		return fmt.Errorf("cds.measurements: %w", err)
	}
	if !bindsEveryLaunchFile(pins) {
		return fmt.Errorf("cds.measurements must bind every entry to the CDS launch file")
	}
	return nil
}

// bindsEveryLaunchFile reports whether the set pins an image at all and binds
// every entry to the exact launch file of the VM it admits.
func bindsEveryLaunchFile(pins refvalues.ReferenceValues) bool {
	if len(pins.Images) == 0 {
		return false
	}
	for _, image := range pins.Images {
		if len(image.LaunchFile) == 0 {
			return false
		}
	}
	return true
}

// The pod and service ranges the node image's RKE2 configuration fixes, which
// a node subnet may not reach into.
//
// INVARIANT: equal to cluster-cidr and service-cidr in
// node-guest-image/c8s/mkosi.extra/etc/rancher/rke2/config.yaml, which
// TestClusterRangesMatchTheNodeImage checks.
var clusterRanges = []string{"10.52.0.0/16", "10.53.0.0/16"}

// clusterCDS renders the launch file of this cluster's CDS VM and the
// measurements document its clients hold it to. The configuration carries the
// cluster's component entries and tenant workloads, the launch identities CDS
// admits and serves, the subnets it may dial a sandbox inventory in, and the
// front-door name it signs onto a leaf; the pin binds those exact bytes.
func clusterCDS(opts BundleOptions, operatorPub string, peerPolicy []byte) (config, pin []byte, err error) {
	family, err := cdsconfig.ParsePlatform(opts.CDS.Platform)
	if err != nil {
		return nil, nil, fmt.Errorf("--cds-platform: %w", err)
	}
	components, err := readBounded(opts.CDS.AllowlistSeedPath, MaxDocumentSize)
	if err != nil {
		return nil, nil, fmt.Errorf("--cds-allowlist-seed: %w", err)
	}
	var tenant []byte
	if opts.CDS.TenantWorkloadsPath != "" {
		if tenant, err = readBounded(opts.CDS.TenantWorkloadsPath, MaxDocumentSize); err != nil {
			return nil, nil, fmt.Errorf("--tenant-workloads: %w", err)
		}
	}
	operatorKeys, err := operatorauth.ParseKeyBundle([]byte(operatorPub))
	if err != nil {
		return nil, nil, fmt.Errorf("the bundle's operator public key: %w", err)
	}
	return cdsconfig.Build(cdsconfig.Inputs{
		ClusterID:       opts.ClusterID,
		OperatorKeys:    operatorKeys,
		ComponentSeed:   components,
		TenantWorkloads: tenant,
		Nodes:           peerPolicy,
		NodeCIDRs:       opts.CDS.NodeCIDRs,
		ClusterCIDRs:    clusterRanges,
		LeafDNSNames:    []string{opts.TLSSAN},
		LeafDNSPatterns: []string{cmdsutil.ServiceDNSSANPattern},
		ManifestPath:    opts.CDS.ManifestPath,
		Family:          family,
		VCPUs:           opts.CDS.VCPUs,
	})
}
