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
	// Address is the <host>:<port> this cluster's CDS serves on, the host a
	// DNS name its clients resolve or the IPv4 address they dial as it
	// stands. A pod ruleset admits that port outside the cluster for this
	// cluster's credential clients.
	Address string `yaml:"address" json:"address"`
	// Measurements is one measurements JSON document, as `launch-config new`
	// and `c8s cds config new` write it: every entry binds the CDS image to
	// its launch file.
	Measurements string `yaml:"measurements" json:"measurements"`
}

// CDSAddress is where this cluster's CDS serves, as the document names it:
// the host its clients dial and the port a pod ruleset admits for them
// outside the cluster.
func (d *Document) CDSAddress() (cmdsutil.CDSAddress, error) {
	address, err := cmdsutil.ParseCDSAddress(d.CDS.Address)
	if err != nil {
		return cmdsutil.CDSAddress{}, fmt.Errorf("cds.address %w", err)
	}
	return address, nil
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

// validateCDS requires the endpoint this cluster's clients dial and a pin
// that is an identity for one VM: every entry bound to the exact launch file
// it boots.
func (d *Document) validateCDS() error {
	address, err := d.CDSAddress()
	if err != nil {
		return err
	}
	if err := validateCDSLiteral(address); err != nil {
		return err
	}
	pins, err := refvalues.Parse([]byte(d.CDS.Measurements))
	if err != nil {
		return fmt.Errorf("cds.measurements: %w", err)
	}
	if _, err := cmdsutil.CDSLaunchFile(pins); err != nil {
		return fmt.Errorf("cds.measurements %w", err)
	}
	return nil
}

// validateCDSLiteral holds a CDS named by address to one a node's pods can
// reach: a routable unicast address, and one outside the ranges their packet
// rules never carry that port to. A CDS named by a DNS name is whatever the
// nodes resolve it to.
func validateCDSLiteral(address cmdsutil.CDSAddress) error {
	literal, named := address.Literal()
	if !named {
		return nil
	}
	if err := ValidateRoutableIPv4(literal); err != nil {
		return fmt.Errorf("cds.address %q: %w", address.Host, err)
	}
	for _, raw := range clusterRanges {
		if in := netip.MustParsePrefix(raw); in.Contains(literal) {
			return fmt.Errorf("cds.address %s is inside this cluster's own range %s, which no pod reaches outside the mesh", address.Host, in)
		}
	}
	return nil
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
