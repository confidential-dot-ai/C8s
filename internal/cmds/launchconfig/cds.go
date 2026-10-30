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

// CDSPort is the port this cluster's CDS serves on, which is what a pod
// ruleset admits outside the cluster for its credential clients. A document
// naming its CDS by address holds that address to one a node can dial.
func (d *Document) CDSPort() (uint16, error) {
	host, port, err := cmdsutil.SplitCDSAddress(d.CDS.Address)
	if err != nil {
		return 0, fmt.Errorf("cds.address %w", err)
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if err := ValidateRoutableIPv4(address); err != nil {
			return 0, fmt.Errorf("cds.address %q: %w", host, err)
		}
	}
	return port, nil
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
	if _, err := d.CDSPort(); err != nil {
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
