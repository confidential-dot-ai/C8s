// Package worker is the worker document: the launch file of a CVM that runs a
// cluster's workloads while the cluster's Kubernetes control plane runs
// outside every TEE. The document's whole bytes are the worker's init data;
// it carries no signature and no launch key.
package worker

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/yamlutil"
)

const SchemaVersion = "c8s-worker/v1"

// Document is the worker.yaml wire contract.
type Document struct {
	SchemaVersion string `yaml:"schemaVersion"`
	// CDS is the block node launch documents carry: where the cluster's CDS
	// listens and the pin binding the configuration it runs on.
	CDS launchconfig.CDS `yaml:"cds"`
	// Router is the block server launch documents carry; nil when the
	// document has none.
	Router     *launchconfig.Router `yaml:"router,omitempty"`
	Kubernetes Kubernetes           `yaml:"kubernetes"`
}

// Kubernetes holds the cluster facts a worker joins its control plane with.
type Kubernetes struct {
	// APIServer is the API server's <host>:<port>.
	APIServer string `yaml:"apiServer"`
	// CACertificate is the one PEM certificate the API server's serving
	// certificate chains to.
	CACertificate string `yaml:"caCertificate"`
	PodCIDR       string `yaml:"podCIDR"`
	ServiceCIDR   string `yaml:"serviceCIDR"`
	// ClusterDNS is the cluster DNS Service's address in ServiceCIDR.
	ClusterDNS string `yaml:"clusterDNS"`
}

// Parse strictly decodes and validates a worker document. It authenticates
// nothing.
func Parse(data []byte) (*Document, error) {
	var doc Document
	if err := yamlutil.Decode(data, &doc); err != nil {
		return nil, fmt.Errorf("worker document: %w", err)
	}
	if err := doc.validate(); err != nil {
		return nil, fmt.Errorf("worker document: %w", err)
	}
	return &doc, nil
}

func (d Document) validate() error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schemaVersion must be %s", SchemaVersion)
	}
	if _, err := d.CDS.Port(); err != nil {
		return err
	}
	launchFile, err := d.CDS.LaunchFile()
	if err != nil {
		return err
	}
	nodeSubnets, err := pinnedNodeSubnets(launchFile)
	if err != nil {
		return err
	}
	if d.Router != nil {
		if err := d.Router.Validate(); err != nil {
			return err
		}
	}
	return d.Kubernetes.validate(nodeSubnets)
}

// pinnedNodeSubnets are the subnets the pinned CDS configuration may dial a
// node in, read by the CDS's own parser.
func pinnedNodeSubnets(launchFile []byte) ([]netip.Prefix, error) {
	config, err := cdsconfig.Parse(launchFile)
	if err != nil {
		return nil, fmt.Errorf("cds.measurements: the pinned CDS configuration: %w", err)
	}
	subnets := make([]netip.Prefix, 0, len(config.NodeCIDRs))
	for _, subnet := range config.NodeCIDRs {
		prefix, err := subnetPrefix(subnet)
		if err != nil {
			return nil, fmt.Errorf("cds.measurements: the pinned CDS configuration: %w", err)
		}
		subnets = append(subnets, prefix)
	}
	return subnets, nil
}

// subnetPrefix converts a parsed subnet, refusing one whose address and mask
// differ in length.
func subnetPrefix(subnet *net.IPNet) (netip.Prefix, error) {
	addr, ok := netip.AddrFromSlice(subnet.IP)
	ones, bits := subnet.Mask.Size()
	if !ok || addr.Unmap().BitLen() != bits {
		return netip.Prefix{}, fmt.Errorf("node subnet %s has an address and mask of different lengths", subnet)
	}
	return netip.PrefixFrom(addr.Unmap(), ones), nil
}
