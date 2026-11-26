// Package worker is the worker document: the launch file of a CVM that runs a
// cluster's workloads while the cluster's Kubernetes control plane runs
// outside every TEE. The document's whole bytes are the worker's init data;
// it carries no signature and no launch key.
package worker

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/issuer"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/taconfig"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/yamlutil"
)

const SchemaVersion = "c8s-worker/v1"

// MaxDocumentSize bounds a document read off the launch disk, whose bytes the
// host writes: a worker reads the document before anything has vouched for it.
const MaxDocumentSize = 1024 * 1024

// Document is the worker.yaml wire contract.
type Document struct {
	SchemaVersion string `yaml:"schemaVersion"`
	// Trust Authority is where this cluster's Trust Authority listens and the pin binding the
	// configuration it runs on.
	TA cmdsutil.TA `yaml:"ta"`
	// TLSSAN is the DNS name of the router's front-door certificate, which
	// the Trust Authority signs onto its leaf.
	TLSSAN string `yaml:"tlsSAN"`
	// Router selects the router's public hostnames and front-door limits;
	// nil when the document sets none.
	Router     *nodeservices.Router `yaml:"router,omitempty"`
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
	ta, err := d.TA.Parse()
	if err != nil {
		return err
	}
	config, err := taconfig.Parse(ta.LaunchFile)
	if err != nil {
		return fmt.Errorf("ta.measurements: the pinned Trust Authority configuration: %w", err)
	}
	nodeSubnets, err := pinnedNodeSubnets(config)
	if err != nil {
		return err
	}
	if err := cmdsutil.ValidateHostname(d.TLSSAN); err != nil {
		return fmt.Errorf("tlsSAN %w", err)
	}
	if !(issuer.CSRPolicy{DNSSANPatterns: config.DNSSANPatterns}).AdmitsDNSName(d.TLSSAN) {
		return fmt.Errorf("tlsSAN %q is not a DNS name the pinned Trust Authority configuration lets a leaf carry", d.TLSSAN)
	}
	if _, err := d.router().Validate(); err != nil {
		return err
	}
	return d.Kubernetes.validate(nodeSubnets)
}

// router is the document's router block; the zero block is a document with
// none.
func (d Document) router() nodeservices.Router {
	if d.Router == nil {
		return nodeservices.Router{}
	}
	return *d.Router
}

// operatorKeys are the pinned Trust Authority configuration's operator keys, PEM-encoded:
// the keys the router verifies route manifests under.
func (d Document) operatorKeys() ([]byte, error) {
	ta, err := d.TA.Parse()
	if err != nil {
		return nil, err
	}
	config, err := taconfig.Parse(ta.LaunchFile)
	if err != nil {
		return nil, fmt.Errorf("ta.measurements: the pinned Trust Authority configuration: %w", err)
	}
	return config.OperatorKeys.PEM(), nil
}

// pinnedNodeSubnets are the subnets the pinned Trust Authority configuration may dial a
// node in.
func pinnedNodeSubnets(config *taconfig.Config) ([]netip.Prefix, error) {
	subnets := make([]netip.Prefix, 0, len(config.NodeCIDRs))
	for _, subnet := range config.NodeCIDRs {
		prefix, err := subnetPrefix(subnet)
		if err != nil {
			return nil, fmt.Errorf("ta.measurements: the pinned Trust Authority configuration: %w", err)
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
