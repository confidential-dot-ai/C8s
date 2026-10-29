// The generator side of a CDS launch file: what an operator's tooling puts
// into one and the rules it checks before writing it.

package cdsconfig

import (
	"errors"
	"fmt"
	"net/netip"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// The pair an operator launches and verifies a CDS VM with, named the same by
// every generator that writes them.
const (
	ConfigFile = "cds-config.yaml"
	PinFile    = "cds-pin.json"
)

// Document is one cluster's CDS settings as a launch file carries them: each
// embedded policy the exact bytes its own parser reads.
type Document struct {
	ClusterID string
	// OperatorKeys authorize policy writes.
	OperatorKeys operatorauth.KeyBundle
	// Workloads is the cluster's allowlist, as MergeWorkloads builds it.
	Workloads *allowlist.Allowlist
	// Nodes is the measurements document pinning the nodes CDS admits.
	Nodes []byte
	// NodeCIDRs are the subnets CDS may call a sandbox inventory on.
	NodeCIDRs []string
	// LeafDNSNames and LeafDNSPatterns are the DNS SAN rules CDS issues under.
	LeafDNSNames    []string
	LeafDNSPatterns []string
}

// Format renders doc as a CDS launch file under the schema version this
// package parses, and only what Parse accepts back.
func Format(doc Document) ([]byte, error) {
	rendered, err := doc.wire()
	if err != nil {
		return nil, err
	}
	data, err := yaml.Marshal(rendered)
	if err != nil {
		return nil, fmt.Errorf("render CDS config: %w", err)
	}
	if _, err := Parse(data); err != nil {
		return nil, fmt.Errorf("rendered CDS config: %w", err)
	}
	return data, nil
}

func (d Document) wire() (wire, error) {
	workloads, err := d.Workloads.Canonical()
	if err != nil {
		return wire{}, fmt.Errorf("workloads: %w", err)
	}
	return wire{
		SchemaVersion:      SchemaVersion,
		ClusterID:          d.ClusterID,
		OperatorPublicKeys: string(d.OperatorKeys.PEM()),
		Workloads:          string(workloads),
		Nodes:              string(d.Nodes),
		NodeCIDRs:          d.NodeCIDRs,
		LeafDNSNames:       d.LeafDNSNames,
		LeafDNSPatterns:    d.LeafDNSPatterns,
	}, nil
}

// MergeWorkloads builds the document's allowlist: the cluster's component
// entries with the tenant's workloads added. A tenant entry may not take a
// component entry's name. A nil tenant document means a cluster running
// components only; empty bytes are a document that does not parse.
func MergeWorkloads(components, tenant []byte) (*allowlist.Allowlist, error) {
	merged, err := allowlist.ParseJSON(components)
	if err != nil {
		return nil, fmt.Errorf("component entries: %w", err)
	}
	if tenant != nil {
		if err := addTenantWorkloads(merged, tenant); err != nil {
			return nil, err
		}
	}
	return merged, nil
}

func addTenantWorkloads(merged *allowlist.Allowlist, tenant []byte) error {
	extra, err := allowlist.ParseJSON(tenant)
	if err != nil {
		return fmt.Errorf("tenant workloads: %w", err)
	}
	if merged.Workloads == nil {
		merged.Workloads = make(map[string]allowlist.Workload, len(extra.Workloads))
	}
	for name, workload := range extra.Workloads {
		if _, taken := merged.Workloads[name]; taken {
			return fmt.Errorf("tenant workload %q is a component entry", name)
		}
		merged.Workloads[name] = workload
	}
	return nil
}

// CheckNodeSubnets refuses a node subnet overlapping one of the cluster's pod
// or service ranges: CDS dials a node address for a sandbox's admission
// inventory, and a pod inside that bound could answer as one. A generator
// applies it, holding the ranges the document does not carry.
func CheckNodeSubnets(nodeCIDRs, clusterCIDRs []string) error {
	if len(clusterCIDRs) == 0 {
		return errors.New("the cluster's pod and service ranges are required to check a node subnet against")
	}
	nodes, err := parsePrefixes("nodeCIDRs", nodeCIDRs)
	if err != nil {
		return err
	}
	cluster, err := parsePrefixes("cluster ranges", clusterCIDRs)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		for _, inCluster := range cluster {
			if node.Overlaps(inCluster) {
				return fmt.Errorf("node subnet %s overlaps the cluster range %s", node, inCluster)
			}
		}
	}
	return nil
}

func parsePrefixes(field string, cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		out = append(out, prefix)
	}
	return out, nil
}
