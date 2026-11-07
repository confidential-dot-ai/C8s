// The generator side of a CDS launch file: what an operator's tooling puts
// into one and the rules it checks before writing it.

package cdsconfig

import (
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/launchfile/cds"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// The pair an operator launches and verifies a CDS VM with, named the same by
// every generator that writes them.
const (
	ConfigFile = cds.ConfigFile
	PinFile    = cds.PinFile
)

// Document is one cluster's CDS settings as a launch file carries them.
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
	// HA is the replica set the cluster's CDS runs as; a zero one the singleton.
	HA HA
}

// Format renders doc as a CDS launch file, and only what Parse accepts back.
func Format(doc Document) ([]byte, error) {
	workloads, err := doc.Workloads.Canonical()
	if err != nil {
		return nil, fmt.Errorf("workloads: %w", err)
	}
	data, err := cds.Format(cds.Document{
		ClusterID:          doc.ClusterID,
		OperatorPublicKeys: doc.OperatorKeys.PEM(),
		Workloads:          workloads,
		Nodes:              doc.Nodes,
		NodeCIDRs:          doc.NodeCIDRs,
		LeafDNSNames:       doc.LeafDNSNames,
		LeafDNSPatterns:    doc.LeafDNSPatterns,
		HA:                 doc.HA,
	})
	if err != nil {
		return nil, err
	}
	if _, err := Parse(data); err != nil {
		return nil, fmt.Errorf("rendered CDS config: %w", err)
	}
	return data, nil
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

// CheckNodeSubnets is cds.CheckNodeSubnets.
func CheckNodeSubnets(
	nodeCIDRs []string,
	clusterCIDRs []string,
) error {
	return cds.CheckNodeSubnets(nodeCIDRs, clusterCIDRs)
}
