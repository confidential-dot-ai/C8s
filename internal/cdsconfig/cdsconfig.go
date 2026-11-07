// Package cdsconfig builds a CDS VM's launch file and pin as `c8s cds config`
// writes them. The launch file itself is pkg/cdslaunchfile.
package cdsconfig

import (
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/cdslaunchfile"
)

const (
	SchemaVersion = cdslaunchfile.SchemaVersion
	ConfigFile    = cdslaunchfile.ConfigFile
	PinFile       = cdslaunchfile.PinFile
)

type (
	Config   = cdslaunchfile.Config
	Cluster  = cdslaunchfile.Cluster
	Document = cdslaunchfile.Document
	HA       = cdslaunchfile.HA
)

func Parse(data []byte) (*Config, error) {
	return cdslaunchfile.Parse(data)
}

func ReadCluster(launchFile []byte) (Cluster, error) {
	return cdslaunchfile.ReadCluster(launchFile)
}

func Format(doc Document) ([]byte, error) {
	return cdslaunchfile.Format(doc)
}

func CheckNodeSubnets(
	nodeCIDRs []string,
	clusterCIDRs []string,
) error {
	return cdslaunchfile.CheckNodeSubnets(nodeCIDRs, clusterCIDRs)
}

// MergeWorkloads builds the document's allowlist: the cluster's component
// entries with the tenant's workloads added. A tenant entry may not take a
// component entry's name. A nil tenant document means a cluster running
// components only; empty bytes are a document that does not parse.
func MergeWorkloads(
	components []byte,
	tenant []byte,
) (*allowlist.Allowlist, error) {
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

func addTenantWorkloads(
	merged *allowlist.Allowlist,
	tenant []byte,
) error {
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
