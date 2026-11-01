package cdsconfig

import (
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// Inputs is everything one cluster's CDS VM is configured with. Both
// generators (`c8s cds config new` and `c8s launch-config new`) fill it, so
// either one's configuration is built and checked the same way. Each embedded
// policy is the exact bytes its own parser reads.
type Inputs struct {
	ClusterID string
	// OperatorKeys authorize policy writes.
	OperatorKeys operatorauth.KeyBundle
	// ComponentSeed holds the cluster's component entries; TenantWorkloads
	// the operator's own, nil for a cluster running components only.
	ComponentSeed   []byte
	TenantWorkloads []byte
	// Nodes is the measurements document pinning the nodes CDS admits.
	Nodes []byte
	// PodImagePolicy optionally pins Pod identities separately from Nodes.
	// Empty disables Pod issuance; nonempty bytes must be a complete policy.
	PodImagePolicy []byte
	// NodeCIDRs are the subnets CDS may dial a sandbox inventory in;
	// ClusterCIDRs are the pod and service ranges they may not reach into.
	NodeCIDRs    []string
	ClusterCIDRs []string
	// LeafDNSNames and LeafDNSPatterns are the DNS SAN rules CDS issues under.
	LeafDNSNames    []string
	LeafDNSPatterns []string
	// HA is the replica set the cluster's CDS runs as; a zero one the singleton.
	HA HA
	// ManifestPath, Family and VCPUs select the CDS guest image the VM boots
	// and the launch digests its pin carries.
	ManifestPath string
	Family       teetypes.Family
	VCPUs        []int
}

// Build renders the configuration and its pin. It writes nothing: a caller
// publishes the pair only once both are rendered.
func Build(in Inputs) (config, pin []byte, err error) {
	if err := CheckNodeSubnets(in.NodeCIDRs, in.ClusterCIDRs); err != nil {
		return nil, nil, err
	}
	workloads, err := MergeWorkloads(in.ComponentSeed, in.TenantWorkloads)
	if err != nil {
		return nil, nil, err
	}
	config, err = Format(Document{
		ClusterID:       in.ClusterID,
		OperatorKeys:    in.OperatorKeys,
		Workloads:       workloads,
		Nodes:           in.Nodes,
		PodImagePolicy:  in.PodImagePolicy,
		NodeCIDRs:       in.NodeCIDRs,
		LeafDNSNames:    in.LeafDNSNames,
		LeafDNSPatterns: in.LeafDNSPatterns,
		HA:              in.HA,
	})
	if err != nil {
		return nil, nil, err
	}
	if pin, err = Pin(in.ManifestPath, in.Family, in.VCPUs, config); err != nil {
		return nil, nil, err
	}
	return config, pin, nil
}
