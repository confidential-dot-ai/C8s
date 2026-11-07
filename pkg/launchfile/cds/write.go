// The generator side of a CDS launch file: what an operator's tooling puts
// into one and the rules it checks before writing it.

package cds

import (
	"errors"
	"fmt"
	"net/netip"

	"gopkg.in/yaml.v3"
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
	// OperatorPublicKeys is the PEM bundle of the keys that authorize policy
	// writes.
	OperatorPublicKeys []byte
	// Workloads is the cluster's allowlist in its canonical JSON.
	Workloads []byte
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

// Format renders doc as a CDS launch file under the schema version this
// package parses, and only what Parse accepts back.
func Format(doc Document) ([]byte, error) {
	data, err := yaml.Marshal(doc.wire())
	if err != nil {
		return nil, fmt.Errorf("render CDS config: %w", err)
	}
	if _, err := Parse(data); err != nil {
		return nil, fmt.Errorf("rendered CDS config: %w", err)
	}
	return data, nil
}

func (d Document) wire() wire {
	return wire{
		SchemaVersion:      SchemaVersion,
		ClusterID:          d.ClusterID,
		OperatorPublicKeys: string(d.OperatorPublicKeys),
		Workloads:          string(d.Workloads),
		Nodes:              string(d.Nodes),
		NodeCIDRs:          d.NodeCIDRs,
		LeafDNSNames:       d.LeafDNSNames,
		LeafDNSPatterns:    d.LeafDNSPatterns,
		HA:                 d.HA.wire(),
	}
}

// CheckNodeSubnets refuses a node subnet overlapping one of the cluster's pod
// or service ranges: CDS dials a node address for a sandbox's admission
// inventory, and a pod inside that bound could answer as one. A generator
// applies it, holding the ranges the document does not carry.
func CheckNodeSubnets(
	nodeCIDRs []string,
	clusterCIDRs []string,
) error {
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

func parsePrefixes(
	field string,
	cidrs []string,
) ([]netip.Prefix, error) {
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
