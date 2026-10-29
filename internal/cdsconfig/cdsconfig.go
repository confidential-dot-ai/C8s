// Package cdsconfig is the CDS VM's launch file: one document holding every
// per-cluster setting CDS runs on, bound to its VM by the launch measurement.
// The host can read a launch file, so it carries no secrets.
package cdsconfig

import (
	"fmt"
	"net"
	"regexp"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/yamlutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const SchemaVersion = "c8s-cds/v1"

type Config struct {
	// ClusterID names the cluster. Two clusters sharing an image and operator
	// keys differ in this field, so their launch files and pins differ too.
	ClusterID string
	// OperatorKeys authorize policy writes.
	OperatorKeys operatorauth.KeyBundle
	Workloads    *allowlist.Allowlist
	// Nodes pins the node launch identities CDS admits and serves.
	Nodes refvalues.ReferenceValues
	// NodeCIDRs bounds the addresses CDS may call a sandbox inventory on.
	NodeCIDRs workloadclaims.CIDRHosts
	// DNSSANPatterns are the rules a leaf's DNS SANs are matched against,
	// compiled from the document's leaf names and patterns. Empty admits no
	// DNS SAN, as issuer.CSRPolicy defines.
	DNSSANPatterns []*regexp.Regexp
	// HA is the replica set this CDS belongs to; nil runs the singleton.
	HA *HA
}

// wire mirrors the document. Workloads and Nodes keep the JSON wire schemas
// their own parsers define, so the documents an operator already holds embed
// here byte for byte.
type wire struct {
	SchemaVersion      string   `yaml:"schemaVersion"`
	ClusterID          string   `yaml:"clusterID"`
	OperatorPublicKeys string   `yaml:"operatorPublicKeys"`
	Workloads          string   `yaml:"workloads"`
	Nodes              string   `yaml:"nodes"`
	NodeCIDRs          []string `yaml:"nodeCIDRs"`
	LeafDNSNames       []string `yaml:"leafDNSNames"`
	LeafDNSPatterns    []string `yaml:"leafDNSPatterns"`
	HA                 *haWire  `yaml:"ha,omitempty"`
}

// Parse validates a CDS configuration document. It authenticates nothing:
// these bytes are trusted once a verified self-report binds them.
func Parse(data []byte) (*Config, error) {
	var document wire
	if err := yamlutil.Decode(data, &document); err != nil {
		return nil, err
	}
	return document.parse()
}

func (w wire) parse() (*Config, error) {
	if w.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("schemaVersion must be %s", SchemaVersion)
	}
	if len(validation.IsDNS1123Label(w.ClusterID)) != 0 {
		return nil, fmt.Errorf("clusterID must be an RFC1123 label")
	}
	operatorKeys, err := operatorauth.ParseKeyBundle([]byte(w.OperatorPublicKeys))
	if err != nil {
		return nil, fmt.Errorf("operatorPublicKeys: %w", err)
	}
	workloads, err := allowlist.ParseJSON([]byte(w.Workloads))
	if err != nil {
		return nil, fmt.Errorf("workloads: %w", err)
	}
	nodes, err := refvalues.Parse([]byte(w.Nodes))
	if err != nil {
		return nil, fmt.Errorf("nodes: %w", err)
	}
	subnets, err := parseNodeCIDRs(w.NodeCIDRs)
	if err != nil {
		return nil, err
	}
	patterns, err := compileLeafDNS(w.LeafDNSNames, w.LeafDNSPatterns)
	if err != nil {
		return nil, err
	}
	ha, err := w.HA.parse()
	if err != nil {
		return nil, err
	}
	return &Config{
		ClusterID:      w.ClusterID,
		OperatorKeys:   operatorKeys,
		Workloads:      workloads,
		Nodes:          nodes,
		NodeCIDRs:      subnets,
		DNSSANPatterns: patterns,
		HA:             ha,
	}, nil
}

// parseNodeCIDRs builds the inventory bound CDS dials within. Each entry must
// name the subnet itself, so what the document says is what CDS enforces.
func parseNodeCIDRs(cidrs []string) (workloadclaims.CIDRHosts, error) {
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("nodeCIDRs must name at least one subnet")
	}
	hosts, err := workloadclaims.ParseInventoryHosts(cidrs)
	if err != nil {
		return nil, fmt.Errorf("nodeCIDRs: %w", err)
	}
	for i, subnet := range hosts {
		if isDefaultRoute(subnet) {
			return nil, fmt.Errorf("nodeCIDRs: %q is a default route", cidrs[i])
		}
		if hasHostBits(cidrs[i], subnet) {
			return nil, fmt.Errorf("nodeCIDRs: %q must name the subnet %s", cidrs[i], subnet)
		}
	}
	return hosts, nil
}

func isDefaultRoute(subnet *net.IPNet) bool {
	ones, _ := subnet.Mask.Size()
	return ones == 0
}

// hasHostBits reports whether raw names an address inside the subnet it parsed
// as; the parser drops those bits, so 10.0.0.5/24 would bound 10.0.0.0/24.
func hasHostBits(raw string, subnet *net.IPNet) bool {
	address, _, err := net.ParseCIDR(raw)
	return err == nil && !address.Equal(subnet.IP)
}

func compileLeafDNS(names []string, patterns []string) ([]*regexp.Regexp, error) {
	compiled, err := cmdsutil.CompileDNSSANPatterns(patterns)
	if err != nil {
		return nil, fmt.Errorf("leafDNSPatterns: %w", err)
	}
	for _, name := range names {
		literal, err := cmdsutil.CompileDNSSANName(name)
		if err != nil {
			return nil, fmt.Errorf("leafDNSNames: %w", err)
		}
		compiled = append(compiled, literal)
	}
	return compiled, nil
}
