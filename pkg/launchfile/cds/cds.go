// Package cds is the CDS VM's launch file: one document holding every
// per-cluster setting CDS runs on, bound to its VM by the launch measurement.
// The host can read a launch file, so it carries no secrets.
//
// This package owns the document and every field but two: operatorPublicKeys
// and workloads embed documents that C8s's operatorauth and allowlist packages
// parse, and Parse returns them as the bytes the document carries.
package cds

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/pkg/launchfile/yamlutil"
)

const SchemaVersion = "c8s-cds/v1"

type Config struct {
	// ClusterID names the cluster. Two clusters sharing an image and operator
	// keys differ in this field, so their launch files and pins differ too.
	ClusterID string
	// OperatorPublicKeys is the PEM bundle of the keys that authorize policy
	// writes, unparsed.
	OperatorPublicKeys []byte
	// Workloads is the cluster's allowlist JSON, unparsed.
	Workloads []byte
	// Nodes pins the node launch identities CDS admits and serves.
	Nodes refvalues.ReferenceValues
	// NodeCIDRs bounds the addresses CDS may call a sandbox inventory on.
	NodeCIDRs []*net.IPNet
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
	if err := checkSchemaVersion(w.SchemaVersion); err != nil {
		return nil, err
	}
	if err := checkClusterID(w.ClusterID); err != nil {
		return nil, err
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
		ClusterID:          w.ClusterID,
		OperatorPublicKeys: []byte(w.OperatorPublicKeys),
		Workloads:          []byte(w.Workloads),
		Nodes:              nodes,
		NodeCIDRs:          subnets,
		DNSSANPatterns:     patterns,
		HA:                 ha,
	}, nil
}

// Cluster is what a client takes from the launch file it pins its CDS to.
// A file naming a single CDS leaves the other fields empty.
type Cluster struct {
	ClusterID string
	// OperatorPublicKeys is the PEM bundle every decree of the cluster is
	// signed under, unparsed.
	OperatorPublicKeys []byte
	Replicated         bool
}

// ReadCluster reads those fields out of launchFile and nothing else, so a
// setting only CDS acts on cannot keep a client from starting.
func ReadCluster(launchFile []byte) (Cluster, error) {
	var document wire
	if err := yamlutil.Decode(launchFile, &document); err != nil {
		return Cluster{}, err
	}
	if err := checkSchemaVersion(document.SchemaVersion); err != nil {
		return Cluster{}, err
	}
	if document.HA == nil {
		return Cluster{}, nil
	}
	if err := checkVoters(document.HA.Voters); err != nil {
		return Cluster{}, err
	}
	if err := checkClusterID(document.ClusterID); err != nil {
		return Cluster{}, err
	}
	return Cluster{
		ClusterID:          document.ClusterID,
		OperatorPublicKeys: []byte(document.OperatorPublicKeys),
		Replicated:         true,
	}, nil
}

func checkSchemaVersion(version string) error {
	if version != SchemaVersion {
		return fmt.Errorf("schemaVersion must be %s", SchemaVersion)
	}
	return nil
}

// dns1123Label is Kubernetes' RFC 1123 label rule, which C8s tests this
// module against.
var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// checkClusterID: a cluster's own names are built from its id.
func checkClusterID(id string) error {
	if len(id) > 63 || !dns1123Label.MatchString(id) {
		return fmt.Errorf("clusterID must be an RFC1123 label")
	}
	return nil
}

// parseNodeCIDRs builds the inventory bound CDS dials within. Each entry must
// name the subnet itself, so what the document says is what CDS enforces.
func parseNodeCIDRs(cidrs []string) ([]*net.IPNet, error) {
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("nodeCIDRs must name at least one subnet")
	}
	hosts := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, subnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("nodeCIDRs: inventory CIDR %q: %w", cidr, err)
		}
		if isDefaultRoute(subnet) {
			return nil, fmt.Errorf("nodeCIDRs: %q is a default route", cidr)
		}
		if hasHostBits(cidr, subnet) {
			return nil, fmt.Errorf("nodeCIDRs: %q must name the subnet %s", cidr, subnet)
		}
		hosts = append(hosts, subnet)
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

func compileLeafDNS(
	names []string,
	patterns []string,
) ([]*regexp.Regexp, error) {
	compiled, err := compileDNSSANPatterns(patterns)
	if err != nil {
		return nil, fmt.Errorf("leafDNSPatterns: %w", err)
	}
	for _, name := range names {
		literal, err := compileDNSSANName(name)
		if err != nil {
			return nil, fmt.Errorf("leafDNSNames: %w", err)
		}
		compiled = append(compiled, literal)
	}
	return compiled, nil
}

// hostnameLabelRe accepts RFC 1123 labels: 1–63 alphanumeric characters,
// with hyphens allowed in the middle.
var hostnameLabelRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// ValidateDNSName checks a literal RFC 1123 hostname, excluding wildcards,
// URLs, regular expressions, and lists of names.
func ValidateDNSName(s string) error {
	if len(s) > 253 {
		return fmt.Errorf("'%s' exceeds maximum hostname length of 253 characters", s)
	}
	for label := range strings.SplitSeq(s, ".") {
		if !hostnameLabelRe.MatchString(label) {
			return fmt.Errorf("'%s' is not a valid RFC 1123 hostname", s)
		}
	}
	return nil
}

// compileDNSSANName compiles one authenticated hostname into a whole-name
// match. The name is a literal identity, never a caller-supplied regular
// expression, so the anchoring is explicit here.
func compileDNSSANName(name string) (*regexp.Regexp, error) {
	if net.ParseIP(name) != nil {
		return nil, fmt.Errorf("'%s' is an IP address, not a DNS hostname", name)
	}
	if err := ValidateDNSName(name); err != nil {
		return nil, err
	}
	return regexp.MustCompile("^" + regexp.QuoteMeta(name) + "$"), nil
}

// compileDNSSANPatterns compiles the patterns a leaf's DNS SANs may match,
// skipping empties so a stray "" does not become a rule of its own. No
// pattern at all admits no DNS SAN (issuer.CSRPolicy).
func compileDNSSANPatterns(patterns []string) ([]*regexp.Regexp, error) {
	var compiled []*regexp.Regexp
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern '%s': %w", pattern, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}
