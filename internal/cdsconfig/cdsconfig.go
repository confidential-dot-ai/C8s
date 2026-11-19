// Package cdsconfig is the CDS VM's launch file: one document holding every
// per-cluster setting CDS runs on, bound to its VM by the launch measurement.
// The host can read a launch file, so it carries no secrets.
package cdsconfig

import (
	"errors"
	"fmt"
	"net"
	"regexp"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdschain"
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
	// PodImages authorize quote-bound Pod mesh issuance only, never node callbacks.
	PodImages []remote.ImagePin
	// NodeCIDRs bounds the addresses CDS may call a sandbox inventory on.
	NodeCIDRs workloadclaims.CIDRHosts
	// DNSSANPatterns are the rules a leaf's DNS SANs are matched against,
	// compiled from the document's leaf names and patterns. Empty admits no
	// DNS SAN, as issuer.CSRPolicy defines.
	DNSSANPatterns []*regexp.Regexp
	// KMS is where pod secret release is brokered to; nil serves no pod secrets.
	KMS *KMS
	// HA is the replica set of a stateless CDS (docs/cds-ha.md), nil for a
	// single CDS. A replica's slot is its endpoint's index.
	HA *HA
}

// HA is a fixed replica set: 1, 3 or 5 distinct <host>:<port> endpoints.
type HA struct {
	Endpoints []string `yaml:"endpoints"`
}

func (h *HA) validate() error {
	if h == nil {
		return nil
	}
	if err := cmdsutil.ValidateCDSEndpoints(h.Endpoints); err != nil {
		return fmt.Errorf("ha.endpoints: %w", err)
	}
	return nil
}

// wire mirrors the document. Workloads and Nodes keep the JSON wire schemas
// their own parsers define, so the documents an operator already holds embed
// here byte for byte.
type wire struct {
	SchemaVersion      string   `yaml:"schemaVersion"`
	ClusterID          string   `yaml:"clusterID"`
	OperatorPublicKeys string   `yaml:"operatorPublicKeys"`
	Workloads          string   `yaml:"workloads"`
	Nodes              string   `yaml:"nodes,omitempty"`
	PodImagePolicy     string   `yaml:"podImagePolicy,omitempty"`
	NodeCIDRs          []string `yaml:"nodeCIDRs"`
	LeafDNSNames       []string `yaml:"leafDNSNames"`
	LeafDNSPatterns    []string `yaml:"leafDNSPatterns"`
	KMS                *kmsWire `yaml:"kms,omitempty"`
	HA                 *HA      `yaml:"ha,omitempty"`
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
	nodes, err := parseNodes(w.Nodes)
	if err != nil {
		return nil, err
	}
	var podImages []remote.ImagePin
	if w.PodImagePolicy != "" {
		pods, err := workloadclaims.ParsePodImagePolicy([]byte(w.PodImagePolicy))
		if err != nil {
			return nil, fmt.Errorf("podImagePolicy: %w", err)
		}
		podImages = pods.Images
	}
	subnets, err := parseNodeCIDRs(w.NodeCIDRs)
	if err != nil {
		return nil, err
	}
	patterns, err := compileLeafDNS(w.LeafDNSNames, w.LeafDNSPatterns)
	if err != nil {
		return nil, err
	}
	if nodes.Empty() {
		return nil, errors.New("nodes: CDS certifies only the nodes its launch file names, and this one names none")
	}
	kms, err := w.KMS.parse()
	if err != nil {
		return nil, err
	}
	if kms != nil && len(podImages) == 0 {
		return nil, errors.New("kms: pod secret release needs a podImagePolicy")
	}
	if err := w.HA.validate(); err != nil {
		return nil, err
	}
	// A replica set serves its node set from the chain, whose nodes entries
	// carry only images that bind their launch: the launch file's set is the
	// first of them.
	if w.HA != nil {
		if err := cdschain.CheckNodes([]byte(w.Nodes)); err != nil {
			return nil, err
		}
	}
	cfg := &Config{
		HA:             w.HA,
		ClusterID:      w.ClusterID,
		OperatorKeys:   operatorKeys,
		Workloads:      workloads,
		Nodes:          nodes,
		PodImages:      podImages,
		NodeCIDRs:      subnets,
		DNSSANPatterns: patterns,
		KMS:            kms,
	}
	if err := cfg.ValidatePodAuthorities(); err != nil {
		return nil, fmt.Errorf("podImagePolicy: %w", err)
	}
	return cfg, nil
}

// parseNodes reads the node pins a launch file names, which may be none.
func parseNodes(document string) (refvalues.ReferenceValues, error) {
	if document == "" {
		return refvalues.ReferenceValues{}, nil
	}
	nodes, err := refvalues.Parse([]byte(document))
	if err != nil {
		return refvalues.ReferenceValues{}, fmt.Errorf("nodes: %w", err)
	}
	return nodes, nil
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
