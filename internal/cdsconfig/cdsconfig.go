// Package cdsconfig is the CDS VM's launch file as CDS runs on it: the
// document pkg/launchfile/cds defines, with its operator keys and allowlist
// parsed by their own C8s parsers.
package cdsconfig

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"regexp"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/launchfile/cds"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const SchemaVersion = cds.SchemaVersion

// HA is the replica set one cluster's CDS runs as.
type HA = cds.HA

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

// Parse validates a CDS configuration document. It authenticates nothing:
// these bytes are trusted once a verified self-report binds them.
func Parse(data []byte) (*Config, error) {
	document, err := cds.Parse(data)
	if err != nil {
		return nil, err
	}
	operatorKeys, err := operatorauth.ParseKeyBundle(document.OperatorPublicKeys)
	if err != nil {
		return nil, fmt.Errorf("operatorPublicKeys: %w", err)
	}
	workloads, err := allowlist.ParseJSON(document.Workloads)
	if err != nil {
		return nil, fmt.Errorf("workloads: %w", err)
	}
	return &Config{
		ClusterID:      document.ClusterID,
		OperatorKeys:   operatorKeys,
		Workloads:      workloads,
		Nodes:          document.Nodes,
		NodeCIDRs:      document.NodeCIDRs,
		DNSSANPatterns: document.DNSSANPatterns,
		HA:             document.HA,
	}, nil
}

// Cluster is what a client takes from the launch file it pins its CDS to.
// A file naming a single CDS leaves the other fields empty.
type Cluster struct {
	ClusterID    string
	OperatorKeys []*ecdsa.PublicKey
	Replicated   bool
}

// ReadCluster reads those fields out of launchFile and nothing else, so a
// setting only CDS acts on cannot keep a client from starting.
func ReadCluster(launchFile []byte) (Cluster, error) {
	cluster, err := cds.ReadCluster(launchFile)
	if err != nil || !cluster.Replicated {
		return Cluster{}, err
	}
	keys, err := operatorauth.ParseKeyBundle(cluster.OperatorPublicKeys)
	if err != nil {
		return Cluster{}, fmt.Errorf("operatorPublicKeys: %w", err)
	}
	if len(keys.Keys()) == 0 {
		return Cluster{}, errors.New("operatorPublicKeys names no key, and every decree of this cluster is signed under one")
	}
	return Cluster{
		ClusterID:    cluster.ClusterID,
		OperatorKeys: keys.Keys(),
		Replicated:   true,
	}, nil
}
