package launchconfig

import (
	"fmt"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// The cluster's pod and service ranges, which a node subnet may not reach
// into.
//
// INVARIANT: equal to the ranges the worker image's kube-proxy static pod and
// CoreDNS configuration carry (images/node-guest/worker/mkosi.extra/usr/lib/c8s/worker).
var clusterRanges = []string{"10.52.0.0/16", "10.53.0.0/16"}

// clusterCDS renders the launch file of this cluster's CDS VM and the
// measurements document its clients hold it to. The configuration carries the
// cluster's component entries and tenant workloads, the launch identities CDS
// admits and serves, the subnets it may dial a sandbox inventory in, and the
// front-door name it signs onto a leaf; the pin binds those exact bytes.
func clusterCDS(opts BundleOptions, operatorPub string, peerPolicy []byte) (config, pin []byte, err error) {
	family, err := cdsconfig.ParsePlatform(opts.CDS.Platform)
	if err != nil {
		return nil, nil, fmt.Errorf("--cds-platform: %w", err)
	}
	components, err := readBounded(opts.CDS.AllowlistSeedPath, MaxDocumentSize)
	if err != nil {
		return nil, nil, fmt.Errorf("--cds-allowlist-seed: %w", err)
	}
	var tenant []byte
	if opts.CDS.TenantWorkloadsPath != "" {
		if tenant, err = readBounded(opts.CDS.TenantWorkloadsPath, MaxDocumentSize); err != nil {
			return nil, nil, fmt.Errorf("--tenant-workloads: %w", err)
		}
	}
	operatorKeys, err := operatorauth.ParseKeyBundle([]byte(operatorPub))
	if err != nil {
		return nil, nil, fmt.Errorf("the bundle's operator public key: %w", err)
	}
	return cdsconfig.Build(cdsconfig.Inputs{
		ClusterID:       opts.ClusterID,
		OperatorKeys:    operatorKeys,
		ComponentSeed:   components,
		TenantWorkloads: tenant,
		Nodes:           peerPolicy,
		NodeCIDRs:       opts.CDS.NodeCIDRs,
		ClusterCIDRs:    clusterRanges,
		LeafDNSNames:    []string{opts.TLSSAN},
		LeafDNSPatterns: []string{cmdsutil.ServiceDNSSANPattern},
		HA:              opts.CDS.ReplicaSet,
		ManifestPath:    opts.CDS.ManifestPath,
		Family:          family,
		VCPUs:           opts.CDS.VCPUs,
	})
}
