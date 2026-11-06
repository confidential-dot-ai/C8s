package nriimagepolicy

import (
	"context"
	"net"
	"net/netip"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// A private CDS name is resolved by this cluster's DNS service alone, and the
// node's own resolver stands in until the cluster is up. Neither answer is
// trusted: armTLS authenticates CDS.

const clusterDNSPort = 53

func clusterFirstDialer(service netip.AddrPort) *net.Dialer {
	return &net.Dialer{
		Timeout:  armtls.DialTimeout,
		Resolver: clusterResolver(service),
	}
}

func clusterResolver(service netip.AddrPort) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, nodeServer string) (net.Conn, error) {
			var dialer net.Dialer
			conn, err := dialer.DialContext(ctx, network, service.String())
			if err == nil {
				return conn, nil
			}
			return dialer.DialContext(ctx, network, nodeServer)
		},
	}
}
