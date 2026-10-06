//go:build linux

package armtlsmesh

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// flushCWConntrack tears down conntrack entries for connections to cw pod IPs
// so the cw guard fails closed the moment it is (re)installed. Without this,
// two windows leak plaintext for the lifetime of a flow, because the guard's
// first rule RETURNs ESTABLISHED,RELATED packets:
//
//   - enabling enforcement on a running cluster (the chart default) leaves
//     in-flight Service-VIP-bypass connections ESTABLISHED, so they keep
//     flowing plaintext;
//   - every sidecar restart / ipset-maxelem rebuild flushes the guard chain
//     while the FORWARD jump persists, so a flow that races the empty-chain
//     window establishes and is then grandfathered.
//
// A cw pod IP appears as the reply-tuple source of a Service-VIP-DNAT'd flow
// and as the reply-tuple destination of a direct pod-IP dial, so a single
// ConntrackReplyAnyIP filter per IP catches both. Deleting a live flow's
// entry forces the next packet to re-establish through the guard, where the
// DROP now runs. Best-effort: a failure is logged, not fatal — the guard
// still blocks all subsequent NEW flows. Returns the entries deleted across
// both families and any failures joined.
func flushCWConntrack(logger *slog.Logger, ips []string) (int, error) {
	if len(ips) == 0 {
		return 0, nil
	}
	var errs []error
	var deleted int
	v4, v6 := splitIPsByFamily(ips)
	for _, fam := range []struct {
		family netlink.InetFamily
		ips    []net.IP
	}{
		{unix.AF_INET, v4},
		{unix.AF_INET6, v6},
	} {
		if len(fam.ips) == 0 {
			continue
		}
		label := inetFamilyLabel(fam.family)
		var filters []netlink.CustomConntrackFilter
		for _, ip := range fam.ips {
			f := &netlink.ConntrackFilter{}
			if err := f.AddIP(netlink.ConntrackReplyAnyIP, ip); err != nil {
				logger.Warn("build cw conntrack filter failed", "ip", ip.String(), "error", err)
				errs = append(errs, fmt.Errorf("%s: %w", label, err))
				continue
			}
			filters = append(filters, f)
		}
		if len(filters) == 0 {
			continue
		}
		n, err := conntrackDeleteFilters(netlink.ConntrackTable, fam.family, filters...)
		deleted += int(n)
		if err != nil {
			logger.Warn("cw conntrack flush failed", "family", label, "deleted", n, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", label, err))
			continue
		}
		if n > 0 {
			logger.Info("flushed cw conntrack entries so the guard fails closed", "family", label, "deleted", n)
		} else {
			logger.Debug("cw conntrack flush matched no entries", "family", label)
		}
	}
	return deleted, errors.Join(errs...)
}

// conntrackDeleteFilters is a var so tests can observe the flush without
// CAP_NET_ADMIN.
var conntrackDeleteFilters = netlink.ConntrackDeleteFilters

// splitIPsByFamily parses and partitions IP strings into IPv4 and IPv6,
// dropping unparseable entries. Extracted so the family split is unit-testable
// without a live conntrack table.
func splitIPsByFamily(ips []string) (v4, v6 []net.IP) {
	for _, s := range ips {
		parsed := net.ParseIP(s)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			v4 = append(v4, parsed)
		} else {
			v6 = append(v6, parsed)
		}
	}
	return v4, v6
}

func inetFamilyLabel(f netlink.InetFamily) string {
	if f == unix.AF_INET6 {
		return "ipv6"
	}
	return "ipv4"
}
