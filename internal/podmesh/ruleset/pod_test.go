//go:build linux

package ruleset

import (
	"fmt"
	"net/netip"
	"testing"
)

func TestStandalonePodCapturesPeersAndAdmitsInternetInTheNamespace(t *testing.T) {
	podNetNS(t, func(path string) error {
		peer, err := startPeerNamespace()
		if err != nil {
			return err
		}
		defer peer.stop()
		if err := connectPeer(peer); err != nil {
			return err
		}
		policy := behaviourPolicy()
		policy.Roles = nil
		policy.Pod = &PodPolicy{Peers: []Destination{{Addr: netip.MustParseAddr(unapproved), Port: 8080}}}
		if err := Install(path, policy); err != nil {
			return err
		}
		listener, err := listenAs(meshUID, "127.0.0.1", policy.Capture.Outbound)
		if err != nil {
			return err
		}
		defer listener.Close()
		go acceptAll(listener)
		cases := []struct {
			uid          uint32
			network, dst string
			want         treatment
		}{
			{workloadUID, "tcp", address(unapproved, 8080), captured},
			{meshUID, "tcp", address(unapproved, 8080), admitted},
			{workloadUID, "tcp", address(unapproved, 53), admitted},
			{meshUID, "tcp", address(unapproved, 53), admitted},
			{workloadUID, "udp", address(resolver, 53), admitted},
			{workloadUID, "tcp", address(resolver, 53), admitted},
			{meshUID, "udp", address(resolver, 53), admitted},
			{meshUID, "tcp", address(service, servicePort), admitted},
			{0, "tcp", address(unapproved, 53), denied},
			{0, "udp", address(resolver, 53), denied},
			{workloadUID, "tcp", address(unapproved6, 8080), denied},
			{meshUID, "udp", address(unapproved6, 53), denied},
		}
		for i, tc := range cases {
			port := firstSourcePort + uint16(i)
			if err := sendAs(tc.uid, tc.network, tc.dst, port); err != nil {
				return err
			}
			got, err := treatmentOf(policy, tc.network, tc.dst, port)
			if err != nil {
				return err
			}
			if got != tc.want {
				return fmt.Errorf("UID %d to %s: got %s want %s", tc.uid, tc.dst, got, tc.want)
			}
		}
		if err := sendAs(meshUID, "tcp", address(unapproved, 53), policy.Capture.Inbound); err != nil {
			return err
		}
		if got, err := treatmentOf(policy, "tcp", address(unapproved, 53), policy.Capture.Inbound); err != nil || got != denied {
			return fmt.Errorf("mesh listener source port bypass: got %s, %v", got, err)
		}
		return Verify(path, policy)
	})
}
