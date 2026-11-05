//go:build linux

package armtlsmesh

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// assignedHandshake runs one mesh handshake between two configurations over a pipe.
func assignedHandshake(t *testing.T, server, client *tls.Config) error {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() { done <- tls.Server(a, server).Handshake() }()
	clientErr := tls.Client(b, client).Handshake()
	return errors.Join(clientErr, <-done)
}

// A generation stamped with a tenant serves and reaches only peers stamped with
// the same tenant; a generation without a stamp meshes only with unstamped peers.
func TestGenerationAdmitsOnlyPeersOfItsOwnAssignedWorkload(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	for _, tc := range []struct {
		name, own, peer string
		ok              bool
	}{
		{"same tenant", "tenant-a", "tenant-a", true},
		{"other tenant", "tenant-a", "tenant-b", false},
		{"unstamped peer", "tenant-a", "", false},
		{"stamped peer at an unstamped endpoint", "", "tenant-a", false},
		{"no tenant anywhere", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := adoptPublishedSet(ca.issue(t, leafSpec{workloadID: tc.own}), time.Now(), discardLogger())
			if err != nil {
				t.Fatal(err)
			}
			if g.assignedWorkloadID != tc.own {
				t.Fatalf("adopted assigned workload = %q, want %q", g.assignedWorkloadID, tc.own)
			}
			peerServer, peerClient := ca.meshConfigsFor(t, leafSpec{workloadID: tc.peer})
			inbound := assignedHandshake(t, g.serverTLS, peerClient)
			outbound := assignedHandshake(t, peerServer, g.clientTLS)
			if tc.ok && (inbound != nil || outbound != nil) {
				t.Fatalf("same-tenant peer refused: inbound %v, outbound %v", inbound, outbound)
			}
			if !tc.ok && (inbound == nil || outbound == nil) {
				t.Fatalf("a peer of another tenant was admitted: inbound %v, outbound %v", inbound, outbound)
			}
			if !tc.ok && !strings.Contains(outbound.Error(), "assigned") {
				t.Fatalf("refusal does not name the tenant check: %v", outbound)
			}
		})
	}
}
