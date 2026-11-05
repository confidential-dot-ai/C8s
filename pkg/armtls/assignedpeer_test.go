package armtls

import (
	"strings"
	"testing"
)

// A pod CVM's endpoint admits a peer with exactly its own assigned workload
// ID, in both roles: two tenants running the same image cannot substitute
// certificates, and a leaf without the stamp is refused where a tenant is
// expected. Endpoints without a stamp mesh only with each other.
func TestRequireSameAssignedWorkloadInBothRoles(t *testing.T) {
	for _, tc := range []struct {
		name, server, client string
		ok                   bool
		refusal              string
	}{
		{"same tenant", "tenant-a", "tenant-a", true, ""},
		{"no tenant on either side", "", "", true, ""},
		{"another tenant", "tenant-a", "tenant-b", false, `is assigned to workload "tenant-a", not "tenant-b"`},
		{"peer without a stamp", "", "tenant-a", false, "carries no assigned workload ID"},
		{"peer with a stamp this endpoint lacks", "tenant-a", "", false, "this endpoint's leaf is assigned to none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := acceptingMeshPair(t,
				meshLeafSpec{assignedWorkload: tc.server},
				meshLeafSpec{assignedWorkload: tc.client},
				RequireSameAssignedWorkload(tc.server),
				RequireSameAssignedWorkload(tc.client),
			)
			_, err := meshHandshake(t, server, client)
			if tc.ok != (err == nil) {
				t.Fatalf("handshake error = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !strings.Contains(err.Error(), tc.refusal) {
				t.Fatalf("handshake error = %v, want %q", err, tc.refusal)
			}
		})
	}
}
