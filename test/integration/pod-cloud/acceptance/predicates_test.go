package acceptance

import (
	"strings"
	"testing"
	"time"
)

func acceptedLeaf() *Leaf {
	return &Leaf{SandboxID: "pcvm-a", Serial: "1", SPKI: "key-a", Workload: "cloud-a", AssignedWorkloadID: "tenant", Denied: true, NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2026-01-01T06:00:00Z"}
}

func TestParseLeafKeepsTheAssignedWorkloadID(t *testing.T) {
	leaf, err := ParseLeaf([]byte(`{"sandboxID":"pcvm-a","serial":"1","spki":"key-a","workload":"cloud-a","assignedWorkloadID":"tenant","denied":true,"rejection":"certificate required"}`))
	if err != nil {
		t.Fatal(err)
	}
	if leaf.AssignedWorkloadID != "tenant" || !strings.Contains(string(leaf.Raw), `"rejection"`) {
		t.Fatalf("assigned workload ID or raw evidence lost: %+v", leaf)
	}
	if err = leaf.Accepted("cloud-a", "tenant"); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptedLeafRequiresTheRunsTenant(t *testing.T) {
	for name, change := range map[string]func(*Leaf){
		"missing-tenant":  func(l *Leaf) { l.AssignedWorkloadID = "" },
		"other-tenant":    func(l *Leaf) { l.AssignedWorkloadID = "other" },
		"other-workload":  func(l *Leaf) { l.Workload = "cloud-b" },
		"certless-access": func(l *Leaf) { l.Denied = false },
		"no-sandbox":      func(l *Leaf) { l.SandboxID = "" },
		"no-serial":       func(l *Leaf) { l.Serial = "" },
		"no-key":          func(l *Leaf) { l.SPKI = "" },
	} {
		t.Run(name, func(t *testing.T) {
			leaf := acceptedLeaf()
			change(leaf)
			if err := leaf.Accepted("cloud-a", "tenant"); err == nil {
				t.Fatal("leaf accepted")
			}
		})
	}
	var missing *Leaf
	if missing.Accepted("cloud-a", "tenant") == nil || acceptedLeaf().Accepted("cloud-a", "") == nil {
		t.Fatal("a missing leaf or an unnamed tenant was accepted")
	}
}

func TestRenewalRetainsTheAssignedWorkloadID(t *testing.T) {
	initial := acceptedLeaf()
	renewed := func() *Leaf {
		l := acceptedLeaf()
		l.Serial, l.SPKI = "2", "key-a2"
		l.NotBefore, l.NotAfter = "2026-01-01T01:00:00Z", "2026-01-01T07:00:00Z"
		return l
	}
	if ok, err := RenewalEventNamed(initial, renewed(), 3000*time.Second, "cloud-a"); err != nil || !ok {
		t.Fatalf("renewal with the same tenant refused: %v %v", ok, err)
	}
	for name, change := range map[string]func(*Leaf){
		"tenant-dropped": func(l *Leaf) { l.AssignedWorkloadID = "" },
		"tenant-changed": func(l *Leaf) { l.AssignedWorkloadID = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			current := renewed()
			change(current)
			if _, err := Renewed(initial, current); err == nil {
				t.Fatal("renewal that lost the tenant accepted")
			}
			if _, err := RenewalEventNamed(initial, current, 3000*time.Second, "cloud-a"); err == nil {
				t.Fatal("renewal event that lost the tenant accepted")
			}
		})
	}
}
