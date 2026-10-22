package nriimagepolicy

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

var relayExit = []exit{{Range: netip.MustParsePrefix("203.0.113.7/32"), Port: 443}}

// A pod holding an entry's exits runs that entry alone: a container that
// breaks the match is refused, one that keeps it starts.
func TestBindEntryHoldsAPodToTheEntryItsExitsCameFrom(t *testing.T) {
	pod := meshPod("default", "collector", testNetNS)
	gate, state := gateWithPod(pod)
	state.exitEntry, state.exits = "collector", relayExit

	if err := gate.bindEntry(pod, "collector", relayExit); err != nil {
		t.Fatalf("a container keeping the match was refused: %v", err)
	}
	for _, entry := range []string{"other", ""} {
		err := gate.bindEntry(pod, entry, nil)
		if err == nil || !strings.Contains(err.Error(), "no longer matches") {
			t.Fatalf("a container matching %q was not refused: %v", entry, err)
		}
	}
	if got := gate.grantedExits(pod.GetId()); len(got) != 1 {
		t.Fatalf("granted exits = %v, want them unchanged", got)
	}
}

// A match whose entry declares no exit changes nothing, and a later match may
// still grant one.
func TestBindEntryWithoutExitsGrantsNothing(t *testing.T) {
	pod := meshPod("default", "app", testNetNS)
	gate, state := gateWithPod(pod)
	for _, entry := range []string{"", "app"} {
		if err := gate.bindEntry(pod, entry, nil); err != nil {
			t.Fatalf("bindEntry(%q) = %v", entry, err)
		}
	}
	if state.exitEntry != "" || state.exits != nil {
		t.Fatalf("pod holds %q %v, want nothing", state.exitEntry, state.exits)
	}
}

// An exit into the cluster's own ranges is refused before the ruleset is
// touched, and so is any exit where trusted policy names no ranges.
func TestBindEntryRefusesAnExitIntoTheCluster(t *testing.T) {
	pod := meshPod("default", "collector", testNetNS)
	gate, state := gateWithPod(pod)
	for _, exits := range [][]exit{
		{{Range: netip.MustParsePrefix("10.52.3.0/24"), Port: 443}},
		{{Range: netip.MustParsePrefix("10.0.0.0/8"), Port: 443}},
		append([]exit{{Range: netip.MustParsePrefix("10.52.0.9/32"), Port: 80}}, relayExit...),
	} {
		err := gate.bindEntry(pod, "collector", exits)
		if err == nil || !strings.Contains(err.Error(), "overlaps the cluster range 10.52.0.0/16") {
			t.Fatalf("exits %v: err = %v, want a cluster-range refusal", exits, err)
		}
	}

	gate.policy.ClusterRanges = nil
	err := gate.bindEntry(pod, "collector", relayExit)
	if err == nil || !strings.Contains(err.Error(), "names no cluster ranges") {
		t.Fatalf("err = %v, want a refusal without cluster ranges", err)
	}
	if state.exitEntry != "" {
		t.Fatalf("a refused grant left the pod holding %q", state.exitEntry)
	}
}

const (
	collectorDigest = "sha256:" + "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
	appDigest       = "sha256:" + "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
)

// exitsPlugin serves an allowlist where the collector entry declares one exit
// and the app entry none.
func exitsPlugin(t *testing.T) *plugin {
	t.Helper()
	served, err := allowlist.ParseServedJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{
		"collector":{"containers":[{"digest":"` + collectorDigest + `","command":{"policy":"any"},"args":{"policy":"any"}}],"egress":[{"cidr":"203.0.113.7/32","port":443}]},
		"app":{"containers":[{"digest":"` + appDigest + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	store := newPolicyStore(nil)
	store.apply(served, 1)
	return &plugin{policy: store, inventory: newAdmissionInventory(t.TempDir())}
}

func starting(digest string) workloadclaims.SandboxContainer {
	return workloadclaims.SandboxContainer{Digest: digest, Argv: []string{"/run"}, Mounts: []allowlist.ObservedMount{}}
}

// The entry a pod's exits come from is the one its workload containers match,
// the starting one included, by the rule secret release uses: platform client
// roles are left out, and a pod that runs anything else matches no entry.
func TestMatchedExitsAreTheMatchedEntrysEgress(t *testing.T) {
	p := exitsPlugin(t)
	p.inventory.recordSandbox("sb")
	p.inventory.recordObserved("mesh", "sb", "c8s-mesh", appDigest, meshRole, []string{"/mesh"}, nil, nil)

	entry, exits := p.matchedExits("sb", starting(collectorDigest))
	if entry != "collector" || !slices.Equal(exits, relayExit) {
		t.Fatalf("matchedExits = %q %v, want the collector's exit", entry, exits)
	}

	p.inventory.record("collector", "sb", "collector", collectorDigest, []string{"/run"}, nil)
	if entry, exits := p.matchedExits("sb", starting(appDigest)); entry != "" || exits != nil {
		t.Fatalf("a pod running two entries' containers matched %q %v", entry, exits)
	}
	if entry, _ := p.matchedExits("unknown", starting(collectorDigest)); entry != "" {
		t.Fatalf("a sandbox the inventory does not know matched %q", entry)
	}
}
