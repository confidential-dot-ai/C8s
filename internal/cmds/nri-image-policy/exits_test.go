package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

var relayExit = []exit{{Range: netip.MustParsePrefix("203.0.113.7/32"), Port: 443}}

const (
	collectorDigest = "sha256:" + "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
	collectorInit   = "sha256:" + "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"
	sidecarDigest   = "sha256:" + "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
	appDigest       = "sha256:" + "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
)

// exitsAllowlist is a served allowlist whose collector entry declares one exit
// and a declared init container, and whose app entry declares none. Extra
// entries are added as JSON members.
func exitsAllowlist(t *testing.T, extra string) *allowlist.Allowlist {
	t.Helper()
	any := func(digest string) string {
		return `{"digest":"` + digest + `","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"}}`
	}
	doc := `{"schema":"c8s.allowlist/v1","workloads":{
		"collector":{"initContainers":[` + any(collectorInit) + `],"containers":[` + any(collectorDigest) + `],"egress":[{"cidr":"203.0.113.7/32","port":443}]},
		"app":{"containers":[` + any(appDigest) + `]}` + extra + `}}`
	served, err := allowlist.ParseServedJSON([]byte(strings.NewReplacer(
		"SIDECAR", any(sidecarDigest), "COLLECTOR", any(collectorDigest), "APP", any(appDigest),
	).Replace(doc)))
	if err != nil {
		t.Fatal(err)
	}
	return served
}

func running(digests ...string) []allowlist.RunningContainer {
	out := make([]allowlist.RunningContainer, 0, len(digests))
	for _, d := range digests {
		out = append(out, allowlist.RunningContainer{Digest: d, Argv: []string{"/run"}, Mounts: []allowlist.ObservedMount{}})
	}
	return out
}

// The decision is a function of the set of workload containers: an entry with
// exits claims the pod once its main containers run and no other entry admits
// them, and a claimed pod runs that entry alone.
func TestDecideExits(t *testing.T) {
	for _, tc := range []struct {
		name     string
		extra    string
		running  []string
		entry    string
		refused  string
		shadowed bool
	}{
		{name: "the collector alone holds its exit", running: []string{collectorDigest}, entry: "collector"},
		{name: "with its declared init container", running: []string{collectorInit, collectorDigest}, entry: "collector"},
		{name: "its init container alone claims nothing", running: []string{collectorInit}},
		{name: "an app pod holds nothing", running: []string{appDigest}},
		{name: "a foreign container beside the collector is refused", running: []string{appDigest, collectorDigest}, refused: "1 container(s) that entry does not declare"},
		{
			name: "an entry that also admits the collector's containers shadows its exit", running: []string{collectorDigest},
			extra: `,"with-sidecar":{"containers":[COLLECTOR,SIDECAR]}`, shadowed: true,
		},
		{
			name: "so its pods run without exits or refusals", running: []string{collectorDigest, sidecarDigest},
			extra: `,"with-sidecar":{"containers":[COLLECTOR,SIDECAR]}`, shadowed: true,
		},
		{
			name: "two entries with exits in one pod are refused", running: []string{collectorDigest, sidecarDigest},
			extra: `,"relay":{"containers":[SIDECAR],"egress":[{"cidr":"198.51.100.0/24","port":443}]}`, refused: "each declare exits",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := decideExits(exitsAllowlist(t, tc.extra), running(tc.running...))
			if got.entry != tc.entry {
				t.Fatalf("entry = %q, want %q", got.entry, tc.entry)
			}
			if tc.entry != "" && !slices.Equal(got.exits, relayExit) {
				t.Fatalf("exits = %v, want %v", got.exits, relayExit)
			}
			if (got.refusal == nil) != (tc.refused == "") || (got.refusal != nil && !strings.Contains(got.refusal.Error(), tc.refused)) {
				t.Fatalf("refusal = %v, want %q", got.refusal, tc.refused)
			}
			if (len(got.shadowed) > 0) != tc.shadowed {
				t.Fatalf("shadowed = %v, want %v", got.shadowed, tc.shadowed)
			}
		})
	}
}

// exitsGate is a gate holding one protected pod, whose exits are added by a
// recording stand-in for the live ruleset.
func exitsGate(t *testing.T) (*meshGate, *protectedPod, *[][]exit) {
	t.Helper()
	pod := meshPod("default", "collector", testNetNS)
	gate, state := gateWithPod(pod)
	var extended [][]exit
	gate.extend = func(_ podNamespace, _ meshPolicy, _ string, exits []exit) error {
		extended = append(extended, exits)
		return nil
	}
	gate.nodeAddress = func() (netip.Addr, error) { return netip.MustParseAddr("10.0.2.15"), nil }
	return gate, state, &extended
}

func TestBindEntryGrantsAndHoldsAPodToItsEntry(t *testing.T) {
	gate, state, extended := exitsGate(t)
	pod := meshPod("default", "collector", testNetNS)
	if err := gate.bindEntry(pod, exitDecision{entry: "collector", exits: relayExit}); err != nil {
		t.Fatal(err)
	}
	if state.exitEntry != "collector" || len(*extended) != 1 {
		t.Fatalf("pod holds %q after %d extensions, want the collector's exit once", state.exitEntry, len(*extended))
	}
	if err := gate.bindEntry(pod, exitDecision{entry: "collector", exits: relayExit}); err != nil || len(*extended) != 1 {
		t.Fatalf("a restart of the same entry: err = %v, extensions = %d", err, len(*extended))
	}
	for name, decision := range map[string]exitDecision{
		"another entry":    {entry: "other"},
		"no entry":         {},
		"unreadable pod":   {undecided: errors.New("unresolved digest")},
		"refused outright": {refusal: errors.New("foreign")},
	} {
		if err := gate.bindEntry(pod, decision); err == nil {
			t.Fatalf("%s: a pod holding exits started it", name)
		}
	}
	if got := gate.grantedExits(pod.GetId()); !slices.Equal(got, relayExit) {
		t.Fatalf("granted exits = %v, want them unchanged", got)
	}
}

// Without exits held, an unreadable pod grants nothing and refuses nothing.
func TestBindEntryWithoutExitsHeld(t *testing.T) {
	gate, state, extended := exitsGate(t)
	pod := meshPod("default", "app", testNetNS)
	for _, decision := range []exitDecision{{}, {undecided: errors.New("no allowlist yet")}, {shadowed: []string{"collector"}}} {
		if err := gate.bindEntry(pod, decision); err != nil {
			t.Fatalf("bindEntry(%+v) = %v", decision, err)
		}
	}
	if state.exitEntry != "" || len(*extended) != 0 {
		t.Fatalf("pod holds %q after %d extensions, want nothing", state.exitEntry, len(*extended))
	}
}

// An exit into the cluster, onto this node, or to any service a platform role
// is bound to (CDS on every port) is refused before the ruleset is touched,
// and so is every exit where the node cannot name what is off limits.
func TestBindEntryRefusesAnExitIntoTheClusterOrOntoTheNode(t *testing.T) {
	for _, tc := range []struct {
		exit  string
		wants string
	}{
		{"10.52.3.0/24", "overlaps the cluster range 10.52.0.0/16"},
		{"10.0.0.0/8", "overlaps the cluster range 10.52.0.0/16"},
		{"10.0.2.15/32", "reaches 10.0.2.15"},
		{"10.43.0.5/32", "reaches 10.43.0.5"},
		{"10.43.0.4/30", "reaches 10.43.0.5"},
	} {
		gate, state, extended := exitsGate(t)
		pod := meshPod("default", "collector", testNetNS)
		exits := []exit{{Range: netip.MustParsePrefix(tc.exit), Port: 8400}}
		err := gate.bindEntry(pod, exitDecision{entry: "collector", exits: exits})
		if err == nil || !strings.Contains(err.Error(), tc.wants) {
			t.Fatalf("exit %s: err = %v, want %q", tc.exit, err, tc.wants)
		}
		if state.exitEntry != "" || len(*extended) != 0 {
			t.Fatalf("exit %s: a refused grant changed the pod", tc.exit)
		}
	}

	gate, _, _ := exitsGate(t)
	pod := meshPod("default", "collector", testNetNS)
	gate.nodeAddress = func() (netip.Addr, error) { return netip.Addr{}, errors.New("unknown") }
	if err := gate.bindEntry(pod, exitDecision{entry: "collector", exits: relayExit}); err == nil || !strings.Contains(err.Error(), "off this node") {
		t.Fatalf("err = %v, want a refusal without the node's address", err)
	}
	gate.nodeAddress = func() (netip.Addr, error) { return netip.MustParseAddr("10.0.2.15"), nil }
	gate.policy.ClusterRanges = nil
	if err := gate.bindEntry(pod, exitDecision{entry: "collector", exits: relayExit}); err == nil || !strings.Contains(err.Error(), "names no cluster ranges") {
		t.Fatalf("err = %v, want a refusal without cluster ranges", err)
	}
}

// Through StartContainer with a real inventory: a pod's outcome depends on the
// set of containers it runs, not on the order they start in, and a restart or
// a declared init container keeps the match.
func TestStartContainerDecidesExitsWhateverTheStartOrder(t *testing.T) {
	type start struct {
		digest string
		ok     bool
	}
	for _, tc := range []struct {
		name   string
		starts []start
		exits  bool
	}{
		{"collector alone", []start{{collectorDigest, true}}, true},
		{"declared init container, then collector", []start{{collectorInit, true}, {collectorDigest, true}}, true},
		{"collector restarted", []start{{collectorDigest, true}, {collectorDigest, true}}, true},
		{"collector, then a foreign container", []start{{collectorDigest, true}, {appDigest, false}}, true},
		{"a foreign container, then collector", []start{{appDigest, true}, {collectorDigest, false}}, false},
		{"an undeclared init container, then collector", []start{{appDigest, true}, {collectorInit, true}, {collectorDigest, false}}, false},
		{"app alone", []start{{appDigest, true}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}}, exitsAllowlist(t, ""))
			p.SetReady()
			p.inventory = newAdmissionInventory(t.TempDir())
			pod := meshPod("default", "pod", testNetNS)
			p.inventory.recordSandbox(pod.GetId())
			p.mesh.pods[pod.GetId()] = &protectedPod{netns: testNamespace(), kubeNamespace: "default"}
			extensions := 0
			p.mesh.extend = func(podNamespace, meshPolicy, string, []exit) error { extensions++; return nil }
			p.mesh.nodeAddress = func() (netip.Addr, error) { return netip.MustParseAddr("10.0.2.15"), nil }

			for i, s := range tc.starts {
				ctr := makeCtrWithImageArgs(pod.GetId(), fmt.Sprintf("c%d", i), "registry/repo@"+s.digest, []string{"/run"})
				err := p.StartContainer(context.Background(), pod, ctr)
				if (err == nil) != s.ok {
					t.Fatalf("start %d (%s): err = %v, want ok=%v", i, s.digest[:13], err, s.ok)
				}
			}
			if held := p.mesh.grantedExits(pod.GetId()) != nil; held != tc.exits || (tc.exits && extensions != 1) {
				t.Fatalf("exits held = %v after %d extensions, want %v once", held, extensions, tc.exits)
			}
		})
	}
}
