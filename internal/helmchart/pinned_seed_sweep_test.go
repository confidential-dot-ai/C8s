//go:build !c8s_node

package helmchart

import (
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// The c8s uninstall host sweep runs the nri-image-policy image with two argv
// shapes of its own (the sweep script, then a /bin/sleep pause). The served
// seed must admit exactly those argvs: on a node whose plugin is still
// enforcing from its in-memory snapshot, a pin the sweep's argv does not
// satisfy deadlocks the uninstall fail-closed.
func TestChartPinnedSeedAdmitsHostSweepArgv(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--set", "nriImagePolicy.baked=true"},
	} {
		out, err := helmTemplate(t, args...)
		if err != nil {
			t.Fatalf("helm template %v: %v\n%s", args, err, out)
		}
		seed := renderedSeed(t, out)

		admitArgvs(t, seed, baseNRIDigest, []string{"/bin/sh", "-c", HostSweepScript()})
		admitArgvs(t, seed, baseNRIDigest, []string{"/bin/sleep", "2147483647"})
		denyArgvs(t, seed, baseNRIDigest, []string{"/bin/sh", "-c", HostSweepScript() + "\nrm -rf /"})
		denyArgvs(t, seed, baseNRIDigest, []string{"/bin/sleep", "2147483648"})
	}
}

// c8s uninstall replays the pinned sweep argvs out of the release's seed
// (resolveSweepArgvs), identifying the shapes by content: the script carries
// the script's own "c8s host sweep" banner; the pause is the entry's one
// shape not running /bin/sh -c. Each rule must match exactly one pinned
// container — a second match makes the replay ambiguous and fails it closed.
func TestChartPinnedSeedHostSweepShapesUnique(t *testing.T) {
	if !strings.Contains(HostSweepScript(), "c8s host sweep") {
		t.Fatal("HostSweepScript lost its \"c8s host sweep\" banner — resolveSweepArgvs selects the script shape by it")
	}
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	digest, err := types.ParseDigest(baseNRIDigest)
	if err != nil {
		t.Fatal(err)
	}
	prefix := pkgallowlist.DigestEntryName(digest, "ghcr.io/confidential-dot-ai/nri-image-policy@"+baseNRIDigest)
	name := generatedEntryName(seed, prefix)
	entry, ok := seed.Workloads[name]
	if !ok {
		t.Fatalf("seed has no entry %q-<policy>", prefix)
	}
	var scriptHits, pauseHits int
	for _, c := range entry.Containers {
		if c.Command.Policy != pkgallowlist.PolicyExact || c.Args.Policy != pkgallowlist.PolicyExact {
			continue
		}
		argv := append(append([]string{}, c.Command.Argv...), c.Args.Argv...)
		if len(argv) == 0 {
			continue
		}
		if strings.Contains(argv[len(argv)-1], "c8s host sweep") {
			scriptHits++
		}
		if argv[0] != "/bin/sh" || len(argv) == 1 || argv[1] != "-c" {
			pauseHits++
		}
	}
	if scriptHits != 1 {
		t.Errorf("entry %q: %d host-sweep script shapes, want exactly 1", name, scriptHits)
	}
	if pauseHits != 1 {
		t.Errorf("entry %q: %d non-/bin/sh -c shapes, want exactly 1 (the sweep pause)", name, pauseHits)
	}
}
