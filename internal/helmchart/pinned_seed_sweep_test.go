//go:build !c8s_node

package helmchart

import (
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
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)

	admitArgvs(t, seed, baseNRIDigest, []string{"/bin/sh", "-c", HostSweepScript()})
	admitArgvs(t, seed, baseNRIDigest, []string{"/bin/sleep", "2147483647"})
	denyArgvs(t, seed, baseNRIDigest, []string{"/bin/sh", "-c", HostSweepScript() + "\nrm -rf /"})
	denyArgvs(t, seed, baseNRIDigest, []string{"/bin/sleep", "2147483648"})
}

// A node whose plugin restarted before the sweep ran has no served allowlist,
// so the boot base is what must admit the sweep.
func TestChartBootConfigAdmitsTheHostSweepArgv(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	base := &cfg.Allowlist.Base

	admitArgvs(t, base, baseNRIDigest, []string{"/bin/sh", "-c", HostSweepScript()})
	admitArgvs(t, base, baseNRIDigest, []string{"/bin/sleep", "2147483647"})
	denyArgvs(t, base, baseNRIDigest, []string{"/bin/sh", "-c", HostSweepScript() + "\nrm -rf /"})
	denyArgvs(t, base, baseNRIDigest, installerArgv(t, out))
}

func installerArgv(t *testing.T, manifest string) []string {
	t.Helper()
	worker := renderedDaemonSet(t, manifest, "c8s-nri-image-policy-worker")
	install, ok := findContainer(worker.Spec.Template.Spec.InitContainers, "install")
	if !ok {
		t.Fatal("the installer DaemonSet has no install init container")
	}
	return effectiveArgv(install)
}

// c8s uninstall replays the pinned sweep argvs out of the release's seed
// (resolveSweepArgvs): the script is the IsHostSweepScript shape, the pause
// the entry's one shape not running /bin/sh -c. Two matches for either rule
// make the replay ambiguous and fail it closed.
func TestChartPinnedSeedHostSweepShapesUnique(t *testing.T) {
	t.Parallel()
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
		if IsHostSweepScript(argv) {
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
