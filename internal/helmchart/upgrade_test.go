package helmchart

import (
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A configuration-only upgrade keeps every image digest but changes the
// operator's argv and so the installer's boot config. The store starts with
// the previous release's policies only, which admit neither new launch. CDS
// keeps its shape, so the old boot base still admits it and it is not
// recreated. Once the new seed is published (c8s allowlist apply), the old
// and the new launches are all admitted.
func TestChartConfigOnlyUpgradeAdmitsOldAndNewShapes(t *testing.T) {
	t.Parallel()
	args := []string{"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true"}
	for valuePath, digest := range componentTestDigests {
		args = append(args, "--set", valuePath+".digest="+digest)
	}
	before, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, before)
	}
	upgraded := append(slices.Clone(args), "--set-json", `operator.extraArgs=["--zap-log-level=debug"]`)
	after, err := helmTemplate(t, upgraded...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, after)
	}

	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.SeedWorkloads(renderedSeed(t, before).Workloads); err != nil {
		t.Fatal(err)
	}
	operatorDigest := componentTestDigests["image"]
	previous, _, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range renderedPodSpecs(t, after) {
		if w.name != "c8s-operator" {
			continue
		}
		for _, c := range w.spec.Containers {
			if imageDigest(c.Image) != operatorDigest {
				continue
			}
			mounts := observedMounts(t, w.spec, c)
			pin := componentPins(t, after, args)[operatorDigest]
			if previous.BuildIndex().AdmitsContainer(pkgallowlist.RunningContainer{Digest: operatorDigest, Argv: runtimeArgv(c, pin.entrypoint), Mounts: mounts, Env: launchEnv(t, w.spec, c, pin.imageEnv)}) {
				t.Fatalf("previous policies admit the upgraded operator container %s; the test no longer exercises a policy change", c.Name)
			}
		}
	}
	if _, _, err := store.SeedWorkloads(renderedSeed(t, after).Workloads); err != nil {
		t.Fatal(err)
	}
	live, _, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	index := live.BuildIndex()

	for release, out := range map[string]string{"before": before, "after": after} {
		pins := componentPins(t, out, args)
		checked := map[string]int{}
		for _, w := range renderedPodSpecs(t, out) {
			for _, c := range slices.Concat(w.spec.InitContainers, w.spec.Containers) {
				switch digest := imageDigest(c.Image); digest {
				case operatorDigest:
					if w.name != "c8s-operator" {
						continue
					}
					checked["operator"]++
					mounts := observedMounts(t, w.spec, c)
					if !index.AdmitsContainer(pkgallowlist.RunningContainer{Digest: digest, Argv: runtimeArgv(c, pins[digest].entrypoint), Mounts: mounts, Env: launchEnv(t, w.spec, c, pins[digest].imageEnv)}) {
						t.Errorf("%s: operator container %s refused after both seeds", release, c.Name)
					}
				case baseNRIDigest:
					if w.name != "c8s-nri-image-policy-worker" {
						continue
					}
					checked["installer"]++
					admitPlatformContainer(t, live, digest, c)
				}
			}
		}
		if checked["operator"] == 0 || checked["installer"] == 0 {
			t.Fatalf("%s: checked %v, want the operator and the installer", release, checked)
		}
	}
}

// Matching ignores the image label, so a mirror of the same digest keeps the
// entry's name: seeding it again adds nothing and the match stays unambiguous.
// volumed is the subject because its argv names no image of its own.
func TestChartEntryNamesIgnoreImageRepository(t *testing.T) {
	t.Parallel()
	const volumedDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	names := func(out string) []string {
		var got []string
		for name, w := range renderedSeed(t, out).Workloads {
			for _, c := range slices.Concat(w.InitContainers, w.Containers) {
				if c.Digest.String() == volumedDigest {
					got = append(got, name)
					break
				}
			}
		}
		slices.Sort(got)
		return got
	}
	derived := []string{
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set", "volumed.enabled=true",
		"--set-string", "volumed.image.digest=" + volumedDigest,
	}
	upstream, err := helmTemplate(t, derived...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, upstream)
	}
	mirrored, err := helmTemplate(t, append(derived, "--set", "volumed.image.repository=mirror.example/c8s/volumed")...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, mirrored)
	}
	want := names(upstream)
	if len(want) == 0 {
		t.Fatal("no seed entry for the volumed digest")
	}
	if got := names(mirrored); !slices.Equal(got, want) {
		t.Errorf("entry names under a mirror = %v, want %v", got, want)
	}
}

// A release before per-shape names seeded each component as
// DigestEntryName with open args and mounts, and one before env matching
// seeded each shape with env any; the current seed must retire both.
func TestChartSeedRetiresPreShapeComponentEntries(t *testing.T) {
	args := []string{"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true"}
	for valuePath, digest := range componentTestDigests {
		args = append(args, "--set", valuePath+".digest="+digest)
	}
	out, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out).Workloads
	old := map[string]pkgallowlist.Workload{}
	for name, w := range seed {
		if len(w.Containers) == 0 {
			continue
		}
		c := w.Containers[0]
		if c.Command.Policy != pkgallowlist.PolicyExact || c.Args.Policy != pkgallowlist.PolicyExact {
			continue
		}
		openEnv := slices.Clone(w.Containers)
		for i := range openEnv {
			openEnv[i].Env = pkgallowlist.EnvPolicy{Policy: pkgallowlist.PolicyAny}
		}
		c.Args, c.Mounts, c.Env = pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny}, pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyAny}, pkgallowlist.EnvPolicy{Policy: pkgallowlist.PolicyAny}
		if openArgs, _, _ := allowlist.OpenComponent(c); !openArgs || strings.HasPrefix(name, "c8s-router-") {
			continue
		}
		// The shape name less its 8-hex policy hash: c8s.digestWorkloadName.
		old[name[:len(name)-9]] = pkgallowlist.Workload{Label: w.Label, InitContainers: []pkgallowlist.Container{}, Containers: []pkgallowlist.Container{c}}
		old[name[:len(name)-8]+"00000000"] = pkgallowlist.Workload{Label: w.Label, InitContainers: []pkgallowlist.Container{}, Containers: openEnv}
	}
	if len(old) == 0 {
		t.Fatal("no component shape in the rendered seed")
	}
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.SeedWorkloads(old); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.SeedWorkloads(seed); err != nil {
		t.Fatal(err)
	}
	live, _, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	for name := range old {
		if _, ok := live.Workloads[name]; ok {
			t.Errorf("pre-shape entry %q survived the seed", name)
		}
	}
}
