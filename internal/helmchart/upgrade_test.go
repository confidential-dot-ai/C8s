package helmchart

import (
	"slices"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A configuration-only upgrade keeps every image digest but changes the
// operator's argv and so the installer's boot config. CDS seeds additively at
// startup, so the upgraded seed must name the new shapes apart from the old
// ones: after both seeds, the old and the new operator and installer launches
// are all admitted.
func TestChartConfigOnlyUpgradeAdmitsOldAndNewShapes(t *testing.T) {
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
	for _, out := range []string{before, after} {
		if _, err := store.SeedWorkloads(renderedSeed(t, out).Workloads); err != nil {
			t.Fatal(err)
		}
	}
	live, _, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	index := live.BuildIndex()

	operatorDigest := componentTestDigests["image"]
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
					mounts := observedMounts(t, w.spec, c, true)
					if !index.AdmitsContainer(pkgallowlist.RunningContainer{Digest: digest, Argv: runtimeArgv(c, pins[digest]), Mounts: mounts, Env: &pkgallowlist.EnvObservation{}}) {
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
