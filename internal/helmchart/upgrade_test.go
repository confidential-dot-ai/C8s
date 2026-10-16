package helmchart

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A configuration-only upgrade keeps every image digest but changes the
// operator's argv and so the installer's boot config. The store starts with
// the previous release's policies only, which admit neither new launch. CDS
// keeps its shape, so the old boot base still admits it and it is not
// recreated. Once the new seed is published (c8s allowlist apply, or
// cds.followSeed), the old and the new launches are all admitted.
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
	if got, want := cdsShapeAnnotation(t, after), cdsShapeAnnotation(t, before); got == "" || got != want {
		t.Fatalf("CDS shape %q after the upgrade, want unchanged %q", got, want)
	}
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
			mounts := observedMounts(t, w.spec, c, true)
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
					mounts := observedMounts(t, w.spec, c, true)
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

// cdsShapeAnnotation is the CDS shape the rendered Deployment records for the
// next upgrade's guard.
func cdsShapeAnnotation(t *testing.T, out string) string {
	t.Helper()
	for _, doc := range strings.Split(out, "\n---") {
		var obj struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name        string            `json:"name"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
		}
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil || obj.Kind != "Deployment" || obj.Metadata.Name != "c8s-cds" {
			continue
		}
		return obj.Metadata.Annotations["confidential.ai/cds-shape"]
	}
	t.Fatal("no c8s-cds Deployment rendered")
	return ""
}

// A changed CDS command line fails the upgrade until its entry is published:
// otherwise the old CDS stops and the enforcers refuse the new one. So does a
// running CDS the render cannot see.
func TestCDSShapeGuard(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm CLI not found")
	}
	dir := t.TempDir()
	tpl, err := os.ReadFile("c8s/templates/_upgrade.tpl")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"Chart.yaml":             "apiVersion: v2\nname: guard\nversion: 0.0.1\n",
		"templates/_upgrade.tpl": string(tpl),
		"templates/guard.yaml":   `{{ include "c8s.cdsShapeGuard" (dict "live" .Values.live "want" .Values.want "published" .Values.published) }}`,
	}
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, live, want, published string
		fails                       bool
	}{
		{name: "first install", live: "none", want: "cds-new"},
		{name: "unchanged", live: "cds-old", want: "cds-old"},
		{name: "not digest-pinned", live: "cds-old"},
		{name: "changed and unpublished", live: "cds-old", want: "cds-new", fails: true},
		{name: "changed and another shape published", live: "cds-old", want: "cds-new", published: "cds-old", fails: true},
		{name: "changed and published", live: "cds-old", want: "cds-new", published: "cds-new"},
		{name: "unknown", want: "cds-new", fails: true},
		{name: "unknown and published", want: "cds-new", published: "cds-new"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := exec.Command("helm", "template", "g", dir,
				"--set-string", "live="+tc.live, "--set-string", "want="+tc.want, "--set-string", "published="+tc.published).CombinedOutput()
			if (err != nil) != tc.fails {
				t.Fatalf("render error = %v, want failure %t\n%s", err, tc.fails, out)
			}
			if tc.fails && !strings.Contains(string(out), "cds.publishedShape="+tc.want) {
				t.Errorf("failure does not name the entry to publish:\n%s", out)
			}
			// A CDS recreated since the nodes last pulled counts from a lower
			// version, which the nodes ignore until it passes theirs.
			if tc.fails && !strings.Contains(string(out), "above every allowlist_version the nodes' image policy plugins reported") {
				t.Errorf("failure does not require publication past the nodes' versions:\n%s", out)
			}
			if tc.fails && tc.live == "" && !strings.Contains(string(out), "cds.liveShape=none") {
				t.Errorf("failure on an unknown CDS does not name cds.liveShape:\n%s", out)
			}
		})
	}
}

// A digest bump alone changes the CDS shape, so it trips the guard against
// the shape a live Deployment records. helm template cannot look one up, so
// cds.liveShape stands in for the annotation.
func TestChartCDSDigestBumpTripsShapeGuard(t *testing.T) {
	t.Parallel()
	before, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, before)
	}
	live := cdsShapeAnnotation(t, before)
	const bumped = "sha256:c100000000000000000000000000000000000000000000000000000000000000"
	out, err := helmTemplate(t, "--set-string", "cds.liveShape="+live, "--set", "cds.image.digest="+bumped)
	if err == nil {
		t.Fatalf("a CDS digest bump rendered without its shape published")
	}
	msg := helmFailMessage(t, out)
	if !strings.Contains(msg, "CDS image, command line or mounts") || !strings.Contains(msg, "cds.publishedShape=cds-c10000000000-") {
		t.Fatalf("guard failure = %q, want the image named as a cause and the bumped entry to publish", msg)
	}
	if out, err := helmTemplate(t, "--set-string", "cds.liveShape="+live); err != nil {
		t.Fatalf("an unchanged CDS against its live shape: %v\n%s", err, out)
	}
}

// Matching ignores the image label, so a mirror of the same digest keeps the
// entry's name: seeding it again adds nothing and the match stays unambiguous.
func TestChartEntryNamesIgnoreImageRepository(t *testing.T) {
	t.Parallel()
	const cdsDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	names := func(out string) []string {
		var got []string
		for name, w := range renderedSeed(t, out).Workloads {
			for _, c := range slices.Concat(w.InitContainers, w.Containers) {
				if c.Digest.String() == cdsDigest {
					got = append(got, name)
					break
				}
			}
		}
		slices.Sort(got)
		return got
	}
	upstream, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, upstream)
	}
	mirrored, err := helmTemplate(t, "--set", "cds.image.repository=mirror.example/c8s/cds")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, mirrored)
	}
	want := names(upstream)
	if len(want) == 0 {
		t.Fatal("no seed entry for the CDS digest")
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

// Following the seed lets whoever edits its ConfigMap publish entries, so CDS
// with operator keys follows it only when cds.followSeed asks. Without keys
// the seed is the only way to publish, so CDS follows it.
func TestChartCDSFollowsSeedOnlyWhenAsked(t *testing.T) {
	t.Parallel()
	keys := filepath.Join(t.TempDir(), "operator.pub")
	if err := os.WriteFile(keys, []byte("-----BEGIN PUBLIC KEY-----\nMFkwfakefakefake\n-----END PUBLIC KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withKeys := []string{"--set-file", "cds.operatorKeys=" + keys}
	for _, tc := range []struct {
		name   string
		args   []string
		follow bool
	}{
		{name: "default", args: withKeys},
		{name: "off", args: append(slices.Clone(withKeys), "--set", "cds.followSeed=false")},
		{name: "on", args: append(slices.Clone(withKeys), "--set", "cds.followSeed=true"), follow: true},
		{name: "no operator keys", args: []string{"--set", "cds.followSeed=false"}, follow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
			if got := slices.Contains(args, "--follow-seed"); got != tc.follow {
				t.Errorf("CDS args contain --follow-seed = %t, want %t: %q", got, tc.follow, args)
			}
		})
	}
}
