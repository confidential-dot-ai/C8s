package helmchart

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// entriesFor names the workloads with a container running digest, but for
// the router's entry, which pins the c8s image beside nginx.
func entriesFor(doc *pkgallowlist.Allowlist, digest string) []string {
	var names []string
	for name, w := range doc.Workloads {
		if !strings.HasPrefix(name, "c8s-router-") && slices.ContainsFunc(slices.Concat(w.InitContainers, w.Containers), func(c pkgallowlist.Container) bool {
			return strings.EqualFold(c.Digest.String(), digest)
		}) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// An operator entry named <image>-<12 hex> replaces the chart's generated
// entry for that digest in the boot base as in the seed. Kept beside it in the
// base, the generated entry would admit what the override narrows.
func TestChartOverrideReplacesGeneratedEntryInSeedAndBase(t *testing.T) {
	t.Parallel()
	const opD = "sha256:abcdef0000000000000000000000000000000000000000000000000000000012"
	args := []string{"--set-string", "image.digest=" + opD, "--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true"}
	derived, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, derived)
	}
	seed := renderedSeed(t, derived)
	generated := entriesFor(seed, opD)
	if len(generated) != 1 {
		t.Fatalf("seed entries for the operator digest = %v, want one generated entry", generated)
	}
	entry := seed.Workloads[generated[0]]
	digest, err := types.ParseDigest(opD)
	if err != nil {
		t.Fatal(err)
	}
	override := pkgallowlist.DigestEntryName(digest, entry.Label)
	raw, err := json.Marshal(map[string]any{"label": entry.Label, "containers": entry.Containers})
	if err != nil {
		t.Fatal(err)
	}
	out, err := helmTemplate(t, append(args, "--set-json", "nriImagePolicy.bootstrapAllowlist.workloads."+override+"="+string(raw))...)
	if err != nil {
		t.Fatalf("helm template with the override: %v\n%s", err, out)
	}
	if got := entriesFor(renderedSeed(t, out), opD); !slices.Equal(got, []string{override}) {
		t.Errorf("seed entries for the operator digest = %v, want only the override %s", got, override)
	}
	base := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist.Base
	if got := entriesFor(&base, opD); !slices.Equal(got, []string{override}) {
		t.Errorf("base entries for the operator digest = %v, want only the override %s", got, override)
	}
}

// An override named for the installer's digest replaces its argv-pinned
// entry, so a narrower one takes effect: admission is the union across
// entries. The seed then holds one entry for the digest, which is what c8s
// uninstall needs to replay the host sweep from it.
func TestChartOverrideReplacesArgvPinnedEntry(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	pinned := entriesFor(seed, baseNRIDigest)
	if len(pinned) != 1 {
		t.Fatalf("seed entries for the installer digest = %v, want one", pinned)
	}
	entry := seed.Workloads[pinned[0]]
	narrowed := 0
	for i, c := range entry.Containers {
		if c.Args.Policy == pkgallowlist.PolicyExact && len(c.Args.Argv) == 1 && strings.Contains(c.Args.Argv[0], "c8s host sweep") {
			entry.Containers[i].Mounts = pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyDeny}
			narrowed++
		}
	}
	if narrowed != 1 {
		t.Fatalf("narrowed %d host-sweep containers, want 1", narrowed)
	}
	digest, err := types.ParseDigest(baseNRIDigest)
	if err != nil {
		t.Fatal(err)
	}
	override := pkgallowlist.DigestEntryName(digest, entry.Label)
	raw, err := json.Marshal(map[string]any{"label": entry.Label, "containers": entry.Containers})
	if err != nil {
		t.Fatal(err)
	}
	out, err = helmTemplate(t, "--set-json", "nriImagePolicy.bootstrapAllowlist.workloads."+override+"="+string(raw))
	if err != nil {
		t.Fatalf("helm template with the override: %v\n%s", err, out)
	}
	seed = renderedSeed(t, out)
	if got := entriesFor(seed, baseNRIDigest); !slices.Equal(got, []string{override}) {
		t.Fatalf("seed entries for the installer digest = %v, want only the override %s", got, override)
	}
	for _, c := range seed.Workloads[override].Containers {
		if len(c.Args.Argv) == 1 && strings.Contains(c.Args.Argv[0], "c8s host sweep") && c.Mounts.Policy != pkgallowlist.PolicyDeny {
			t.Errorf("host-sweep mounts = %s, want the override's deny", c.Mounts.Policy)
		}
	}
}

// An override admitting CDS replaces its generated entry in the seed.
func TestChartCDSOverrideReplacesGeneratedEntry(t *testing.T) {
	t.Parallel()
	base, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, base)
	}
	seed := renderedSeed(t, base)
	live := cdsShapeAnnotation(t, base)
	entry, ok := seed.Workloads[live]
	if !ok {
		t.Fatalf("seed has no entry %s for the CDS shape", live)
	}
	digest := entry.Containers[0].Digest
	override := pkgallowlist.DigestEntryName(digest, entry.Label)
	raw, err := json.Marshal(map[string]any{"label": entry.Label, "containers": entry.Containers})
	if err != nil {
		t.Fatal(err)
	}
	out, err := helmTemplate(t, "--set-json", "nriImagePolicy.bootstrapAllowlist.workloads."+override+"="+string(raw))
	if err != nil {
		t.Fatalf("helm template with the override: %v\n%s", err, out)
	}
	if got := entriesFor(renderedSeed(t, out), digest.String()); !slices.Equal(got, []string{override}) {
		t.Errorf("seed entries for the CDS digest = %v, want only the override %s", got, override)
	}
}
