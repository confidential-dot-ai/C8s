package measurements

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

const (
	snpFixture = "testdata/confos-snp-manifest.json"
	tdxFixture = "testdata/confos-tdx-manifest.json"
)

// stageImage copies a build manifest into a directory named like a build
// output, since the entry name comes from that directory.
func stageImage(t *testing.T, fixture, name string) string {
	t.Helper()
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// An SNP image contributes one entry per vCPU variant, because the vCPU count
// is part of the launch measurement.
func TestDeriveSNPEntryPerVariant(t *testing.T) {
	dir := stageImage(t, snpFixture, "c8s-worker")

	set, err := derive([]string{dir}, "")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if set.Family != teetypes.FamilySNP {
		t.Errorf("tee = %q, want %q", set.Family, teetypes.FamilySNP)
	}
	if len(set.Images) != 4 {
		t.Fatalf("got %d entries, want one per snp_variants entry", len(set.Images))
	}
	for _, want := range []string{"c8s-worker-smp2", "c8s-worker-smp4", "c8s-worker-smp8", "c8s-worker-smp16"} {
		if !hasEntry(set.Images, want) {
			t.Errorf("no entry named %q; got %v", want, names(set.Images))
		}
	}
	for _, e := range set.Images {
		if len(e.Registers) != 0 {
			t.Errorf("SNP entry %s carries RTMR pins", e.Name)
		}
	}
}

// A TDX image pins MRTD with RTMR[1] and RTMR[2]; RTMR[0] varies with the VM
// shape and RTMR[3] is extended at runtime.
func TestDeriveTDXPinsTheTuple(t *testing.T) {
	dir := stageImage(t, tdxFixture, "c8s-broker")

	set, err := derive([]string{dir}, "")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if set.Family != teetypes.FamilyTDX {
		t.Errorf("tee = %q, want %q", set.Family, teetypes.FamilyTDX)
	}
	if len(set.Images) != 1 {
		t.Fatalf("got %d entries, want 1", len(set.Images))
	}
	e := set.Images[0]
	if e.Name != "c8s-broker" {
		t.Errorf("name = %q, want the image directory name", e.Name)
	}
	if _, pinned := e.Registers[0]; pinned {
		t.Error("RTMR[0] pinned: it varies with vCPU and memory shape")
	}
	if _, pinned := e.Registers[3]; pinned {
		t.Error("RTMR[3] pinned: it is extended by in-guest software")
	}
	for _, idx := range []int{1, 2} {
		if len(e.Registers[idx]) != refvalues.DigestSize {
			t.Errorf("RTMR[%d] = %d bytes, want %d", idx, len(e.Registers[idx]), refvalues.DigestSize)
		}
	}
}

// Whatever derive emits must load everywhere, so it round-trips through the
// same parser every component uses.
func TestDeriveOutputParses(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"snp", snpFixture},
		{"tdx", tdxFixture},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := derive([]string{stageImage(t, tc.fixture, "img")}, "")
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			doc, err := refvalues.Format(set)
			if err != nil {
				t.Fatalf("format: %v", err)
			}
			reparsed, err := refvalues.Parse(doc)
			if err != nil {
				t.Fatalf("derived config does not parse: %v\n%s", err, doc)
			}
			if len(reparsed.Images) != len(set.Images) || reparsed.Family != set.Family {
				t.Errorf("round trip changed the config: %d/%s vs %d/%s",
					len(reparsed.Images), reparsed.Family, len(set.Images), set.Family)
			}
		})
	}
}

// Merging images of different platforms would produce a config no cluster can
// use, since one file describes one platform.
func TestDeriveRefusesMixedPlatforms(t *testing.T) {
	snp := stageImage(t, snpFixture, "worker")
	tdx := stageImage(t, tdxFixture, "broker")

	if _, err := derive([]string{snp, tdx}, ""); err == nil {
		t.Fatal("merged an SNP and a TDX image into one config")
	}
}

func TestDeriveMergesImagesOfOnePlatform(t *testing.T) {
	a := stageImage(t, tdxFixture, "leader")
	b := stageImage(t, tdxFixture, "worker")

	set, err := derive([]string{a, b}, "")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(set.Images) != 2 {
		t.Fatalf("got %d entries, want one per image", len(set.Images))
	}
	if !hasEntry(set.Images, "leader") || !hasEntry(set.Images, "worker") {
		t.Errorf("entries = %v, want both image names", names(set.Images))
	}
}

// A manifest built for both platforms carries two sets of values, so the
// caller has to say which one the cluster runs.
func TestDeriveMultiPlatformNeedsTEE(t *testing.T) {
	dir := stageImage(t, snpFixture, "img")
	patchManifest(t, dir, func(m map[string]any) {
		m["build"].(map[string]any)["platform"] = "multi"
	})

	_, err := derive([]string{dir}, "")
	if err == nil {
		t.Fatal("derived from a multi-platform manifest without --tee")
	}
	if !strings.Contains(err.Error(), "--tee") {
		t.Errorf("error %q does not name the flag that resolves it", err)
	}
	if _, err := derive([]string{dir}, string(teetypes.FamilySNP)); err != nil {
		t.Fatalf("--tee did not resolve the ambiguity: %v", err)
	}
}

func TestDeriveRefusesTEEItsManifestIsNotBuiltFor(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		tee     string
		built   teetypes.Family
		asked   teetypes.Family
	}{
		{
			fixture: snpFixture,
			tee:     "tdx",
			built:   teetypes.FamilySNP,
			asked:   teetypes.FamilyTDX,
		},
		{
			fixture: snpFixture,
			tee:     "gcp-tdx",
			built:   teetypes.FamilySNP,
			asked:   teetypes.FamilyTDX,
		},
		{
			fixture: tdxFixture,
			tee:     "sev-snp",
			built:   teetypes.FamilyTDX,
			asked:   teetypes.FamilySNP,
		},
	} {
		t.Run(tc.tee, func(t *testing.T) {
			_, err := derive([]string{stageImage(t, tc.fixture, "img")}, tc.tee)
			if err == nil {
				t.Fatalf("derived a %s config from an image built for %s", tc.asked, tc.built)
			}
			if !strings.Contains(err.Error(), "--tee asks for "+string(tc.asked)) {
				t.Errorf("error %q does not name the platform --tee asks for", err)
			}
			if !strings.Contains(err.Error(), "is built for "+string(tc.built)) {
				t.Errorf("error %q does not name the platform the image is built for", err)
			}
		})
	}
}

func TestDeriveAcceptsTheTEEItsManifestIsBuiltFor(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		tee     string
		want    teetypes.Family
	}{
		{
			fixture: snpFixture,
			tee:     "sev-snp",
			want:    teetypes.FamilySNP,
		},
		{
			fixture: snpFixture,
			tee:     "az-snp",
			want:    teetypes.FamilySNP,
		},
		{
			fixture: tdxFixture,
			tee:     "tdx",
			want:    teetypes.FamilyTDX,
		},
	} {
		t.Run(tc.tee, func(t *testing.T) {
			set, err := derive([]string{stageImage(t, tc.fixture, "img")}, tc.tee)
			if err != nil {
				t.Fatalf("derive --tee %s: %v", tc.tee, err)
			}
			if set.Family != tc.want {
				t.Errorf("tee = %q, want %q", set.Family, tc.want)
			}
		})
	}
}

// confos rejects manifests of another schema version rather than migrating
// them; reading one anyway would pin fields that may have moved.
func TestDeriveRejectsOtherSchemaVersion(t *testing.T) {
	dir := stageImage(t, snpFixture, "img")
	patchManifest(t, dir, func(m map[string]any) { m["version"] = 2 })

	_, err := derive([]string{dir}, "")
	if err == nil {
		t.Fatal("derived from a version 2 manifest")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("error %q does not mention the schema version", err)
	}
}

func TestDeriveRejectsBadInput(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	if _, err := derive([]string{missing}, ""); err == nil {
		t.Error("accepted a path that does not exist")
	}
	if _, err := derive([]string{stageImage(t, snpFixture, "img")}, "sev"); err == nil {
		t.Error("accepted an unknown --tee value")
	}
}

// A manifest path is accepted directly, and names the entry after the
// directory holding it.
func TestDeriveAcceptsManifestPath(t *testing.T) {
	dir := stageImage(t, tdxFixture, "direct")

	set, err := derive([]string{filepath.Join(dir, "manifest.json")}, "")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if set.Images[0].Name != "direct" {
		t.Errorf("name = %q, want %q", set.Images[0].Name, "direct")
	}
}

func TestLintReportsAProblem(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	bad := filepath.Join(dir, "bad.json")

	set, err := derive([]string{stageImage(t, tdxFixture, "img")}, "")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := refvalues.Format(set)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte(`{"schema_version":"1","tee":"tdx","measurements":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newLintCmd()
	cmd.SetOut(new(strings.Builder))
	cmd.SetArgs([]string{good})
	if err := cmd.Execute(); err != nil {
		t.Errorf("lint rejected a derived config: %v", err)
	}

	cmd = newLintCmd()
	cmd.SetOut(new(strings.Builder))
	cmd.SetArgs([]string{bad})
	if err := cmd.Execute(); err == nil {
		t.Error("lint accepted a config pinning no image")
	}
}

func TestDeriveCmdWritesTheOutFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "measurements.json")

	cmd := newDeriveCmd()
	cmd.SetOut(new(strings.Builder))
	cmd.SetArgs([]string{"--out", out, stageImage(t, snpFixture, "img")})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("derive: %v", err)
	}
	if _, err := refvalues.Load(out); err != nil {
		t.Fatalf("written config does not load: %v", err)
	}
}

func patchManifest(t *testing.T, dir string, edit func(map[string]any)) {
	t.Helper()
	path := filepath.Join(dir, "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	patched, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, patched, 0o600); err != nil {
		t.Fatal(err)
	}
}

func hasEntry(images []remote.ImagePin, name string) bool {
	for _, img := range images {
		if img.Name == name {
			return true
		}
	}
	return false
}

func names(images []remote.ImagePin) []string {
	out := make([]string, 0, len(images))
	for _, img := range images {
		out = append(out, img.Name)
	}
	return out
}

// With no --out the config goes to stdout, so it can be piped.
func TestDeriveCmdWritesStdout(t *testing.T) {
	var out strings.Builder
	cmd := newDeriveCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{stageImage(t, tdxFixture, "img")})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("derive: %v", err)
	}
	if _, err := refvalues.Parse([]byte(out.String())); err != nil {
		t.Fatalf("stdout is not a loadable config: %v\n%s", err, out.String())
	}
}

func TestDeriveCmdRefusesAnotherTEE(t *testing.T) {
	out := filepath.Join(t.TempDir(), "measurements.json")

	cmd := newDeriveCmd()
	cmd.SetOut(new(strings.Builder))
	cmd.SetErr(new(strings.Builder))
	cmd.SetArgs([]string{"--tee", "tdx", "--out", out, snpFixture})
	if err := cmd.Execute(); err == nil {
		t.Fatal("derive --tee tdx accepted an image built for sev-snp")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("derive wrote %s after refusing --tee (stat: %v)", out, err)
	}
}

func TestDeriveCmdReportsBadInput(t *testing.T) {
	cmd := newDeriveCmd()
	cmd.SetOut(new(strings.Builder))
	cmd.SetErr(new(strings.Builder))
	cmd.SetArgs([]string{filepath.Join(t.TempDir(), "absent")})
	if err := cmd.Execute(); err == nil {
		t.Fatal("derive accepted a path that does not exist")
	}
}
