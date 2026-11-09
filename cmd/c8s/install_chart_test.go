//go:build !c8s_node

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
)

func TestInstallFromAnUnreleasedBuildNeedsChart(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))
	setCLIVersion(t, "v0.92.0-3-gabc1234")
	err := runInstall(t, "--platform=aks-snp", "--wait=false", "--force")
	if err == nil || !strings.Contains(err.Error(), "not a release build") || !strings.Contains(err.Error(), "--chart") {
		t.Fatalf("want the unreleased-build refusal naming --chart, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm pull")
	mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
}

// --chart renders the named chart with the image values its -f files set.
func TestInstallRendersTheChartFlagsChart(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))
	setCLIVersion(t, "dev")
	dir, err := helmchart.ExtractTemp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	chart := filepath.Join(dir, helmchart.CloudChartFSPath)
	if err := runInstall(t, "--chart", chart, "--platform=aks-snp", "--wait=false", "--force"); err != nil {
		t.Fatalf("install: %v", err)
	}
	calls := s.f.calls(t)
	mustNotContainPrefix(t, calls, "helm pull")
	mustContainLine(t, calls, "helm upgrade --install c8s "+chart+" --namespace c8s-system -f "+filepath.Join(chart, "values-aks-snp.yaml")+" -f "+lastValuesFile(t, calls))
	if image := readYAMLTree(t, s.computed)["image"]; image != nil {
		t.Errorf("computed values pin image %v, want the chart's own", image)
	}
}

// A typo'd --chart is named before anything renders.
func TestInstallChartFlagNamesNoChart(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))
	err := runInstall(t, "--chart", filepath.Join(t.TempDir(), "absent"), "--platform=aks-snp", "--wait=false", "--force")
	if err == nil || !strings.Contains(err.Error(), "names no chart directory") {
		t.Fatalf("want the --chart refusal, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
}

func TestReleaseImagePinsReadOnlyRepositoryAndDigest(t *testing.T) {
	components := []c8sComponent{
		{valuesPath: "image", repository: "ghcr.io/x/op"},
		{valuesPath: "volumed.image", repository: "ghcr.io/x/volumed"},
	}
	for name, tc := range map[string]struct {
		values  string
		wantErr string
	}{
		"pins each repository at its release digest": {values: stampedValues("{repository: ghcr.io/x/op, digest: " + testDigest + "}")},
		"another repository":                         {values: stampedValues("{repository: ghcr.io/x/other, digest: " + testDigest + "}"), wantErr: "image.repository is ghcr.io/x/other, want the bundled chart's ghcr.io/x/op"},
		"a digest that is not sha256":                {values: stampedValues("{repository: ghcr.io/x/op, digest: sha512:ab}"), wantErr: `image.digest is "sha512:ab"`},
		"an unstamped digest":                        {values: stampedValues(`{repository: ghcr.io/x/op, digest: ""}`), wantErr: `image.digest is ""`},
		"no such component":                          {values: stampedValues("{}"), wantErr: `missing segment "repository"`},
	} {
		t.Run(name, func(t *testing.T) {
			release := t.TempDir()
			if err := os.WriteFile(filepath.Join(release, "values.yaml"), []byte(tc.values), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := releaseImagePins(components, release)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("releaseImagePins = %v, want error %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertArgsEqual(t, got, []string{
				"--set-string", "image.repository=ghcr.io/x/op",
				"--set-string", "image.digest=" + testDigest,
				"--set-string", "volumed.image.repository=ghcr.io/x/volumed",
				"--set-string", "volumed.image.digest=" + testDigest,
			})
		})
	}
}

// stampedValues is a release chart's values with operatorImage and a stamped volumed image.
func stampedValues(operatorImage string) string {
	return "image: " + operatorImage + "\nvolumed: {enabled: true, image: {repository: ghcr.io/x/volumed, digest: " + testDigest + "}}\n"
}

// lastValuesFile is the computed values file the logged helm upgrade passed last.
func lastValuesFile(t *testing.T, calls []string) string {
	t.Helper()
	upgrade := calls[lineIndex(calls, "helm upgrade ")]
	return upgrade[strings.LastIndex(upgrade, " ")+1:]
}
