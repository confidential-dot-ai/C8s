//go:build !c8s_node

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	"github.com/confidential-dot-ai/c8s/internal/version"
)

// releaseChartRepository is the cloud chart each release publishes at its own version.
const releaseChartRepository = "oci://ghcr.io/confidential-dot-ai/charts/c8s-cloud"

// releaseChartDir is where an install untars the release chart, apart from the bundled one.
const releaseChartDir = "release-chart"

// releaseVersion matches the tags semver-tag.yml releases, vX.Y.Z and
// vX.Y.Z-beta.N; the submatch is the chart version.
var releaseVersion = regexp.MustCompile(`^v(\d+\.\d+\.\d+(?:-beta\.\d+)?)$`)

// renderChart is the chart an install renders, its component table, and the
// value args pinning those components' images.
type renderChart struct {
	path       string
	components []c8sComponent
	imagePins  []string
}

// installChart is the --chart directory with the images its values set, or
// the bundled chart with the digests of this release's chart.
func installChart(ctx context.Context, work string) (renderChart, error) {
	if installChartDir != "" {
		return chartFlagChart(ctx, installChartDir)
	}
	chartVersion, ok := releaseChartVersion(version.Version)
	if !ok {
		return renderChart{}, fmt.Errorf("c8s %s is not a release build, so no release chart pins its images: pass --%s <chart directory> and set each component's image digest or tag with -f", version.Version, flagChart)
	}
	return bundledChartWithReleaseDigests(ctx, chartVersion, work)
}

// releaseChartVersion is the chart version a release CLI installs: its own.
func releaseChartVersion(cliVersion string) (string, bool) {
	match := releaseVersion.FindStringSubmatch(cliVersion)
	if match == nil {
		return "", false
	}
	return match[1], true
}

func chartFlagChart(ctx context.Context, dir string) (renderChart, error) {
	if _, err := os.Stat(filepath.Join(dir, "Chart.yaml")); err != nil {
		return renderChart{}, fmt.Errorf("--%s %s names no chart directory: %w", flagChart, dir, err)
	}
	components, err := chartComponents(ctx, dir)
	if err != nil {
		return renderChart{}, fmt.Errorf("read chart components: %w", err)
	}
	return renderChart{path: dir, components: components}, nil
}

func bundledChartWithReleaseDigests(ctx context.Context, chartVersion, work string) (renderChart, error) {
	if err := helmchart.Extract(work); err != nil {
		return renderChart{}, fmt.Errorf("extract embedded chart: %w", err)
	}
	chartPath := filepath.Join(work, helmchart.CloudChartFSPath)
	components, err := chartComponents(ctx, chartPath)
	if err != nil {
		return renderChart{}, fmt.Errorf("read chart components: %w", err)
	}
	release, err := pullChart(ctx, releaseChartRepository, chartVersion, filepath.Join(work, releaseChartDir))
	if err != nil {
		return renderChart{}, err
	}
	imagePins, err := releaseImagePins(components, release)
	if err != nil {
		return renderChart{}, fmt.Errorf("release chart %s %s: %w", releaseChartRepository, chartVersion, err)
	}
	return renderChart{path: chartPath, components: components, imagePins: imagePins}, nil
}

// releaseImagePins pins each component to its repository at the digest the
// release chart at releasePath stamps for it. Only those two fields are read
// from the release chart.
func releaseImagePins(components []c8sComponent, releasePath string) ([]string, error) {
	stamped, err := decodeValuesFile(filepath.Join(releasePath, "values.yaml"))
	if err != nil {
		return nil, err
	}
	var args []string
	for _, c := range components {
		digest, err := releaseDigest(stamped, c)
		if err != nil {
			return nil, err
		}
		args = append(args,
			"--set-string", c.valuesPath+".repository="+c.repository,
			"--set-string", c.valuesPath+".digest="+digest,
		)
	}
	return args, nil
}

// releaseDigest is the digest the release chart stamps for c, under the
// repository the bundled chart names for c.
func releaseDigest(stamped map[string]any, c c8sComponent) (string, error) {
	repository, err := stringAtPath(stamped, c.valuesPath+".repository")
	if err != nil {
		return "", err
	}
	if repository != c.repository {
		return "", fmt.Errorf("%s.repository is %s, want the bundled chart's %s", c.valuesPath, repository, c.repository)
	}
	digest, err := stringAtPath(stamped, c.valuesPath+".digest")
	if err != nil {
		return "", err
	}
	if !imageDigestPattern.MatchString(digest) {
		return "", fmt.Errorf("%s.digest is %q, want sha256:<64 hex>", c.valuesPath, digest)
	}
	return digest, nil
}

// pullChart untars the chart at repository, version chartVersion, into the
// new directory dir and returns the chart directory helm created there.
func pullChart(ctx context.Context, repository, chartVersion, dir string) (string, error) {
	fmt.Fprintf(os.Stderr, "+ helm pull %s --version %s\n", repository, chartVersion)
	out, err := exec.CommandContext(ctx, "helm", "pull", repository, "--version", chartVersion, "--untar", "--untardir", dir).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("helm pull %s --version %s: %w: %s", repository, chartVersion, err, strings.TrimSpace(string(out)))
	}
	return untarredChart(dir)
}

// untarredChart is the one directory helm pull --untar created in dir.
func untarredChart(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	if len(entries) != 1 || !entries[0].IsDir() {
		return "", fmt.Errorf("helm pull left %d entries in %s, want one chart directory", len(entries), dir)
	}
	return filepath.Join(dir, entries[0].Name()), nil
}
