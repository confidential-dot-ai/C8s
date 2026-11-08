//go:build !c8s_node

// Package helmchart bundles the C8s Helm charts into the Go binary
// so `c8s install` is a single-file install tool — no side chart download.
//
// The charts live under this package: cloud/ (the installed chart) and lib/
// (c8s-lib, the library it depends on). Develop them with the `helm` CLI
// directly (helm lint internal/helmchart/cloud,
// helm template test internal/helmchart/cloud).
//
// Build tag: dropped from `-tags c8s_node` builds along with the
// `c8s install` subcommand that consumes it.
package helmchart

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"
)

// ChartFS contains the full chart trees including dotfiles and underscored
// template partials (_helpers.tpl). ExtractTemp adds the charts/ dependency
// links, which go:embed skips.
//
//go:embed all:cloud all:lib
var ChartFS embed.FS

const (
	// ChartRoot is the path prefix inside ChartFS that a helm action expects
	// as a chart directory.
	ChartRoot = "cloud"
	// ComponentsFile is the component table and its image pins, relative to a
	// chart directory whose c8s-lib dependency is linked.
	ComponentsFile = "charts/c8s-lib/files/components.yaml"
	// RouterNginxDir holds the files the worker image installs in
	// /usr/lib/c8s/router-nginx, relative to a chart directory like
	// ComponentsFile.
	RouterNginxDir = "charts/c8s-lib/files/router-nginx"
	// RouterHostPort is the node port the router's nginx binds; the chart's
	// router Deployment renders the same number.
	RouterHostPort = 443
)

// HostSweepScript is the uninstall host sweep script, normalized the way the
// chart's argv pin renders it (trailing newlines collapsed to one).
func HostSweepScript() string {
	b, err := ChartFS.ReadFile(ChartRoot + "/files/scripts/host-sweep.sh")
	if err != nil {
		panic(err)
	}
	return strings.TrimRight(string(b), "\n") + "\n"
}

// ExtractTemp writes the embedded charts to a new temporary directory and
// returns it; the caller removes it.
func ExtractTemp() (string, error) {
	dir, err := os.MkdirTemp("", "c8s-chart-*")
	if err != nil {
		return "", err
	}
	if err := extractCharts(dir); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// extractCharts writes the embedded charts under dir, the cloud chart with its
// Chart.yaml dependencies linked into its charts/ directory.
func extractCharts(dir string) error {
	if err := os.CopyFS(dir, ChartFS); err != nil {
		return err
	}
	return linkDependencies(dir, ChartRoot)
}

type chartDependency struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
}

// linkDependencies links each dependency of the chart at dir/chart into its
// charts/ directory.
func linkDependencies(dir string, chart string) error {
	dependencies, err := chartDependencies(chart)
	if err != nil {
		return err
	}
	chartsDir := filepath.Join(dir, chart, "charts")
	if err := os.MkdirAll(chartsDir, 0o755); err != nil {
		return err
	}
	for _, dependency := range dependencies {
		if err := linkDependency(chartsDir, chart, dependency); err != nil {
			return fmt.Errorf("chart %s: %w", chart, err)
		}
	}
	return nil
}

// chartDependencies reads the dependencies the embedded chart's Chart.yaml
// lists.
func chartDependencies(chart string) ([]chartDependency, error) {
	data, err := ChartFS.ReadFile(path.Join(chart, "Chart.yaml"))
	if err != nil {
		return nil, err
	}
	var metadata struct {
		Dependencies []chartDependency `json:"dependencies"`
	}
	if err := yaml.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}
	return metadata.Dependencies, nil
}

// linkDependency links chartsDir/<name> to the dependency's file://
// directory, which Chart.yaml states relative to the chart.
func linkDependency(chartsDir string, chart string, dependency chartDependency) error {
	target, ok := strings.CutPrefix(dependency.Repository, "file://")
	if !ok {
		return fmt.Errorf("dependency %s: repository %s is not a file:// directory", dependency.Name, dependency.Repository)
	}
	if _, err := fs.Stat(ChartFS, path.Join(chart, target)); err != nil {
		return fmt.Errorf("dependency %s: %w", dependency.Name, err)
	}
	targetFromChartsDir := filepath.Join("..", target)
	return os.Symlink(targetFromChartsDir, filepath.Join(chartsDir, dependency.Name))
}
