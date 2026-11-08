//go:build !c8s_node

// Package helmchart extracts the embedded C8s Helm charts into a renderable
// tree, so `c8s install` renders the charts it was built with.
//
// The charts live in the repository's charts/ directory: cloud/ (the installed
// chart), worker/ (c8s-worker, which the worker render commands template),
// control-plane/ (c8s-control-plane, its CRD, ClusterRole and webhooks) and
// lib/ (c8s-lib, the library they depend on). Develop them with the `helm` CLI
// directly (helm lint charts/cloud, helm template test charts/cloud).
//
// Build tag: dropped from `-tags c8s_node` builds along with the
// `c8s install` subcommand that consumes it.
package helmchart

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/charts"
)

const (
	// CloudChartFSPath is the path prefix inside charts.FS that a helm action expects
	// as a chart directory.
	CloudChartFSPath = "cloud"
	// WorkerChart is the c8s-worker chart's path inside charts.FS.
	WorkerChart = "worker"
	// controlPlaneChart is the c8s-control-plane dependency of both charts.
	controlPlaneChart = "control-plane"
	// ComponentsFile is the component table and its image pins, relative to a
	// chart directory whose c8s-lib dependency is linked.
	ComponentsFile = "charts/c8s-lib/files/components.yaml"
	// RouterNginxDir holds the files the worker image installs in
	// /usr/lib/c8s/router-nginx, relative to a chart directory like
	// ComponentsFile.
	RouterNginxDir = "charts/c8s-lib/files/router-nginx"
	// StaticPodsDir holds the worker image's static pod templates, relative to
	// the worker chart.
	StaticPodsDir = "files/static-pods"
	// WorkerSeedTemplate renders the allowlist seed the worker image bakes,
	// relative to the worker chart.
	WorkerSeedTemplate = "templates/image/allowlist-seed.yaml"
	// RouterHostPort is the node port the router's nginx binds; the chart's
	// router Deployment renders the same number.
	RouterHostPort = 443
)

// HostSweepScript is the uninstall host sweep script, normalized the way the
// chart's argv pin renders it (trailing newlines collapsed to one).
func HostSweepScript() string {
	b, err := charts.FS.ReadFile(CloudChartFSPath + "/files/scripts/host-sweep.sh")
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
	if err := Extract(dir); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// Extract writes the embedded charts under dir, each chart with its
// Chart.yaml dependencies linked into its charts/ directory.
func Extract(dir string) error {
	if err := os.CopyFS(dir, charts.FS); err != nil {
		return err
	}
	for _, chart := range []string{CloudChartFSPath, controlPlaneChart, WorkerChart} {
		if err := linkDependencies(dir, chart); err != nil {
			return err
		}
	}
	return nil
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
	data, err := charts.FS.ReadFile(path.Join(chart, "Chart.yaml"))
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
	if _, err := fs.Stat(charts.FS, path.Join(chart, target)); err != nil {
		return fmt.Errorf("dependency %s: %w", dependency.Name, err)
	}
	targetFromChartsDir := filepath.Join("..", target)
	return os.Symlink(targetFromChartsDir, filepath.Join(chartsDir, dependency.Name))
}
