package helmchart

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/charts"
)

// Every chart's Chart.yaml dependencies resolve to a chart in the extracted tree.
func TestExtractLinksEveryChartDependency(t *testing.T) {
	dir := t.TempDir()
	if err := Extract(dir); err != nil {
		t.Fatal(err)
	}
	for _, chart := range []string{CloudChartFSPath, controlPlaneChart, WorkerChart} {
		dependencies, err := chartDependencies(chart)
		if err != nil {
			t.Fatal(err)
		}
		for _, dependency := range dependencies {
			linked := filepath.Join(dir, chart, "charts", dependency.Name, "Chart.yaml")
			if _, err := os.Stat(linked); err != nil {
				t.Errorf("chart %s: dependency %s is not linked: %v", chart, dependency.Name, err)
			}
		}
	}
}

// Extract links the dependencies of every embedded chart that has any.
func TestExtractCoversEveryEmbeddedChart(t *testing.T) {
	entries, err := charts.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	extracted := map[string]bool{CloudChartFSPath: true, controlPlaneChart: true, WorkerChart: true}
	for _, entry := range entries {
		dependencies, err := chartDependencies(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if len(dependencies) > 0 && !extracted[entry.Name()] {
			t.Errorf("chart %s has dependencies but Extract does not link them", entry.Name())
		}
	}
}
