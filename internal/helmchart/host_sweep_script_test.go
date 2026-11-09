package helmchart

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sweepScriptTemplate renders the chart's own host sweep: the bytes its argv
// pin carries, which `c8s uninstall` must apply.
const sweepScriptTemplate = `apiVersion: v1
kind: ConfigMap
metadata:
  name: sweep-script
  namespace: {{ .Release.Namespace }}
data:
  sweep.sh: |
{{ include "nri-image-policy.hostSweepScript" . | indent 4 }}
`

// The CLI's sweep is the chart's sweep, file list and order included: a sweep
// the chart's pin does not cover is refused on the node it has to clean.
func TestHostSweepScriptIsTheChartsSweep(t *testing.T) {
	chart := extractedChart(t)
	if err := os.WriteFile(filepath.Join(chart, "templates", "zz-sweep-script.yaml"), []byte(sweepScriptTemplate), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := helmTemplateIn(t, chart)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	rendered := renderedConfigMap(t, out, "sweep-script").Data["sweep.sh"]
	if got := strings.TrimRight(rendered, "\n ") + "\n"; got != HostSweepScript() {
		t.Errorf("the CLI's sweep is not the chart's:\n%s\nwant\n%s", got, HostSweepScript())
	}
}
