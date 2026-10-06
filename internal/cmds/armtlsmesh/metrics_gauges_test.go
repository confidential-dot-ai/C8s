//go:build linux

package armtlsmesh

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// registryValue reads one metric value from the metrics' own registry via the
// dto protocol, matching on name and an exact subset of labels.
func registryValue(t *testing.T, m *metrics, name string, labels map[string]string) float64 {
	t.Helper()
	fams, err := m.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]*dto.MetricFamily, len(fams))
	for _, f := range fams {
		byName[f.GetName()] = f
	}
	v, ok := familyValue(byName, name, labels)
	if !ok {
		t.Fatalf("metric %s%v not found", name, labels)
	}
	return v
}

func familyValue(fams map[string]*dto.MetricFamily, name string, labels map[string]string) (float64, bool) {
	fam, ok := fams[name]
	if !ok {
		return 0, false
	}
	for _, m := range fam.GetMetric() {
		got := make(map[string]string, len(m.GetLabel()))
		for _, lp := range m.GetLabel() {
			got[lp.GetName()] = lp.GetValue()
		}
		match := true
		for k, v := range labels {
			if got[k] != v {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		switch {
		case m.GetGauge() != nil:
			return m.GetGauge().GetValue(), true
		case m.GetCounter() != nil:
			return m.GetCounter().GetValue(), true
		case m.GetUntyped() != nil:
			return m.GetUntyped().GetValue(), true
		}
	}
	return 0, false
}

// tryScrapeMetrics fetches and decodes /metrics from a running health server.
func tryScrapeMetrics(port int) (map[string]*dto.MetricFamily, error) {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", port))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/metrics status %d", resp.StatusCode)
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	return parser.TextToMetricFamilies(resp.Body)
}

func TestCertPipelineHealthyStartsAtSentinel(t *testing.T) {
	m := newMetrics()
	if got := registryValue(t, m, "armtls_mesh_cert_pipeline_healthy", nil); got != -1 {
		t.Errorf("cert_pipeline_healthy initial = %v, want -1 (probe-not-configured sentinel)", got)
	}
}

func TestCertModeGauges(t *testing.T) {
	type want struct {
		activeCDS      float64
		activeSelf     float64
		configuredCDS  float64
		configuredSelf float64
		mismatch       float64
	}
	tests := []struct {
		name       string
		active     int64
		configured int64
		want       want
	}{
		{"boot self-signed", 0, 0, want{0, 1, 0, 1, 0}},
		{"configured cds, still self-signed", 0, 1, want{0, 1, 1, 0, 1}},
		{"upgraded to cds", 1, 1, want{1, 0, 1, 0, 0}},
		{"active cds but configured self-signed", 1, 0, want{1, 0, 0, 1, 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newMetrics()
			m.certMode.Store(tc.active)
			m.certModeConfigured.Store(tc.configured)
			checks := []struct {
				name   string
				labels map[string]string
				want   float64
			}{
				{"armtls_mesh_cert_mode", map[string]string{"mode": "cds"}, tc.want.activeCDS},
				{"armtls_mesh_cert_mode", map[string]string{"mode": "self-signed"}, tc.want.activeSelf},
				{"armtls_mesh_cert_mode_configured", map[string]string{"mode": "cds"}, tc.want.configuredCDS},
				{"armtls_mesh_cert_mode_configured", map[string]string{"mode": "self-signed"}, tc.want.configuredSelf},
				{"armtls_mesh_cert_mode_mismatch", nil, tc.want.mismatch},
			}
			for _, c := range checks {
				if got := registryValue(t, m, c.name, c.labels); got != c.want {
					t.Errorf("%s%v = %v, want %v", c.name, c.labels, got, c.want)
				}
			}
		})
	}
}

func TestRecordOutboundDestRejectedUnknownReason(t *testing.T) {
	m := testMetrics()
	m.recordOutboundDestRejected("some-new-reason")
	if got := testutil.ToFloat64(m.outboundDestRejected.WithLabelValues(outboundRejectUnknownPod)); got != 1 {
		t.Errorf("unknown reason not folded into unknown_pod bucket: %v", got)
	}
}

func TestMetricsRegistriesAreIndependent(t *testing.T) {
	first, second := newMetrics(), newMetrics()
	first.attestationFailures.Inc()
	for i, m := range []*metrics{first, second} {
		want := float64(1 - i)
		if got := registryValue(t, m, "armtls_mesh_attestation_failures_total", nil); got != want {
			t.Errorf("registry %d attestation failures = %v, want %v", i, got, want)
		}
	}
}
