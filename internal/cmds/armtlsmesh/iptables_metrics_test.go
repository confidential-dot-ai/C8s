//go:build linux

package armtlsmesh

import (
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestIptablesMetricsFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "armtls-iptables-metrics.json")
	want := iptablesMetricsSnapshot{
		JumpPositionViolations:  7,
		JumpPositionCheckErrors: 3,
		IPSetOverflows:          2,
		UpdatedAtUnixNano:       time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC).UnixNano(),
	}

	if err := writeIptablesMetricsFile(path, want); err != nil {
		t.Fatalf("writeIptablesMetricsFile: %v", err)
	}
	got, err := readIptablesMetricsFile(path)
	if err != nil {
		t.Fatalf("readIptablesMetricsFile: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot = %+v, want %+v", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat metrics file: %v", err)
	}
	if got := info.Mode().Perm(); got != iptablesMetricsFilePerm {
		t.Fatalf("metrics file mode = %v, want %v so non-root proxy can read sidecar output", got, iptablesMetricsFilePerm)
	}
}

func TestPublishIptablesMetricsRefreshesTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "armtls-iptables-metrics.json")
	configureIptablesMetricsFile(path)
	t.Cleanup(func() { configureIptablesMetricsFile("") })

	publishIptablesMetrics(slog.New(slog.DiscardHandler))
	first, err := readIptablesMetricsFile(path)
	if err != nil {
		t.Fatalf("read first metrics snapshot: %v", err)
	}
	if first.UpdatedAtUnixNano == 0 {
		t.Fatal("first metrics snapshot missing UpdatedAtUnixNano")
	}

	time.Sleep(time.Millisecond)
	publishIptablesMetrics(slog.New(slog.DiscardHandler))
	second, err := readIptablesMetricsFile(path)
	if err != nil {
		t.Fatalf("read second metrics snapshot: %v", err)
	}
	if second.UpdatedAtUnixNano <= first.UpdatedAtUnixNano {
		t.Fatalf("UpdatedAtUnixNano did not advance: first=%d second=%d", first.UpdatedAtUnixNano, second.UpdatedAtUnixNano)
	}
}

func TestMetricsRefreshesIptablesSidecarCounters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "armtls-iptables-metrics.json")
	stamp := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	if err := writeIptablesMetricsFile(path, iptablesMetricsSnapshot{
		JumpPositionViolations:  11,
		JumpPositionCheckErrors: 5,
		IPSetOverflows:          4,
		CWInboundDrops:          9,
		CWPassthroughReturns:    13,
		UpdatedAtUnixNano:       stamp.UnixNano(),
	}); err != nil {
		t.Fatalf("writeIptablesMetricsFile: %v", err)
	}

	m := newMetrics()
	if err := m.refreshIptablesMetrics(path); err != nil {
		t.Fatalf("refreshIptablesMetrics: %v", err)
	}

	if got := testutil.ToFloat64(m.iptablesJumpViolations); got != 11 {
		t.Errorf("iptablesJumpViolations = %v, want 11", got)
	}
	if got := testutil.ToFloat64(m.iptablesJumpCheckErrors); got != 5 {
		t.Errorf("iptablesJumpCheckErrors = %v, want 5", got)
	}
	if got := testutil.ToFloat64(m.iptablesIPSetOverflows); got != 4 {
		t.Errorf("iptablesIPSetOverflows = %v, want 4", got)
	}
	if got := testutil.ToFloat64(m.iptablesCWInboundDrops); got != 9 {
		t.Errorf("iptablesCWInboundDrops = %v, want 9", got)
	}
	if got := testutil.ToFloat64(m.iptablesCWPassthroughReturns); got != 13 {
		t.Errorf("iptablesCWPassthroughReturns = %v, want 13", got)
	}
	if got := testutil.ToFloat64(m.iptablesMetricsTimestamp); got != float64(stamp.Unix()) {
		t.Errorf("iptablesMetricsTimestamp = %v, want %d", got, stamp.Unix())
	}
}

// A sidecar snapshot without an UpdatedAtUnixNano (e.g. older sidecar binary
// during a rolling upgrade) must not zero out the freshness gauge — alerts
// reading `time() - gauge` would page on 1970-01-01 if it did.
func TestMetricsPreservesIptablesTimestampOnZeroSnapshot(t *testing.T) {
	m := newMetrics()
	m.iptablesMetricsTimestamp.Set(1_700_000_000)
	path := filepath.Join(t.TempDir(), "armtls-iptables-metrics.json")
	if err := writeIptablesMetricsFile(path, iptablesMetricsSnapshot{
		JumpPositionViolations: 1,
		// UpdatedAtUnixNano intentionally zero.
	}); err != nil {
		t.Fatalf("writeIptablesMetricsFile: %v", err)
	}
	if err := m.refreshIptablesMetrics(path); err != nil {
		t.Fatalf("refreshIptablesMetrics: %v", err)
	}
	if got := testutil.ToFloat64(m.iptablesMetricsTimestamp); got != 1_700_000_000 {
		t.Fatalf("iptablesMetricsTimestamp = %v, want preserved 1_700_000_000", got)
	}
}
