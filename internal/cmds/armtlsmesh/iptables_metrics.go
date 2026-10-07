//go:build linux

package armtlsmesh

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

const defaultIptablesMetricsFile = "/tmp/armtls-iptables-metrics.json"

// iptablesMetricsFilePerm must allow the non-root proxy container to read
// metrics published by the root iptables-sync sidecar through the shared /tmp.
const iptablesMetricsFilePerm os.FileMode = 0o644

type iptablesMetricsSnapshot struct {
	JumpPositionViolations  int64 `json:"jump_position_violations"`
	JumpPositionCheckErrors int64 `json:"jump_position_check_errors"`
	IPSetOverflows          int64 `json:"ipset_overflows"`
	IPSetSyncFailures       int64 `json:"ipset_sync_failures"`
	CWInboundDrops          int64 `json:"cw_inbound_drops"`
	CWPassthroughReturns    int64 `json:"cw_passthrough_returns"`
	// Membership is what the guard and the interception rules key on, so a set
	// that empties is enforcement that stopped without anything failing. The
	// sizes make the level observable; CWIPSetShrinks makes the transition
	// alertable, since a steady zero and a drop to zero read the same on a
	// gauge scraped every 30s.
	PodIPSetMembers int64 `json:"pod_ipset_members"`
	CWIPSetMembers  int64 `json:"cw_ipset_members"`
	CWIPSetShrinks  int64 `json:"cw_ipset_shrinks"`
	// UpdatedAtUnixNano is the wall-clock time the sidecar wrote this
	// snapshot, used by the proxy to expose a freshness gauge so a wedged
	// iptables-sync (file not advancing) shows up as a stale-timestamp
	// alert instead of frozen counters.
	UpdatedAtUnixNano int64 `json:"updated_at_unix_nano"`
}

var (
	// iptablesMetricsFile holds the path where the sidecar writes its metrics
	// snapshot. nil pointer = unconfigured (initial state); pointer to "" =
	// disabled by explicit empty path. Set once at startup via
	// configureIptablesMetricsFile.
	iptablesMetricsFile atomic.Pointer[string]
	iptablesMetricsMu   sync.Mutex
)

func configureIptablesMetricsFile(path string) {
	iptablesMetricsFile.Store(&path)
}

func currentIptablesMetricsSnapshot() iptablesMetricsSnapshot {
	return iptablesMetricsSnapshot{
		JumpPositionViolations:  iptablesJumpPositionViolations(),
		JumpPositionCheckErrors: iptablesJumpPositionCheckErrors(),
		IPSetOverflows:          iptablesIPSetOverflows(),
		IPSetSyncFailures:       iptablesIPSetSyncFailures(),
		CWInboundDrops:          iptablesCWInboundDrops(),
		CWPassthroughReturns:    iptablesCWPassthroughReturns(),
		PodIPSetMembers:         podIPSetMemberCount(),
		CWIPSetMembers:          cwIPSetMemberCount(),
		CWIPSetShrinks:          cwIPSetShrinks(),
		UpdatedAtUnixNano:       time.Now().UnixNano(),
	}
}

// publishIptablesMetrics writes the current snapshot to the configured
// metrics file. logger must be non-nil; tests that don't care about the
// warn output should pass slog.New(slog.DiscardHandler).
func publishIptablesMetrics(logger *slog.Logger) {
	p := iptablesMetricsFile.Load()
	if p == nil || *p == "" {
		return
	}
	if err := writeIptablesMetricsFile(*p, currentIptablesMetricsSnapshot()); err != nil {
		logger.Warn("write iptables metrics file failed", "path", *p, "error", err)
	}
}

func readIptablesMetricsFile(path string) (iptablesMetricsSnapshot, error) {
	var snap iptablesMetricsSnapshot
	raw, err := os.ReadFile(path)
	if err != nil {
		return snap, err
	}
	if err := json.Unmarshal(raw, &snap); err != nil {
		return snap, fmt.Errorf("decode iptables metrics file %q: %w", path, err)
	}
	return snap, nil
}

func writeIptablesMetricsFile(path string, snap iptablesMetricsSnapshot) error {
	if path == "" {
		return nil
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	// Serialise writers so two publishIptablesMetrics callers don't race on
	// the rename target. fileutil.WriteAtomic handles the tmp/Chmod/rename
	// dance itself.
	iptablesMetricsMu.Lock()
	defer iptablesMetricsMu.Unlock()
	return fileutil.WriteAtomic(path, raw, iptablesMetricsFilePerm)
}
