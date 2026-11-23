package ta

import (
	"context"
	"log"
	"log/slog"
	"sync"
	"testing"
)

// levelCapture records the level of every slog record routed to it.
type levelCapture struct {
	mu      sync.Mutex
	records map[string]slog.Level
}

func (c *levelCapture) Enabled(context.Context, slog.Level) bool { return true }
func (c *levelCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records[r.Message] = r.Level
	return nil
}
func (c *levelCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *levelCapture) WithGroup(string) slog.Handler      { return c }

func TestServerLogFilterDemotesProbeHandshakeNoise(t *testing.T) {
	capture := &levelCapture{records: map[string]slog.Level{}}
	old := slog.Default()
	slog.SetDefault(slog.New(capture))
	t.Cleanup(func() { slog.SetDefault(old) })

	logger := log.New(serverLogFilter{}, "", 0)
	cases := []struct {
		line string
		want slog.Level
	}{
		{"http: TLS handshake error from 10.0.0.1:33812: EOF", slog.LevelDebug},
		{"http: TLS handshake error from 10.0.0.1:33812: connection reset by peer", slog.LevelDebug},
		{"http: TLS handshake error from 10.0.0.1:33812: tls: client offered only unsupported versions", slog.LevelInfo},
		{"http: panic serving 10.0.0.1:33812: boom", slog.LevelInfo},
	}
	for _, tc := range cases {
		logger.Print(tc.line)
	}

	capture.mu.Lock()
	defer capture.mu.Unlock()
	for _, tc := range cases {
		got, ok := capture.records[tc.line]
		if !ok {
			t.Errorf("line %q was not logged at all", tc.line)
			continue
		}
		if got != tc.want {
			t.Errorf("serverLogFilter(%q) logged at %v, want %v", tc.line, got, tc.want)
		}
	}
}
