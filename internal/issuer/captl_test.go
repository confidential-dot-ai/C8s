package issuer_test

import (
	"testing"
	"time"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/issuer"
)

func TestCapTTL(t *testing.T) {
	const max = 24 * time.Hour
	for _, tc := range []struct {
		name      string
		requested time.Duration
		max       time.Duration
		want      time.Duration
	}{
		{"zero falls back to default then caps", 0, max, issuer.DefaultLeafTTL},
		{"negative falls back to default", -time.Hour, max, issuer.DefaultLeafTTL},
		{"under cap passes through", time.Hour, max, time.Hour},
		{"at cap passes through", max, max, max},
		{"over cap clips", 168 * time.Hour, max, max},
		{"max=0 disables cap", 168 * time.Hour, 0, 168 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := issuer.CapTTL(tc.requested, tc.max)
			if got != tc.want {
				t.Errorf("CapTTL(%v, %v) = %v, want %v", tc.requested, tc.max, got, tc.want)
			}
		})
	}
}
