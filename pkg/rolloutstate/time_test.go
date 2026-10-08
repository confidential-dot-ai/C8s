package rolloutstate

import (
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestCheckTime(t *testing.T) {
	now := time.Now()
	stamped := func(at time.Time) types.RolloutState {
		var st types.RolloutState
		Stamp(&st, at)
		return st
	}
	for _, tc := range []struct {
		name string
		st   types.RolloutState
		ok   bool
	}{
		{"fresh", stamped(now), true},
		{"within skew after expiry", stamped(now.Add(-Validity - MaxClockSkew/2)), true},
		{"expired", stamped(now.Add(-Validity - MaxClockSkew - 2*time.Second)), false},
		{"slightly ahead", stamped(now.Add(MaxClockSkew / 2)), true},
		{"issued in the future", stamped(now.Add(MaxClockSkew + 2*time.Second)), false},
		{"no window", types.RolloutState{}, false},
		{"inverted window", types.RolloutState{IssuedAt: now.Unix(), ExpiresAt: now.Unix() - 1}, false},
	} {
		if err := CheckTime(&tc.st, now); (err == nil) != tc.ok {
			t.Errorf("%s: CheckTime = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}
