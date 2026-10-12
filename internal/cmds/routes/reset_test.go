package routes

import (
	"crypto/x509"
	"strconv"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/routing"
)

// After a CDS reset, a router keeps a revision that may be above the
// writer's clock. --revision outranks it; the default does not.
func TestRevisionOutranksARouterAfterACDSReset(t *testing.T) {
	h := newHarness(t)
	router := routing.NewState(routing.StateConfig{MeshCAs: func() ([]*x509.Certificate, error) { return nil, nil }})
	add := func(extra ...string) {
		h.mustRun(t, append([]string{"add", "--host", "app.example", "--path", "/", "--address", "a:1", "--workload", "a"}, extra...)...)
	}
	accept := func() error {
		_, err := router.Accept(*h.cds.env, h.cds.keys)
		return err
	}
	reset := func() { h.cds.env, h.cds.rev = nil, 0 }

	held := uint64(time.Now().Unix()) + 3600
	add("--revision", strconv.FormatUint(held, 10))
	if err := accept(); err != nil {
		t.Fatalf("router Accept(revision %d) = %v", held, err)
	}
	reset()
	add()
	if err := accept(); err == nil {
		t.Fatalf("router accepted default revision %d below its %d", h.cds.rev, held)
	}
	reset()
	add("--revision", strconv.FormatUint(held+1, 10))
	if err := accept(); err != nil {
		t.Fatalf("router Accept(revision %d) = %v, want it applied over %d", held+1, err, held)
	}
}

// NextRevision tracks the clock, so a burst of writes stays near it.
func TestNextRevision(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name         string
		stored, flag uint64
		want         uint64
		wantErr      bool
	}{
		{"new manifest", 0, 0, 1_800_000_000, false},
		{"stored below the clock", 7, 0, 1_800_000_000, false},
		{"stored at the clock", 1_800_000_000, 0, 1_800_000_001, false},
		{"explicit", 1_800_000_000, 1_900_000_000, 1_900_000_000, false},
		{"explicit at the stored", 1_800_000_000, 1_800_000_000, 0, true},
	} {
		got, err := NextRevision(tc.stored, tc.flag, now)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("%s: NextRevision(%d, %d) = %d, %v; want %d, error %t", tc.name, tc.stored, tc.flag, got, err, tc.want, tc.wantErr)
		}
	}
}
