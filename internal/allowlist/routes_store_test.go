package allowlist

import (
	"bytes"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

func routesEnvelope(rev string) routes.Envelope {
	return routes.Envelope{Manifest: []byte(`{"revision":` + rev + `}`), Token: "token-" + rev}
}

func assertStoredRoutes(t *testing.T, s *Store, want routes.Envelope) {
	t.Helper()
	got, err := s.LoadRoutes()
	if err != nil {
		t.Fatalf("LoadRoutes() error = %v", err)
	}
	if !bytes.Equal(got.Manifest, want.Manifest) || got.Token != want.Token {
		t.Fatalf("LoadRoutes() = %q, %q, want %q, %q", got.Manifest, got.Token, want.Manifest, want.Token)
	}
}

func TestLoadRoutesEmpty(t *testing.T) {
	s, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.LoadRoutes(); !errors.Is(err, ErrNoRoutes) {
		t.Fatalf("LoadRoutes() error = %v, want ErrNoRoutes", err)
	}
}

// C3, C4: the revision only rises, and a refused write leaves the stored
// manifest whole.
func TestReplaceRoutesRevisionMustRise(t *testing.T) {
	s, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	r2 := routesEnvelope("2")
	if err := s.ReplaceRoutes(r2, 2, ""); err != nil {
		t.Fatalf("ReplaceRoutes(2) error = %v", err)
	}
	for _, rev := range []uint64{1, 2} {
		if err := s.ReplaceRoutes(routesEnvelope("x"), rev, ""); !errors.Is(err, ErrRevisionNotGreater) {
			t.Fatalf("ReplaceRoutes(%d) error = %v, want ErrRevisionNotGreater", rev, err)
		}
	}
	assertStoredRoutes(t, &s, r2)

	r3 := routesEnvelope("3")
	if err := s.ReplaceRoutes(r3, 3, ""); err != nil {
		t.Fatalf("ReplaceRoutes(3) error = %v", err)
	}
	assertStoredRoutes(t, &s, r3)
	if g := s.Generation(); g != 0 {
		t.Fatalf("Generation() = %d after route writes, want 0", g)
	}
}

// C5: the manifest lives in the allowlist database, so a persistent file
// keeps it across a reopen.
func TestReplaceRoutesPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	want := routesEnvelope("7")
	if err := s.ReplaceRoutes(want, 7, ""); err != nil {
		t.Fatalf("ReplaceRoutes() error = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertStoredRoutes(t, &reopened, want)
	if err := reopened.ReplaceRoutes(routesEnvelope("x"), 7, ""); !errors.Is(err, ErrRevisionNotGreater) {
		t.Fatalf("ReplaceRoutes(7) after reopen error = %v, want ErrRevisionNotGreater", err)
	}
}

// C3: If-Match must name the stored manifest's route digest, and the revision
// check comes first.
func TestReplaceRoutesIfMatch(t *testing.T) {
	r2 := routesEnvelope("2")
	d := routes.Digest(r2.Manifest)
	stored := hex.EncodeToString(d[:])
	cases := []struct {
		name     string
		seed     bool
		revision uint64
		ifMatch  string
		want     error
	}{
		{"absent", true, 3, "", nil},
		{"match", true, 3, stored, nil},
		{"mismatch", true, 3, strings.Repeat("0", 64), ErrDigestMismatch},
		{"stale revision before mismatch", true, 2, strings.Repeat("0", 64), ErrRevisionNotGreater},
		{"stale revision with match", true, 2, stored, ErrRevisionNotGreater},
		{"nothing stored", false, 3, stored, ErrDigestMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := OpenInMemory()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if tc.seed {
				if err := s.ReplaceRoutes(r2, 2, ""); err != nil {
					t.Fatal(err)
				}
			}
			r3 := routesEnvelope("3")
			if err := s.ReplaceRoutes(r3, tc.revision, tc.ifMatch); !errors.Is(err, tc.want) {
				t.Fatalf("ReplaceRoutes(%d, %q) error = %v, want %v", tc.revision, tc.ifMatch, err, tc.want)
			}
			switch {
			case tc.want == nil:
				assertStoredRoutes(t, &s, r3)
			case tc.seed:
				assertStoredRoutes(t, &s, r2)
			default:
				if _, err := s.LoadRoutes(); !errors.Is(err, ErrNoRoutes) {
					t.Fatalf("LoadRoutes() error = %v, want ErrNoRoutes", err)
				}
			}
		})
	}
}
