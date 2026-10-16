package allowlist

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// routesEnvelope returns a valid manifest at revision under a placeholder
// token: the store checks no token.
func routesEnvelope(revision uint64, token string) routes.Envelope {
	m := fmt.Sprintf(`{"schema":"c8s.routes/v1","revision":%d,"notBefore":"2026-01-01T00:00:00Z","maxAgeSeconds":60,"hosts":{}}`, revision)
	return routes.Envelope{Manifest: []byte(m), Token: token}
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

// A manifest that does not parse carries no revision to store.
func TestReplaceRoutesRefusesInvalidManifest(t *testing.T) {
	s, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.ReplaceRoutes(routes.Envelope{Manifest: []byte(`{"revision":2}`), Token: "t"}, ""); err == nil {
		t.Fatal("ReplaceRoutes(invalid manifest) = nil, want error")
	}
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

	r2 := routesEnvelope(2, "token-2")
	if err := s.ReplaceRoutes(r2, ""); err != nil {
		t.Fatalf("ReplaceRoutes(2) error = %v", err)
	}
	for _, rev := range []uint64{1, 2} {
		if err := s.ReplaceRoutes(routesEnvelope(rev, "x"), ""); !errors.Is(err, ErrRevisionNotGreater) {
			t.Fatalf("ReplaceRoutes(%d) error = %v, want ErrRevisionNotGreater", rev, err)
		}
	}
	assertStoredRoutes(t, &s, r2)

	r3 := routesEnvelope(3, "token-3")
	if err := s.ReplaceRoutes(r3, ""); err != nil {
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
	want := routesEnvelope(7, "token-7")
	if err := s.ReplaceRoutes(want, ""); err != nil {
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
	if err := reopened.ReplaceRoutes(routesEnvelope(7, "x"), ""); !errors.Is(err, ErrRevisionNotGreater) {
		t.Fatalf("ReplaceRoutes(7) after reopen error = %v, want ErrRevisionNotGreater", err)
	}
}

// C3: If-Match must name the stored manifest's route digest, and the revision
// check comes first.
func TestReplaceRoutesIfMatch(t *testing.T) {
	r2 := routesEnvelope(2, "token-2")
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
				if err := s.ReplaceRoutes(r2, ""); err != nil {
					t.Fatal(err)
				}
			}
			r3 := routesEnvelope(tc.revision, "token-3")
			if err := s.ReplaceRoutes(r3, tc.ifMatch); !errors.Is(err, tc.want) {
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
