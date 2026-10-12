package allowlist

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

var (
	// ErrNoRoutes reports that no signed route manifest is stored.
	ErrNoRoutes = errors.New("no route manifest stored")
	// ErrRevisionNotGreater reports a route manifest write whose revision is
	// not greater than the stored one (route policy C3).
	ErrRevisionNotGreater = errors.New("route manifest revision is not greater than the stored one")
	// ErrDigestMismatch reports a route manifest write whose expected route
	// digest is not the stored manifest's (route policy C3).
	ErrDigestMismatch = errors.New("stored route manifest digest differs from If-Match")
)

// LoadRoutes returns the stored signed route manifest, or ErrNoRoutes.
func (s *Store) LoadRoutes() (routes.Envelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var env routes.Envelope
	err := s.db.QueryRow("SELECT manifest, token FROM route_manifest WHERE id = 1").Scan(&env.Manifest, &env.Token)
	if errors.Is(err, sql.ErrNoRows) {
		return routes.Envelope{}, ErrNoRoutes
	}
	if err != nil {
		return routes.Envelope{}, fmt.Errorf("read route manifest: %w", err)
	}
	return env, nil
}

// ReplaceRoutes stores env as the signed route manifest when revision is
// greater than the stored one and, when ifMatch is not empty, the stored
// manifest's lower-case hex route digest equals ifMatch. One statement checks
// both and replaces the previous manifest (C3, C4). It returns
// ErrRevisionNotGreater, else ErrDigestMismatch, when a check fails; with
// ifMatch set and no manifest stored, that is ErrDigestMismatch. revision must
// be the one parsed from env.Manifest. Route writes leave Generation alone: no
// allowlist reader depends on them.
func (s *Store) ReplaceRoutes(env routes.Envelope, revision uint64, ifMatch string) error {
	if revision > math.MaxInt64 {
		return fmt.Errorf("route manifest revision %d out of range", revision)
	}
	d := routes.Digest(env.Manifest)
	digest := hex.EncodeToString(d[:])
	s.mu.Lock()
	defer s.mu.Unlock()

	args := []any{int64(revision), digest, env.Manifest, env.Token}
	query := `
INSERT INTO route_manifest (id, revision, digest, manifest, token) VALUES (1, ?1, ?2, ?3, ?4)
ON CONFLICT (id) DO UPDATE SET
	revision = excluded.revision, digest = excluded.digest, manifest = excluded.manifest, token = excluded.token
WHERE excluded.revision > route_manifest.revision`
	if ifMatch != "" {
		// An UPDATE, so that If-Match never matches an empty store.
		query = `
UPDATE route_manifest SET revision = ?1, digest = ?2, manifest = ?3, token = ?4
WHERE id = 1 AND ?1 > revision AND digest = ?5`
		args = append(args, ifMatch)
	}
	res, err := s.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("store route manifest: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store route manifest: %w", err)
	}
	if n > 0 {
		return nil
	}
	// Under s.mu, so this reads the row the write was refused against.
	var stored int64
	err = s.db.QueryRow("SELECT revision FROM route_manifest WHERE id = 1").Scan(&stored)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrDigestMismatch
	case err != nil:
		return fmt.Errorf("store route manifest: %w", err)
	case int64(revision) <= stored:
		return ErrRevisionNotGreater
	default:
		return ErrDigestMismatch
	}
}
