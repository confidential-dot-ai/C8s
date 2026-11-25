package allowlist

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/routes"
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

// ReplaceRoutes stores env as the signed route manifest when its revision is
// greater than the stored one and, when ifMatch is not empty, the stored
// manifest's lower-case hex route digest equals ifMatch. One statement checks
// both and replaces the previous manifest (C3, C4). It returns
// ErrRevisionNotGreater, else ErrDigestMismatch, when a check fails; with
// ifMatch set and no manifest stored, that is ErrDigestMismatch. It fails on a
// manifest routes.Parse refuses. Route writes leave Generation alone: no
// allowlist reader depends on them.
func (s *Store) ReplaceRoutes(env routes.Envelope, ifMatch string) error {
	m, err := routes.Parse(env.Manifest)
	if err != nil {
		return err
	}
	// D2 caps the revision at 2^53-1, so it fits the INTEGER column.
	revision := int64(m.Revision)
	d := routes.Digest(env.Manifest)
	digest := hex.EncodeToString(d[:])
	s.mu.Lock()
	defer s.mu.Unlock()

	args := []any{revision, digest, env.Manifest, env.Token}
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
	case revision <= stored:
		return ErrRevisionNotGreater
	default:
		return ErrDigestMismatch
	}
}

// SetRoutes stores env as the signed route manifest whatever the stored one,
// and removes the stored one when env is nil: a Trust Authority replica serves the route
// manifest of its chain, which a resolve can move back.
func (s *Store) SetRoutes(env *routes.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if env == nil {
		if _, err := s.db.Exec("DELETE FROM route_manifest WHERE id = 1"); err != nil {
			return fmt.Errorf("remove route manifest: %w", err)
		}
		return nil
	}
	m, err := routes.Parse(env.Manifest)
	if err != nil {
		return err
	}
	d := routes.Digest(env.Manifest)
	_, err = s.db.Exec(`
INSERT INTO route_manifest (id, revision, digest, manifest, token) VALUES (1, ?1, ?2, ?3, ?4)
ON CONFLICT (id) DO UPDATE SET
	revision = excluded.revision, digest = excluded.digest, manifest = excluded.manifest, token = excluded.token`,
		int64(m.Revision), hex.EncodeToString(d[:]), env.Manifest, env.Token)
	if err != nil {
		return fmt.Errorf("store route manifest: %w", err)
	}
	s.routesFloor = max(s.routesFloor, m.Revision)
	return nil
}

// RoutesFloor is the highest route manifest revision SetRoutes stored in
// this process. A resolve can move the stored manifest back, but a router
// keeps the highest revision it accepted, so a new manifest must go above
// this one to reach it.
func (s *Store) RoutesFloor() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.routesFloor
}
