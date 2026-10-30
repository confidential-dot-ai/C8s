package allowlist

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"

	"modernc.org/sqlite"
)

// imageConn is the modernc.org/sqlite connection API a database image needs.
type imageConn interface {
	Serialize() ([]byte, error)
	Deserialize([]byte) error
	NewBackup(dstURI string) (*sqlite.Backup, error)
}

var memdbSeq atomic.Uint64

// memdbURI names a new in-memory database that every connection opening the
// name shares, until the last one closes.
func memdbURI(use string) string {
	return fmt.Sprintf("file:/c8s-allowlist-%s-%d?vfs=memdb", use, memdbSeq.Add(1))
}

// Dump returns the whole database as a SQLite database image, free pages and
// the deleted rows they hold left out. Two replicas with the same rows may
// still produce different bytes: compare stores by content, not by image.
func (s *Store) Dump() ([]byte, error) {
	uri := memdbURI("dump")
	dst, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, err
	}
	defer dst.Close()
	// Holding a connection keeps the database alive until it is read.
	conn, err := dst.Conn(context.Background())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := s.vacuumInto(uri); err != nil {
		return nil, err
	}

	var image []byte
	if err := withImageConn(conn, func(c imageConn) error {
		var err error
		image, err = c.Serialize()
		return err
	}); err != nil {
		return nil, fmt.Errorf("dump allowlist: %w", err)
	}
	return image, nil
}

func (s *Store) vacuumInto(uri string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec("VACUUM INTO ?", uri); err != nil {
		return fmt.Errorf("dump allowlist: %w", err)
	}
	return nil
}

var ErrImageContent = errors.New("allowlist: the database image holds other content than the digest it was restored under")

// Restore replaces the whole database with an image from Dump, whose rows
// must hold the content the digest names. The image is read on a scratch
// connection first, then copied in with the SQLite backup API in one step,
// so an image SQLite cannot read, or that holds other content, leaves the
// store as it was.
func (s *Store) Restore(image []byte, content [32]byte) error {
	ctx := context.Background()
	scratch, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return err
	}
	defer scratch.Close()
	conn, err := scratch.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := readImage(ctx, conn, image); err != nil {
		return err
	}
	return s.replaceIfItHolds(ctx, conn, content)
}

// For a store whose content comes from the log alone.
func (s *Store) Empty() error {
	fresh, err := OpenInMemory()
	if err != nil {
		return err
	}
	defer fresh.Close()
	image, err := fresh.Dump()
	if err != nil {
		return err
	}
	return s.Restore(image, fresh.Digest())
}

func (s *Store) replaceIfItHolds(ctx context.Context, conn *sql.Conn, content [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc, err := scanDigest(ctx, conn)
	if err != nil {
		return fmt.Errorf("restore allowlist: content digest: %w", err)
	}
	if acc.Sum() != content {
		return fmt.Errorf("%w: it holds %x, and the digest names %x", ErrImageContent, acc.Sum(), content)
	}
	if err := copyDatabase(conn, s.uri); err != nil {
		return fmt.Errorf("restore allowlist: %w", err)
	}
	// The backup API copies pages, so no row hook reports the content.
	s.dig.startsFrom(acc)
	s.gen++
	return nil
}

func readImage(ctx context.Context, conn *sql.Conn, image []byte) error {
	if err := withImageConn(conn, func(c imageConn) error { return c.Deserialize(image) }); err != nil {
		return fmt.Errorf("restore allowlist: %w", err)
	}
	var check string
	if err := conn.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&check); err != nil || check != "ok" {
		return fmt.Errorf("restore allowlist: not a sound database image (%s): %v", check, err)
	}
	return nil
}

func copyDatabase(conn *sql.Conn, uri string) error {
	return withImageConn(conn, func(c imageConn) error {
		backup, err := c.NewBackup(uri)
		if err != nil {
			return err
		}
		if _, err := backup.Step(-1); err != nil {
			_ = backup.Finish()
			return err
		}
		return backup.Finish()
	})
}

func withImageConn(conn *sql.Conn, fn func(imageConn) error) error {
	return conn.Raw(func(driverConn any) error {
		c, ok := driverConn.(imageConn)
		if !ok {
			return fmt.Errorf("the SQLite driver connection (%T) carries no database image", driverConn)
		}
		return fn(c)
	})
}
