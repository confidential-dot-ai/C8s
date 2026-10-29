package allowlist

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"math"
	"sync"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/confidential-dot-ai/c8s/internal/lthash"
)

// The content digest names what the database holds: a multiset hash
// (lthash) over every row of every table, so it does not depend on rowids,
// page layout or the order rows were written in. Two replicas that hold the
// same rows have the same digest, however each got there (a log replay, a
// snapshot install, a VACUUM INTO image). SQLite's pre-update hook reports
// every row a statement inserts, updates or deletes, on every connection the
// store opens; the change counts once its transaction commits. A write
// therefore costs the hashing of the rows it changes, and reading the digest
// costs nothing. scanDigest computes the same value from the rows
// themselves: comparing the two finds content that changed under the store
// (memory or disk corruption), or a hook that missed a write.

// contentDigest is the digest of one store's database.
type contentDigest struct {
	mu  sync.Mutex
	acc lthash.Hash
}

func (d *contentDigest) reset(acc lthash.Hash) {
	d.mu.Lock()
	d.acc = acc
	d.mu.Unlock()
}

func (d *contentDigest) sum() [32]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.acc.Sum()
}

// openDB opens uri with the digest hooks on every connection.
func (d *contentDigest) openDB(uri string) (*sql.DB, error) {
	c, err := sqlite.NewConnector(uri)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(hookedConnector{Connector: c, dig: d}), nil
}

type hookedConnector struct {
	driver.Connector
	dig *contentDigest
}

// Connect registers the digest hooks on a new connection. The changes of
// its open transaction are kept apart until it commits.
func (c hookedConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	h, ok := conn.(sqlite.HookRegisterer)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("allowlist: sqlite connection without update hooks")
	}
	pending := new(lthash.Hash)
	h.RegisterPreUpdateHook(func(u sqlite.SQLitePreUpdateData) { preUpdate(pending, u) })
	h.RegisterCommitHook(func() int32 {
		c.dig.mu.Lock()
		c.dig.acc.Combine(pending)
		c.dig.mu.Unlock()
		*pending = lthash.Hash{}
		return 0
	})
	h.RegisterRollbackHook(func() { *pending = lthash.Hash{} })
	return conn, nil
}

// preUpdate records one row change of the main database. A row it cannot
// read leaves the digest wrong, which the next full comparison reports.
func preUpdate(pending *lthash.Hash, u sqlite.SQLitePreUpdateData) {
	if u.DatabaseName != "main" {
		return // VACUUM INTO's target, temp tables
	}
	n := u.Count()
	if u.Op != sqlite3.SQLITE_INSERT {
		old := make([]any, n)
		if err := u.Old(old...); err != nil {
			slog.Error("allowlist: content digest: read old row", "table", u.TableName, "err", err)
			return
		}
		pending.Remove(rowDigest(u.TableName, old))
	}
	if u.Op != sqlite3.SQLITE_DELETE {
		row := make([]any, n)
		if err := u.New(row...); err != nil {
			slog.Error("allowlist: content digest: read new row", "table", u.TableName, "err", err)
			return
		}
		pending.Add(rowDigest(u.TableName, row))
	}
}

// rowDigest is the SHA-256 of one row: the table name, then each column in
// table order, tagged with its SQLite storage class and length-prefixed, so
// NULL, an empty TEXT and an empty BLOB all differ. The rowid is not part of
// it: it is not content, and replicas need not agree on it.
func rowDigest(table string, cols []any) [32]byte {
	h := sha256.New()
	field(h, 't', []byte(table))
	for _, v := range cols {
		switch v := v.(type) {
		case nil:
			h.Write([]byte{'n'})
		case int64:
			var b [9]byte
			b[0] = 'i'
			binary.BigEndian.PutUint64(b[1:], uint64(v))
			h.Write(b[:])
		case float64:
			var b [9]byte
			b[0] = 'f'
			binary.BigEndian.PutUint64(b[1:], math.Float64bits(v))
			h.Write(b[:])
		case string:
			field(h, 's', []byte(v))
		case []byte:
			field(h, 'b', v)
		default:
			field(h, '?', fmt.Appendf(nil, "%T %v", v, v))
		}
	}
	return [32]byte(h.Sum(nil))
}

func field(h hash.Hash, tag byte, b []byte) {
	var p [9]byte
	p[0] = tag
	binary.BigEndian.PutUint64(p[1:], uint64(len(b)))
	h.Write(p[:])
	h.Write(b)
}

// rowQuerier is a database or one of its connections.
type rowQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// scanDigest computes the content digest from every row of every table.
func scanDigest(ctx context.Context, q rowQuerier) (lthash.Hash, error) {
	var acc lthash.Hash
	rows, err := q.QueryContext(ctx, "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name")
	if err != nil {
		return acc, err
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return acc, err
		}
		tables = append(tables, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return acc, err
	}
	for _, t := range tables {
		if err := scanTable(ctx, q, t, &acc); err != nil {
			return acc, fmt.Errorf("table %s: %w", t, err)
		}
	}
	return acc, nil
}

func scanTable(ctx context.Context, q rowQuerier, table string, acc *lthash.Hash) error {
	rows, err := q.QueryContext(ctx, fmt.Sprintf("SELECT * FROM %q", table))
	if err != nil {
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		acc.Add(rowDigest(table, vals))
	}
	return rows.Err()
}

// Digest is the content digest of the database (O(1)).
func (s *Store) Digest() [32]byte { return s.dig.sum() }

// ScanDigest recomputes the content digest from the rows themselves. It
// reads the whole database under the store's lock.
func (s *Store) ScanDigest() ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc, err := scanDigest(context.Background(), s.db)
	return acc.Sum(), err
}

// ImageDigest is the content digest of a database image from Dump, read
// from its rows, after the same checks and migration Restore applies.
func ImageDigest(image []byte) ([32]byte, error) {
	var sum [32]byte
	err := withImage(image, func(conn *sql.Conn, acc *lthash.Hash) error {
		sum = acc.Sum()
		return nil
	})
	return sum, err
}
