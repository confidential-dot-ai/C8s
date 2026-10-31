package allowlist

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/confidential-dot-ai/c8s/internal/lthash"
)

// The content digest names what the database holds: a multiset hash over
// every row of every table, independent of rowids, page layout and the order
// the rows were written in, so two stores holding the same rows agree.
//
// SQLite's pre-update hook reports every row a statement changes, on every
// connection the store opens, and the rows count once their transaction
// commits. Two kinds of change the digest cannot account for are refused:
//   - a statement that changed rows and then failed: SQLite rolls that
//     statement back and leaves the transaction open, so the connection
//     refuses to commit it;
//   - a column a hook and a scan read as different Go types, which is REAL
//     (SQLite keeps an integral real as an integer) and DATE, DATETIME or
//     TIMESTAMP (the driver scans a time.Time): naming such a row fails, so
//     the store holding it does not open.

type contentDigest struct {
	mu  sync.Mutex
	acc lthash.Hash
}

// For content that arrived without the hooks reporting it.
func (d *contentDigest) startsFrom(acc lthash.Hash) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.acc = acc
}

func (d *contentDigest) sum() [32]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.acc.Sum()
}

// What the commit hook answers SQLite: any value but zero rolls back.
const (
	commits   int32 = 0
	rollsBack int32 = 1
)

func (d *contentDigest) committed(changes *rowChanges) int32 {
	defer changes.discard()
	if changes.untrusted {
		return rollsBack
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.acc.Combine(&changes.pending)
	return commits
}

// A driver connection serves one caller at a time and the hooks run inside
// its statements, so no field here is shared between goroutines.
type rowChanges struct {
	pending  lthash.Hash
	reported int
	// No commit takes untrusted changes.
	untrusted bool
}

func (c *rowChanges) row(u sqlite.SQLitePreUpdateData) {
	if !changesTheStore(u) {
		return
	}
	c.reported++
	delta, err := changedRow(u)
	if err != nil {
		slog.Error("allowlist: the content digest cannot name a row a write changed",
			"table", u.TableName, "error", err)
		return
	}
	c.pending.Combine(&delta)
}

// SQLite rolls back the rows of a failed statement, which leaves the rest of
// the transaction's changes indistinguishable from them.
func (c *rowChanges) ran(reportedBefore int, err error) {
	if err != nil && c.reported != reportedBefore {
		c.untrusted = true
	}
}

func (c *rowChanges) discard() {
	c.pending = lthash.Hash{}
	c.untrusted = false
}

// Not a VACUUM INTO target or a temporary table.
func changesTheStore(u sqlite.SQLitePreUpdateData) bool {
	return u.DatabaseName == "main"
}

func changedRow(u sqlite.SQLitePreUpdateData) (lthash.Hash, error) {
	switch u.Op {
	case sqlite3.SQLITE_INSERT:
		return rowStored(u)
	case sqlite3.SQLITE_DELETE:
		return rowReplaced(u)
	case sqlite3.SQLITE_UPDATE:
		return rowUpdated(u)
	}
	return lthash.Hash{}, fmt.Errorf("a row change SQLite reports as operation %d", u.Op)
}

func rowStored(u sqlite.SQLitePreUpdateData) (lthash.Hash, error) {
	var delta lthash.Hash
	element, err := hookRow(u, u.New)
	if err != nil {
		return delta, err
	}
	delta.Add(element)
	return delta, nil
}

func rowReplaced(u sqlite.SQLitePreUpdateData) (lthash.Hash, error) {
	var delta lthash.Hash
	element, err := hookRow(u, u.Old)
	if err != nil {
		return delta, err
	}
	delta.Remove(element)
	return delta, nil
}

func rowUpdated(u sqlite.SQLitePreUpdateData) (lthash.Hash, error) {
	delta, err := rowReplaced(u)
	if err != nil {
		return lthash.Hash{}, err
	}
	stored, err := rowStored(u)
	if err != nil {
		return lthash.Hash{}, err
	}
	delta.Combine(&stored)
	return delta, nil
}

func hookRow(u sqlite.SQLitePreUpdateData, fill func(...any) error) ([32]byte, error) {
	row := make([]any, u.Count())
	if err := fill(row...); err != nil {
		return [32]byte{}, err
	}
	return rowElement(u.TableName, row)
}

// The hooks and a scan of the rows name a row alike. The rowid is left out:
// stores need not agree on it.
func rowElement(table string, columns []any) ([32]byte, error) {
	fields := make([][]byte, 0, len(columns)+1)
	fields = append(fields, []byte(table))
	for at, value := range columns {
		field, err := columnField(value)
		if err != nil {
			return [32]byte{}, fmt.Errorf("%s column %d: %w", table, at, err)
		}
		fields = append(fields, field)
	}
	return lthash.Element(fields...), nil
}

// Storage class then bytes, so NULL, an empty text and an empty blob differ.
func columnField(value any) ([]byte, error) {
	switch value := value.(type) {
	case nil:
		return []byte{'n'}, nil
	case int64:
		return binary.BigEndian.AppendUint64([]byte{'i'}, uint64(value)), nil
	case string:
		return append([]byte{'s'}, value...), nil
	case []byte:
		return append([]byte{'b'}, value...), nil
	}
	return nil, fmt.Errorf("a column value of type %T is one the digest cannot name", value)
}

func (d *contentDigest) openDB(uri string) (*sql.DB, error) {
	connector, err := sqlite.NewConnector(uri)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(hookedConnector{
		Connector: connector,
		dig:       d,
	}), nil
}

type hookedConnector struct {
	driver.Connector
	dig *contentDigest
}

type sqliteConn interface {
	driver.Conn
	driver.ConnBeginTx
	driver.ConnPrepareContext
	driver.ExecerContext
	driver.QueryerContext
	driver.Pinger
	driver.SessionResetter
	driver.Validator
	sqlite.HookRegisterer
}

func (c hookedConnector) Connect(ctx context.Context) (driver.Conn, error) {
	opened, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	conn, ok := opened.(sqliteConn)
	if !ok {
		_ = opened.Close()
		return nil, fmt.Errorf("allowlist: a SQLite connection (%T) the content digest cannot follow", opened)
	}
	changes := &rowChanges{}
	conn.RegisterPreUpdateHook(changes.row)
	conn.RegisterCommitHook(func() int32 { return c.dig.committed(changes) })
	conn.RegisterRollbackHook(changes.discard)
	return hookedConn{
		sqliteConn: conn,
		changes:    changes,
	}, nil
}

type hookedConn struct {
	sqliteConn
	changes *rowChanges
}

func (c hookedConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	reported := c.changes.reported
	result, err := c.sqliteConn.ExecContext(ctx, query, args)
	c.changes.ran(reported, err)
	return result, err
}

func (c hookedConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	reported := c.changes.reported
	rows, err := c.sqliteConn.QueryContext(ctx, query, args)
	c.changes.ran(reported, err)
	return rows, err
}

func (c hookedConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	stmt, err := c.sqliteConn.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	prepared, ok := stmt.(sqliteStmt)
	if !ok {
		_ = stmt.Close()
		return nil, fmt.Errorf("allowlist: a prepared statement (%T) the content digest cannot follow", stmt)
	}
	return hookedStmt{
		sqliteStmt: prepared,
		changes:    c.changes,
	}, nil
}

type sqliteStmt interface {
	driver.Stmt
	driver.StmtExecContext
	driver.StmtQueryContext
}

type hookedStmt struct {
	sqliteStmt
	changes *rowChanges
}

func (s hookedStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	reported := s.changes.reported
	result, err := s.sqliteStmt.ExecContext(ctx, args)
	s.changes.ran(reported, err)
	return result, err
}

func (s hookedStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	reported := s.changes.reported
	rows, err := s.sqliteStmt.QueryContext(ctx, args)
	s.changes.ran(reported, err)
	return rows, err
}

type rowQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func scanDigest(ctx context.Context, q rowQuerier) (lthash.Hash, error) {
	var acc lthash.Hash
	tables, err := tableNames(ctx, q)
	if err != nil {
		return acc, err
	}
	for _, table := range tables {
		if err := scanTable(ctx, q, table, &acc); err != nil {
			return acc, fmt.Errorf("table %s: %w", table, err)
		}
	}
	return acc, nil
}

// SQLite's own tables left out.
func tableNames(ctx context.Context, q rowQuerier) ([]string, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT name
		FROM sqlite_schema
		WHERE type = 'table' AND name NOT LIKE 'sqlite\_%' ESCAPE '\'
		ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func scanTable(ctx context.Context, q rowQuerier, table string, acc *lthash.Hash) error {
	rows, err := q.QueryContext(ctx, fmt.Sprintf("SELECT * FROM %q", table))
	if err != nil {
		return err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return err
	}
	for rows.Next() {
		row, err := scanRow(rows, len(columns))
		if err != nil {
			return err
		}
		element, err := rowElement(table, row)
		if err != nil {
			return err
		}
		acc.Add(element)
	}
	return rows.Err()
}

func scanRow(rows *sql.Rows, columns int) ([]any, error) {
	row := make([]any, columns)
	into := make([]any, columns)
	for at := range row {
		into[at] = &row[at]
	}
	if err := rows.Scan(into...); err != nil {
		return nil, err
	}
	return row, nil
}

func (s *Store) Digest() [32]byte {
	return s.dig.sum()
}

// ScanDigest reads the digest from the rows and reports it with the one the
// store keeps, both as of one moment; they differ when content changed under
// the store.
func (s *Store) ScanDigest() (scanned, kept [32]byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc, err := scanDigest(context.Background(), s.db)
	return acc.Sum(), s.dig.sum(), err
}
