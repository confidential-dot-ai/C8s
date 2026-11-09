package casregister

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Config struct {
	Directory     string
	MemberID      string
	Clusters      []string
	QueueSize     int
	MaxValueBytes int
}

type enrollment struct {
	Member   string
	Clusters []string
	Limit    int
}

type Acceptor struct {
	id       string
	limit    int
	clusters map[string]*acceptorActor
	cancel   context.CancelFunc
	closed   <-chan struct{}
	wait     sync.WaitGroup
}

type acceptorActor struct {
	db    *sql.DB
	inbox chan acceptorRequest
	slots chan struct{}
}

type acceptorRequest struct {
	ctx    context.Context
	ballot Ballot
	value  []byte
	accept bool
	result chan acceptorResult
}

type acceptorResult struct {
	promise Promise
	err     error
}

func config(c Config) (Config, enrollment, error) {
	if c.Directory == "" || c.MemberID == "" || len(c.MemberID) > 256 || len(c.Clusters) == 0 || len(c.Clusters) > 1024 {
		return c, enrollment{}, ErrInvalid
	}
	if c.QueueSize == 0 {
		c.QueueSize = 8
	}
	if c.MaxValueBytes == 0 {
		c.MaxValueBytes = 16 << 20
	}
	if c.QueueSize < 1 || c.QueueSize > 1024 || c.MaxValueBytes < 1 || c.MaxValueBytes > MaxValueBytes {
		return c, enrollment{}, ErrInvalid
	}
	c.Clusters = slices.Clone(c.Clusters)
	slices.Sort(c.Clusters)
	for i, name := range c.Clusters {
		if name == "" || len(name) > 256 || (i > 0 && name == c.Clusters[i-1]) {
			return c, enrollment{}, ErrInvalid
		}
	}
	e := enrollment{
		Member:   c.MemberID,
		Clusters: c.Clusters,
		Limit:    c.MaxValueBytes,
	}
	return c, e, nil
}

// Bootstrap creates a new, absent authority directory. It must never substitute
// for Open when an enrolled member loses its durable state.
func Bootstrap(c Config) (*Acceptor, error) {
	c, enrolled, err := config(c)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(
		c.Directory,
		0700,
	); err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(c.Directory)
		}
	}()
	for _, cluster := range c.Clusters {
		db, err := openDB(
			c.Directory,
			cluster,
			true,
		)
		if err != nil {
			return nil, err
		}
		_, err = db.Exec("CREATE TABLE state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), promise BLOB NOT NULL, ballot BLOB NOT NULL, value BLOB NOT NULL)")
		if err == nil {
			_, err = db.Exec(
				"INSERT INTO state VALUES (1, ?, ?, ?)",
				Ballot{}.encode(),
				Ballot{}.encode(),
				[]byte{},
			)
		}
		closeErr := db.Close()
		if err != nil || closeErr != nil {
			return nil, errors.Join(
				err,
				closeErr,
			)
		}
	}
	data, _ := json.Marshal(enrolled)
	file, err := os.OpenFile(
		filepath.Join(
			c.Directory,
			"enrollment.json",
		),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0600,
	)
	if err != nil {
		return nil, err
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(
		writeErr,
		syncErr,
		closeErr,
		syncDirectory(c.Directory),
		syncDirectory(filepath.Dir(c.Directory)),
	); err != nil {
		return nil, err
	}
	a, err := Open(c)
	complete = err == nil
	return a, err
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func Open(c Config) (*Acceptor, error) {
	c, want, err := config(c)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(
		c.Directory,
		"enrollment.json",
	))
	if err != nil {
		return nil, err
	}
	var held enrollment
	if json.Unmarshal(
		data,
		&held,
	) != nil || held.Member != want.Member || held.Limit != want.Limit || !slices.Equal(
		held.Clusters,
		want.Clusters,
	) {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &Acceptor{
		id:       c.MemberID,
		limit:    c.MaxValueBytes,
		clusters: make(map[string]*acceptorActor),
		cancel:   cancel,
		closed:   ctx.Done(),
	}
	for _, cluster := range c.Clusters {
		db, err := openDB(
			c.Directory,
			cluster,
			false,
		)
		if err == nil {
			_, _, _, err = load(db)
		}
		if err != nil {
			if db != nil {
				_ = db.Close()
			}
			cancel()
			for _, actor := range a.clusters {
				_ = actor.db.Close()
			}
			return nil, err
		}
		a.clusters[cluster] = &acceptorActor{
			db: db,
			inbox: make(
				chan acceptorRequest,
				c.QueueSize,
			),
			slots: make(
				chan struct{},
				c.QueueSize+1,
			),
		}
	}
	for _, actor := range a.clusters {
		a.wait.Add(1)
		go func() {
			defer a.wait.Done()
			defer actor.db.Close()
			defer actor.drain()
			for {
				select {
				case <-ctx.Done():
					return
				case request := <-actor.inbox:
					var promise Promise
					err := ctx.Err()
					if err == nil {
						promise, err = actor.apply(request)
					}
					request.result <- acceptorResult{
						promise: promise,
						err:     err,
					}
					clear(request.value)
					<-actor.slots
				}
			}
		}()
	}
	return a, nil
}

func (a *acceptorActor) drain() {
	for {
		select {
		case r := <-a.inbox:
			clear(r.value)
			r.result <- acceptorResult{err: ErrClosed}
			<-a.slots
		default:
			return
		}
	}
}

func openDB(
	directory string,
	cluster string,
	create bool,
) (*sql.DB, error) {
	sum := sha256.Sum256([]byte(cluster))
	path, err := filepath.Abs(filepath.Join(
		directory,
		hex.EncodeToString(sum[:])+".sqlite",
	))
	if err != nil {
		return nil, err
	}
	mode := "rw"
	if create {
		mode = "rwc"
	}
	query := url.Values{
		"mode":    {mode},
		"_pragma": {"synchronous(FULL)"},
	}
	u := url.URL{
		Scheme:   "file",
		Path:     path,
		RawQuery: query.Encode(),
	}
	db, err := sql.Open(
		"sqlite",
		u.String(),
	)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()
	var journal string
	if err = db.QueryRowContext(
		ctx,
		"PRAGMA journal_mode=WAL",
	).Scan(&journal); err == nil && journal != "wal" {
		err = ErrInvalid
	}
	if err == nil {
		_, err = db.ExecContext(
			ctx,
			"PRAGMA synchronous=FULL",
		)
	}
	var synchronous int
	if err == nil {
		err = db.QueryRowContext(
			ctx,
			"PRAGMA synchronous",
		).Scan(&synchronous)
		if err == nil && synchronous != 2 {
			err = ErrInvalid
		}
	}
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

type rowReader interface {
	QueryRow(
		string,
		...any,
	) *sql.Row
}

func load(reader rowReader) (Ballot, Ballot, []byte, error) {
	var promised, accepted, value []byte
	if err := reader.QueryRow("SELECT promise, ballot, value FROM state WHERE singleton=1").Scan(
		&promised,
		&accepted,
		&value,
	); err != nil {
		return Ballot{}, Ballot{}, nil, err
	}
	p, pErr := decodeBallot(promised)
	b, bErr := decodeBallot(accepted)
	if pErr != nil || bErr != nil || b.Compare(p) > 0 || len(value) > MaxValueBytes || (b == (Ballot{}) && len(value) != 0) {
		return Ballot{}, Ballot{}, nil, ErrInvalid
	}
	return p, b, value, nil
}

func (a *acceptorActor) apply(r acceptorRequest) (Promise, error) {
	if err := r.ctx.Err(); err != nil {
		return Promise{}, err
	}
	tx, err := a.db.BeginTx(
		r.ctx,
		nil,
	)
	if err != nil {
		return Promise{}, err
	}
	defer tx.Rollback()
	promised, accepted, value, err := load(tx)
	if err != nil {
		return Promise{}, err
	}
	if r.ballot.Compare(promised) < 0 {
		return Promise{}, &Preempted{Promise: promised}
	}
	if r.accept {
		if r.ballot == accepted && !bytes.Equal(
			r.value,
			value,
		) {
			return Promise{}, ErrEquivocation
		}
		_, err = tx.ExecContext(
			r.ctx,
			"UPDATE state SET promise=?, ballot=?, value=? WHERE singleton=1",
			r.ballot.encode(),
			r.ballot.encode(),
			r.value,
		)
	} else {
		_, err = tx.ExecContext(
			r.ctx,
			"UPDATE state SET promise=? WHERE singleton=1",
			r.ballot.encode(),
		)
	}
	if err != nil {
		return Promise{}, err
	}
	if err := tx.Commit(); err != nil {
		return Promise{}, err
	}
	return Promise{
		Accepted: accepted,
		Value:    value,
	}, nil
}

func (a *Acceptor) ID() string { return a.id }

func (a *Acceptor) Prepare(
	ctx context.Context,
	cluster string,
	ballot Ballot,
) (Promise, error) {
	return a.call(
		ctx,
		cluster,
		ballot,
		nil,
		false,
	)
}

func (a *Acceptor) Accept(
	ctx context.Context,
	cluster string,
	ballot Ballot,
	value []byte,
) error {
	_, err := a.call(
		ctx,
		cluster,
		ballot,
		value,
		true,
	)
	return err
}

func (a *Acceptor) call(
	ctx context.Context,
	cluster string,
	ballot Ballot,
	value []byte,
	accept bool,
) (Promise, error) {
	actor, ok := a.clusters[cluster]
	if !ok || !ballot.valid() || len(value) > a.limit {
		return Promise{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(
		ctx,
		5*time.Second,
	)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Promise{}, err
	}
	select {
	case <-a.closed:
		return Promise{}, ErrClosed
	case actor.slots <- struct{}{}:
	default:
		return Promise{}, ErrBusy
	}
	queued := false
	defer func() {
		if !queued {
			<-actor.slots
		}
	}()
	r := acceptorRequest{
		ctx:    ctx,
		ballot: ballot,
		value:  bytes.Clone(value),
		accept: accept,
		result: make(
			chan acceptorResult,
			1,
		),
	}
	if accept && r.value == nil {
		r.value = []byte{}
	}
	select {
	case <-a.closed:
		return Promise{}, ErrClosed
	case actor.inbox <- r:
		queued = true
	default:
		return Promise{}, ErrBusy
	}
	select {
	case result := <-r.result:
		return result.promise, result.err
	case <-a.closed:
		return Promise{}, ErrClosed
	case <-ctx.Done():
		return Promise{}, ctx.Err()
	}
}

func (a *Acceptor) Close() error {
	a.cancel()
	a.wait.Wait()
	return nil
}
