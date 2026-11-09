package casregister

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func authorities(t *testing.T) ([]*Acceptor, []Config) {
	t.Helper()
	var acceptors []*Acceptor
	var configs []Config
	for i := range 3 {
		cfg := Config{
			Directory: filepath.Join(
				t.TempDir(),
				"authority",
			),
			MemberID: fmt.Sprintf(
				"member-%d",
				i,
			),
			Clusters: []string{
				"cluster",
				"other",
			},
			QueueSize:     8,
			MaxValueBytes: 4096,
		}
		a, err := Bootstrap(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Close() })
		acceptors, configs = append(
			acceptors,
			a,
		), append(
			configs,
			cfg,
		)
	}
	return acceptors, configs
}

func peers(acceptors []*Acceptor) []Peer {
	var out []Peer
	for _, a := range acceptors {
		out = append(
			out,
			a,
		)
	}
	return out
}

func proposer(
	t *testing.T,
	peers []Peer,
) *Proposer {
	t.Helper()
	p, err := NewProposer(
		peers,
		"cluster",
		8,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func read(
	t *testing.T,
	p *Proposer,
) []byte {
	t.Helper()
	value, err := p.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testBallot(round uint64) Ballot {
	return Ballot{
		Round: round,
		Owner: [32]byte{1},
	}
}

func TestDurableStateAndPromises(t *testing.T) {
	acceptors, configs := authorities(t)
	p := proposer(
		t,
		peers(acceptors),
	)
	want := []byte("opaque encrypted CDS state")
	if _, err := p.Update(
		context.Background(),
		func([]byte) ([]byte, error) { return want, nil },
	); err != nil {
		t.Fatal(err)
	}
	for _, a := range acceptors {
		if _, err := a.Prepare(
			context.Background(),
			"cluster",
			testBallot(1_000_000),
		); err != nil {
			t.Fatal(err)
		}
		_ = a.Close()
	}
	p.Close()
	for i, cfg := range configs {
		a, err := Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Close() })
		acceptors[i] = a
		if err := a.Accept(
			context.Background(),
			"cluster",
			testBallot(2),
			[]byte("old"),
		); err == nil {
			t.Fatal("forgot persisted promise")
		}
	}
	fresh := proposer(
		t,
		peers(acceptors),
	)
	if got := read(
		t,
		fresh,
	); !bytes.Equal(
		got,
		want,
	) {
		t.Fatalf(
			"lost acknowledged state: %q",
			got,
		)
	}
	for _, a := range acceptors {
		if err := a.Accept(
			context.Background(),
			"other",
			testBallot(1),
			[]byte("first"),
		); err != nil {
			t.Fatal(err)
		}
		if err := a.Accept(
			context.Background(),
			"other",
			testBallot(1),
			[]byte("second"),
		); !errors.Is(
			err,
			ErrEquivocation,
		) {
			t.Fatalf(
				"same-ballot overwrite: %v",
				err,
			)
		}
	}
}

type dropAck struct{ Peer }

type offline struct{ Peer }

func (o offline) Prepare(
	context.Context,
	string,
	Ballot,
) (Promise, error) {
	return Promise{}, ErrClosed
}

func (o offline) Accept(
	context.Context,
	string,
	Ballot,
	[]byte,
) error {
	return ErrClosed
}

func TestStateDependentRefusalAcceptsItsObservation(t *testing.T) {
	a, _ := authorities(t)
	if err := a[0].Accept(
		context.Background(),
		"cluster",
		testBallot(1),
		[]byte("spent"),
	); err != nil {
		t.Fatal(err)
	}
	p := proposer(
		t,
		[]Peer{
			a[0],
			a[1],
			offline{a[2]},
		},
	)
	refused := false
	if _, err := p.Update(
		context.Background(),
		func(current []byte) ([]byte, error) {
			refused = string(current) == "spent"
			return current, nil
		},
	); err != nil || !refused {
		t.Fatalf(
			"could not commit observed refusal: refused=%v, %v",
			refused,
			err,
		)
	}
	q := proposer(
		t,
		[]Peer{
			offline{a[0]},
			a[1],
			a[2],
		},
	)
	if got := read(
		t,
		q,
	); string(got) != "spent" {
		t.Fatalf(
			"later quorum forgot the refused spend: %q",
			got,
		)
	}
}

func (d dropAck) Accept(
	ctx context.Context,
	cluster string,
	ballot Ballot,
	value []byte,
) error {
	if err := d.Peer.Accept(
		ctx,
		cluster,
		ballot,
		value,
	); err != nil {
		return err
	}
	return errors.New("lost acknowledgment")
}

func TestUnknownDoesNotRetryTransform(t *testing.T) {
	acceptors, _ := authorities(t)
	var wrapped []Peer
	for _, a := range acceptors {
		wrapped = append(
			wrapped,
			dropAck{a},
		)
	}
	p := proposer(
		t,
		wrapped,
	)
	calls := 0
	_, err := p.Update(
		context.Background(),
		func([]byte) ([]byte, error) {
			calls++
			return []byte("one effect"), nil
		},
	)
	if !errors.Is(
		err,
		ErrUnknown,
	) || calls != 1 {
		t.Fatalf(
			"ambiguous operation was retried or misclassified: %v, calls=%d",
			err,
			calls,
		)
	}
	if got := read(
		t,
		proposer(
			t,
			peers(acceptors),
		),
	); string(got) != "one effect" {
		t.Fatalf(
			"committed state missing: %q",
			got,
		)
	}
}

type delayedAccept struct {
	Peer
	started   chan<- struct{}
	release   <-chan struct{}
	completed chan<- error
	jobs      *sync.WaitGroup
}

func (d delayedAccept) Accept(
	ctx context.Context,
	cluster string,
	ballot Ballot,
	value []byte,
) error {
	value = bytes.Clone(value)
	d.jobs.Add(1)
	go func() {
		defer d.jobs.Done()
		<-d.release
		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancel()
		d.completed <- d.Peer.Accept(
			ctx,
			cluster,
			ballot,
			value,
		)
	}()
	d.started <- struct{}{}
	<-ctx.Done()
	return ctx.Err()
}

func TestCanceledAcceptanceCanCommitLater(t *testing.T) {
	acceptors, _ := authorities(t)
	started, release, completed := make(
		chan struct{},
		3,
	), make(chan struct{}), make(
		chan error,
		3,
	)
	var jobs sync.WaitGroup
	var wrapped []Peer
	for _, a := range acceptors {
		wrapped = append(
			wrapped,
			delayedAccept{
				a,
				started,
				release,
				completed,
				&jobs,
			},
		)
	}
	p := proposer(
		t,
		wrapped,
	)
	ctx, cancel := context.WithCancel(context.Background())
	var once sync.Once
	finish := func() {
		once.Do(func() {
			cancel()
			p.Close()
			close(release)
			jobs.Wait()
		})
	}
	t.Cleanup(finish)
	done := make(
		chan error,
		1,
	)
	go func() {
		_, err := p.Update(
			ctx,
			func([]byte) ([]byte, error) { return []byte("late"), nil },
		)
		done <- err
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("acceptance not dispatched")
		}
	}
	cancel()
	if err := <-done; !errors.Is(
		err,
		ErrUnknown,
	) {
		t.Fatalf(
			"acceptance cancellation reported a definite outcome: %v",
			err,
		)
	}
	finish()
	for len(completed) > 0 {
		if err := <-completed; err != nil {
			t.Fatal(err)
		}
	}
	if got := read(
		t,
		proposer(
			t,
			peers(acceptors),
		),
	); string(got) != "late" {
		t.Fatalf(
			"late accept was discarded: %q",
			got,
		)
	}
}

func TestCancellationBeforeAcceptanceFencesEffect(t *testing.T) {
	acceptors, _ := authorities(t)
	p := proposer(
		t,
		peers(acceptors),
	)
	entered, release := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(
		chan error,
		1,
	)
	go func() {
		_, err := p.Update(
			ctx,
			func([]byte) ([]byte, error) {
				close(entered)
				<-release
				return []byte("must not commit"), nil
			},
		)
		done <- err
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf(
			"transform never started: %v",
			err,
		)
	}
	cancel()
	select {
	case err := <-done:
		t.Fatalf(
			"returned while callback still owns input: %v",
			err,
		)
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	if err := <-done; !errors.Is(
		err,
		ErrUnavailable,
	) || errors.Is(
		err,
		ErrUnknown,
	) {
		t.Fatalf(
			"pre-accept cancellation: %v",
			err,
		)
	}
	p.Close()
	if got := read(
		t,
		proposer(
			t,
			peers(acceptors),
		),
	); len(got) != 0 {
		t.Fatal("canceled transform committed")
	}
}

func TestConcurrentSingleUse(t *testing.T) {
	acceptors, _ := authorities(t)
	start := make(chan struct{})
	var done sync.WaitGroup
	var success atomic.Int32
	for range 3 {
		p := proposer(
			t,
			peers(acceptors),
		)
		done.Add(1)
		go func() {
			defer done.Done()
			<-start
			refused := false
			_, err := p.Update(
				context.Background(),
				func(current []byte) ([]byte, error) {
					if len(current) != 0 {
						refused = true
						return current, nil
					}
					return []byte("spent"), nil
				},
			)
			if err == nil && !refused {
				success.Add(1)
			} else if err != nil && !errors.Is(
				err,
				ErrUnknown,
			) {
				t.Errorf(
					"unexpected failure: %v",
					err,
				)
			}
		}()
	}
	close(start)
	done.Wait()
	if success.Load() > 1 {
		t.Fatal("single-use transition acknowledged twice")
	}
	if got := read(
		t,
		proposer(
			t,
			peers(acceptors),
		),
	); string(got) != "spent" {
		t.Fatalf(
			"missing chosen effect: %q",
			got,
		)
	}
}

func TestClusterBackpressureIsolation(t *testing.T) {
	acceptors, _ := authorities(t)
	a := acceptors[0]
	actor := a.clusters["cluster"]
	conn, err := actor.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var done sync.WaitGroup
	for i := range 9 {
		done.Add(1)
		go func() {
			defer done.Done()
			_, _ = a.Prepare(
				ctx,
				"cluster",
				testBallot(uint64(i+1)),
			)
		}()
		want := i + 1
		waitFor(
			t,
			func() bool { return len(actor.slots) == want },
		)
		if i == 0 {
			waitFor(
				t,
				func() bool { return actor.db.Stats().WaitCount > 0 },
			)
		}
	}
	if _, err := a.Prepare(
		context.Background(),
		"cluster",
		testBallot(99),
	); !errors.Is(
		err,
		ErrBusy,
	) {
		t.Fatalf(
			"overload was not rejected: %v",
			err,
		)
	}
	if _, err := a.Prepare(
		context.Background(),
		"other",
		testBallot(1),
	); err != nil {
		t.Fatalf(
			"another cluster was blocked: %v",
			err,
		)
	}
	cancel()
	_ = conn.Close()
	done.Wait()
}

func TestAdmissionCopiesAndBounds(t *testing.T) {
	acceptors, _ := authorities(t)
	a := acceptors[0]
	if err := a.Accept(
		context.Background(),
		"cluster",
		testBallot(1),
		make(
			[]byte,
			4097,
		),
	); !errors.Is(
		err,
		ErrInvalid,
	) {
		t.Fatalf(
			"oversize payload admitted: %v",
			err,
		)
	}
	actor := a.clusters["cluster"]
	conn, err := actor.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("immutable at admission")
	done := make(
		chan error,
		1,
	)
	go func() {
		done <- a.Accept(
			context.Background(),
			"cluster",
			testBallot(1),
			payload,
		)
	}()
	waitFor(
		t,
		func() bool { return actor.db.Stats().WaitCount > 0 },
	)
	clear(payload)
	_ = conn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got, err := a.Prepare(
		context.Background(),
		"cluster",
		testBallot(2),
	)
	if err != nil || string(got.Value) != "immutable at admission" {
		t.Fatalf(
			"caller mutation changed admitted state: %q, %v",
			got.Value,
			err,
		)
	}
}

func TestOneFailedMemberAndNoQuorum(t *testing.T) {
	acceptors, _ := authorities(t)
	p := proposer(
		t,
		peers(acceptors),
	)
	_ = acceptors[2].Close()
	if _, err := p.Update(
		context.Background(),
		func([]byte) ([]byte, error) { return []byte("chosen"), nil },
	); err != nil {
		t.Fatalf(
			"one failed member blocked quorum: %v",
			err,
		)
	}
	_ = acceptors[1].Close()
	called := false
	_, err := p.Update(
		context.Background(),
		func([]byte) ([]byte, error) {
			called = true
			return []byte("unavailable"), nil
		},
	)
	if !errors.Is(
		err,
		ErrUnavailable,
	) || errors.Is(
		err,
		ErrUnknown,
	) || called {
		t.Fatalf(
			"no quorum admitted an application transition: %v, called=%v",
			err,
			called,
		)
	}
}

func TestAcceptorCrashDurability(t *testing.T) {
	acceptors, configs := authorities(t)
	_ = acceptors[0].Close()
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestAcceptorCrashChild$",
	)
	command.Env = append(
		os.Environ(),
		"CASREGISTER_CHILD_DIRECTORY="+configs[0].Directory,
	)
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	ready := make(
		chan string,
		1,
	)
	go func() {
		line, _ := bufio.NewReader(output).ReadString('\n')
		ready <- line
	}()
	select {
	case line := <-ready:
		if line != "committed\n" {
			t.Fatalf(
				"child did not commit: %q",
				line,
			)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("child startup timed out")
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	if command.ProcessState.ExitCode() != -1 {
		t.Fatalf(
			"child did not terminate by signal: %v",
			command.ProcessState,
		)
	}
	a, err := Open(configs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Prepare(
		context.Background(),
		"cluster",
		testBallot(8),
	); err == nil {
		t.Fatal("crash erased promise")
	}
	got, err := a.Prepare(
		context.Background(),
		"cluster",
		testBallot(10),
	)
	if err != nil || string(got.Value) != "survived abrupt process loss" {
		t.Fatalf(
			"crash erased accepted value: %q, %v",
			got.Value,
			err,
		)
	}
}

func TestAcceptorCrashChild(t *testing.T) {
	directory := os.Getenv("CASREGISTER_CHILD_DIRECTORY")
	if directory == "" {
		t.Skip("child process helper")
	}
	a, err := Open(Config{
		Directory: directory,
		MemberID:  "member-0",
		Clusters: []string{
			"cluster",
			"other",
		},
		QueueSize:     8,
		MaxValueBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Accept(
		context.Background(),
		"cluster",
		testBallot(9),
		[]byte("survived abrupt process loss"),
	); err != nil {
		t.Fatal(err)
	}
	fmt.Println("committed")
	for {
		time.Sleep(time.Hour)
	}
}

func waitFor(
	t *testing.T,
	predicate func() bool,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMissingStateAndInvalidMembershipRefuse(t *testing.T) {
	acceptors, configs := authorities(t)
	if _, err := Bootstrap(configs[0]); err == nil {
		t.Fatal("bootstrapped existing member")
	}
	bad := configs[0]
	bad.MemberID = "different"
	if _, err := Open(bad); err == nil {
		t.Fatal("opened mismatched member identity")
	}
	if _, err := NewProposer(
		[]Peer{
			acceptors[0],
			acceptors[0],
			acceptors[1],
		},
		"cluster",
		8,
	); err == nil {
		t.Fatal("duplicate members counted toward quorum")
	}
	_ = acceptors[0].Close()
	files, err := filepath.Glob(filepath.Join(
		configs[0].Directory,
		"*.sqlite",
	))
	if err != nil || len(files) != 2 {
		t.Fatalf(
			"database files: %v, %v",
			files,
			err,
		)
	}
	if err := os.Remove(files[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(configs[0]); err == nil {
		t.Fatal("missing enrolled state silently bootstrapped")
	}
	if _, err := os.Stat(files[0]); !os.IsNotExist(err) {
		t.Fatalf(
			"open recreated missing database: %v",
			err,
		)
	}
}
