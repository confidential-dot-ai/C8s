//go:build linux

package armtlsmesh

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

type endpointAcceptResult struct {
	conn net.Conn
	err  error
}

type endpointTestListener struct {
	results chan endpointAcceptResult
	closed  chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func newEndpointTestListener(t *testing.T) *endpointTestListener {
	t.Helper()
	ln := &endpointTestListener{
		results: make(chan endpointAcceptResult),
		closed:  make(chan struct{}),
	}
	t.Cleanup(func() {
		ln.Close()
	})
	return ln
}

func (l *endpointTestListener) Accept() (net.Conn, error) {
	l.calls.Add(1)
	select {
	case result := <-l.results:
		return result.conn, result.err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *endpointTestListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
	})
	return nil
}

func (l *endpointTestListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

func runEndpointAccept(t *testing.T, ctx context.Context, e *podEndpoint, ln net.Listener, handle func(context.Context, net.Conn)) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- e.accept(ctx, ln, handle)
	}()
	return done
}

func waitEndpointAccept(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("accept did not return")
		return nil
	}
}

func TestPodAcceptBoundsEachListenerAndRecoversCapacity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &podEndpoint{logger: discardLogger()}
	started := make(chan net.Conn, 1)
	handle := func(_ context.Context, conn net.Conn) {
		started <- conn
		_, _ = io.Copy(io.Discard, conn)
	}
	listeners := []*endpointTestListener{newEndpointTestListener(t), newEndpointTestListener(t)}
	var done []<-chan error
	var clients []net.Conn
	for _, ln := range listeners {
		done = append(done, runEndpointAccept(t, ctx, e, ln, handle))
		for range podMaxConnections {
			server, client := net.Pipe()
			t.Cleanup(func() {
				client.Close()
			})
			clients = append(clients, client)
			ln.results <- endpointAcceptResult{conn: server}
			select {
			case accepted := <-started:
				if accepted != server {
					t.Fatal("accepted connection was wrapped")
				}
			case <-time.After(time.Second):
				t.Fatal("listener did not admit its own capacity")
			}
		}
		server, excess := net.Pipe()
		defer excess.Close()
		ln.results <- endpointAcceptResult{conn: server}
		_ = excess.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := excess.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("excess connection read = %v, want EOF", err)
		}
	}
	for _, client := range clients {
		client.Close()
	}
	e.active.Wait()
	for _, ln := range listeners {
		for range podMaxConnections {
			server, recovered := net.Pipe()
			defer recovered.Close()
			ln.results <- endpointAcceptResult{conn: server}
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("listener did not recover capacity")
			}
		}
	}
	cancel()
	for _, stopped := range done {
		if err := waitEndpointAccept(t, stopped); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPodAcceptStopsPermanentErrors(t *testing.T) {
	for _, failure := range []error{syscall.EBADF, net.ErrClosed} {
		t.Run(failure.Error(), func(t *testing.T) {
			ln := newEndpointTestListener(t)
			e := &podEndpoint{logger: discardLogger()}
			done := runEndpointAccept(t, t.Context(), e, ln, func(context.Context, net.Conn) {
				t.Error("unexpected handler")
			})
			ln.results <- endpointAcceptResult{err: failure}
			if err := waitEndpointAccept(t, done); !errors.Is(err, failure) {
				t.Fatalf("accept = %v, want %v", err, failure)
			}
			if calls := ln.calls.Load(); calls != 1 {
				t.Fatalf("accept called %d times, want 1", calls)
			}
		})
	}
}

func TestPodAcceptBackoffWaitsAndResets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ln := newEndpointTestListener(t)
		e := &podEndpoint{logger: discardLogger()}
		started := make(chan struct{})
		done := runEndpointAccept(t, ctx, e, ln, func(context.Context, net.Conn) {
			close(started)
		})
		for _, delay := range []time.Duration{5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000} {
			calls := ln.calls.Load()
			if calls == 0 {
				synctest.Wait()
				calls = ln.calls.Load()
			}
			ln.results <- endpointAcceptResult{err: &net.OpError{
				Op:  "accept",
				Net: "tcp",
				Err: syscall.EMFILE,
			}}
			synctest.Wait()
			if ln.calls.Load() != calls {
				t.Fatal("accept retried without backoff")
			}
			time.Sleep((delay - 1) * time.Millisecond)
			synctest.Wait()
			if ln.calls.Load() != calls {
				t.Fatal("accept retried before the backoff elapsed")
			}
			time.Sleep(time.Millisecond)
			synctest.Wait()
			if ln.calls.Load() != calls+1 {
				t.Fatal("accept did not retry after backoff")
			}
		}
		server, client := net.Pipe()
		defer client.Close()
		ln.results <- endpointAcceptResult{conn: server}
		synctest.Wait()
		select {
		case <-started:
		default:
			t.Fatal("handler did not run after transient accept errors")
		}
		calls := ln.calls.Load()
		ln.results <- endpointAcceptResult{err: &net.OpError{
			Op:  "accept",
			Net: "tcp",
			Err: syscall.EMFILE,
		}}
		time.Sleep(5 * time.Millisecond)
		synctest.Wait()
		if ln.calls.Load() != calls+1 {
			t.Fatal("successful accept did not reset backoff")
		}
		ln.results <- endpointAcceptResult{err: &net.OpError{
			Op:  "accept",
			Net: "tcp",
			Err: syscall.EMFILE,
		}}
		synctest.Wait()
		cancel()
		if err := waitEndpointAccept(t, done); err != nil {
			t.Fatal(err)
		}
	})
}
