//go:build linux

package armtlsmesh

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// A connection accepted as the endpoint stops is either served and drained or
// closed, and never counted once the drain waits on the connections in flight.
func TestDrainClosesAConnectionAcceptedAtCancellation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &podEndpoint{
		logger: discardLogger(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	var observed sync.Once
	var releasing sync.Once
	releaseHandlers := func() {
		releasing.Do(func() {
			close(release)
		})
	}
	defer releaseHandlers()
	defer cancel()
	var accepting sync.WaitGroup
	accepting.Add(1)
	go func() {
		defer accepting.Done()
		if err := e.accept(ctx, ln, func(_ context.Context, conn net.Conn) {
			if _, ok := conn.(*net.TCPConn); !ok {
				t.Errorf("accepted connection type = %T, want *net.TCPConn", conn)
			}
			observed.Do(func() {
				close(started)
			})
			<-release
		}); err != nil {
			t.Errorf("accept: %v", err)
		}
	}()

	stop := make(chan struct{})
	var dialers sync.WaitGroup
	for range 4 {
		dialers.Add(1)
		go func() {
			defer dialers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				conn, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					return
				}
				conn.Close()
			}
		}()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("no accepted handler started")
	}

	cancel()
	drained := make(chan struct{})
	go func() {
		e.drain()
		close(drained)
	}()
	select {
	case <-drained:
		t.Fatal("drain returned while an accepted handler was held")
	case <-time.After(20 * time.Millisecond):
	}
	releaseHandlers()
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("drain did not finish after releasing handlers")
	}
	close(stop)
	dialers.Wait()
	accepting.Wait()
}
