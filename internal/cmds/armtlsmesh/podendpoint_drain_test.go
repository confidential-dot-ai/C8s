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
	var accepting sync.WaitGroup
	accepting.Add(1)
	go func() {
		defer accepting.Done()
		if err := e.accept(ctx, ln, func(context.Context, net.Conn) {}); err != nil {
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
	time.Sleep(5 * time.Millisecond)

	cancel()
	e.drain()
	close(stop)
	dialers.Wait()
	accepting.Wait()
}
