//go:build integration && linux

package cdsha_test

import (
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

// Link is the fault state of one direction between two replicas.
type Link struct {
	// Blackhole discards every byte in this direction, as a firewall drop
	// would: the sender sees no error, only silence.
	Blackhole bool
	// Latency delays every chunk; Jitter adds up to that much at random.
	Latency, Jitter time.Duration
	// Loss is the chance a chunk is "lost" and retransmitted: it is delayed
	// by a further 200 ms (TCP does not lose bytes, it delays them).
	Loss float64
}

// faultNet is a TCP proxy in front of every replica's peer port. A replica
// advertises the proxy's address; the proxy forwards to the replica's real
// listener. Replicas dial from their advertised IP, so the proxy knows the
// source replica of each connection and applies the per-direction link.
type faultNet struct {
	mu    sync.Mutex
	links map[[2]int]Link // [from, to]
	conns map[*proxyConn]struct{}
	lns   []net.Listener
}

type proxyConn struct {
	down, up  net.Conn // down: from the dialing replica; up: to the target
	closeOnce sync.Once
}

func (c *proxyConn) close() {
	c.closeOnce.Do(func() {
		c.down.Close()
		c.up.Close()
	})
}

func newFaultNet() *faultNet {
	return &faultNet{links: map[[2]int]Link{}, conns: map[*proxyConn]struct{}{}}
}

// listen proxies listen -> target for replica `to`; srcOf maps a dialing IP
// to the replica index (-1 for anything else).
func (f *faultNet) listen(listen, target string, to int, srcOf func(ip string) int) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.lns = append(f.lns, ln)
	f.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			go f.handle(c, srcOf(host), to, target)
		}
	}()
	return nil
}

func (f *faultNet) close() {
	f.mu.Lock()
	lns := f.lns
	f.lns = nil
	var conns []*proxyConn
	for c := range f.conns {
		conns = append(conns, c)
	}
	f.mu.Unlock()
	for _, ln := range lns {
		ln.Close()
	}
	for _, c := range conns {
		c.close()
	}
}

func (f *faultNet) link(from, to int) Link {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.links[[2]int{from, to}]
}

// Set replaces the link from -> to.
func (f *faultNet) Set(from, to int, l Link) {
	f.mu.Lock()
	f.links[[2]int{from, to}] = l
	f.mu.Unlock()
}

// Update changes the link from -> to in place.
func (f *faultNet) Update(from, to int, fn func(*Link)) {
	f.mu.Lock()
	l := f.links[[2]int{from, to}]
	fn(&l)
	f.links[[2]int{from, to}] = l
	f.mu.Unlock()
}

// HealAll clears every fault.
func (f *faultNet) HealAll() {
	f.mu.Lock()
	f.links = map[[2]int]Link{}
	f.mu.Unlock()
}

func (f *faultNet) handle(down net.Conn, from, to int, target string) {
	up, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		down.Close()
		return
	}
	pc := &proxyConn{down: down, up: up}
	f.mu.Lock()
	f.conns[pc] = struct{}{}
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		delete(f.conns, pc)
		f.mu.Unlock()
	}()
	done := make(chan struct{}, 2)
	go func() { f.pump(pc, down, up, from, to); done <- struct{}{} }()
	go func() { f.pump(pc, up, down, to, from); done <- struct{}{} }()
	<-done
	<-done
	pc.close()
}

type chunk struct {
	b  []byte
	at time.Time
}

// pump copies src -> dst under the link from -> to. On EOF it half-closes
// dst once every queued byte is written; on any error it closes both sides.
func (f *faultNet) pump(pc *proxyConn, src, dst net.Conn, from, to int) {
	q := make(chan chunk, 1024)
	wrote := make(chan bool, 1)
	go func() {
		ok := true
		for c := range q {
			if !ok {
				continue // drain so the reader is not stuck
			}
			if d := time.Until(c.at); d > 0 {
				time.Sleep(d)
			}
			if _, err := dst.Write(c.b); err != nil {
				ok = false
				pc.close()
			}
		}
		wrote <- ok
	}()
	buf := make([]byte, 32<<10)
	var rerr error
	for {
		n, err := src.Read(buf)
		if n > 0 {
			l := Link{}
			if from >= 0 {
				l = f.link(from, to)
			}
			if !l.Blackhole {
				delay := l.Latency
				if l.Jitter > 0 {
					delay += time.Duration(rand.Int64N(int64(l.Jitter)))
				}
				if l.Loss > 0 && rand.Float64() < l.Loss {
					delay += 200 * time.Millisecond
				}
				q <- chunk{b: append([]byte(nil), buf[:n]...), at: time.Now().Add(delay)}
			}
		}
		if err != nil {
			rerr = err
			break
		}
	}
	close(q)
	ok := <-wrote
	if rerr != io.EOF || !ok {
		pc.close()
		return
	}
	if tc, isTCP := dst.(*net.TCPConn); isTCP {
		_ = tc.CloseWrite()
	}
}
