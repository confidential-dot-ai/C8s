package connectbroker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Server connects the mesh endpoint of one pod to its advertised peers.
type Server struct {
	// Peers are the tuples the pod's signed launch advertises; every other
	// destination is refused.
	Peers []netip.AddrPort
	// UID is the only socket owner served: the mesh endpoint's.
	UID uint32
	// Dial opens the guest-side connection; nil means a plain TCP dial from
	// this process's network namespace.
	Dial func(context.Context, string) (net.Conn, error)
	// Timeout bounds one request, dial included.
	Timeout time.Duration
	Logger  *slog.Logger
}

// Serve answers requests until ctx ends or the listener fails. It returns only
// once every connection it accepted is closed: an accepted socket keeps the
// volume the broker listens in busy, so a stopped broker must hold nothing there.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	var handlers sync.WaitGroup
	defer handlers.Wait()
	// A listener failure ends the requests in flight too, not only a stop.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("mesh connect broker accept: %w", err)
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	// The server stopping ends the request: the connection closes under its reads.
	defer context.AfterFunc(ctx, func() { _ = raw.Close() })()
	conn, ok := raw.(*net.UnixConn)
	if !ok {
		return
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	peer, err := s.connect(ctx, conn)
	if err != nil {
		s.log().Warn("refusing a mesh connect request", "error", err)
		_, _ = conn.Write([]byte("refused: " + err.Error() + "\n"))
		return
	}
	defer peer.Close()
	file, err := peer.File()
	if err != nil {
		_, _ = conn.Write([]byte("refused: socket unavailable\n"))
		return
	}
	defer file.Close()
	if _, _, err := conn.WriteMsgUnix([]byte(replyOK), unix.UnixRights(int(file.Fd())), nil); err != nil {
		s.log().Warn("mesh connect reply failed", "error", err)
	}
}

// connect authenticates the caller, reads its request and dials the peer.
func (s *Server) connect(ctx context.Context, conn *net.UnixConn) (*net.TCPConn, error) {
	if !ownedBy(conn, s.UID) {
		return nil, fmt.Errorf("%w: caller is not the mesh endpoint", ErrRefused)
	}
	line, err := readRequest(bufio.NewReaderSize(conn, maxRequest))
	if err != nil {
		return nil, err
	}
	dst, err := decodeRequest(line)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(s.Peers, dst) {
		return nil, fmt.Errorf("%w: %s is not an advertised peer", ErrRefused, dst)
	}
	dial := s.Dial
	if dial == nil {
		dial = func(ctx context.Context, address string) (net.Conn, error) {
			return (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", address)
		}
	}
	peer, err := dial(ctx, dst.String())
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", dst, err)
	}
	tcp, ok := peer.(*net.TCPConn)
	if !ok {
		peer.Close()
		return nil, errors.New("guest dial returned no TCP socket")
	}
	return tcp, nil
}

func (s *Server) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}
