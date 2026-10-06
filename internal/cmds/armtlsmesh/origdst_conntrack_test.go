//go:build linux

package armtlsmesh

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// A connection that never went through iptables REDIRECT must be rejected.
// Without conntrack both family probes fail and the error must come from the
// final IPv4 fallback, never a synthesized zero address; with conntrack the
// kernel answers with the listener's own address, which must be refused as a
// direct dial (forwarding there would loop the proxy onto itself).
func TestDefaultOrigDstFuncFailsWithoutRedirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acceptedCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		acceptedCh <- c
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	accepted := <-acceptedCh
	defer accepted.Close()

	// The proxy reads the original destination from the connection it
	// accepted, so probe that side, not the client's.
	dst, err := defaultOrigDstFunc(accepted)
	if err == nil {
		t.Fatalf("defaultOrigDstFunc succeeded with %q on a non-redirected connection", dst)
	}
	if !strings.Contains(err.Error(), "getsockopt IPv4") && !strings.Contains(err.Error(), "dialed directly") {
		t.Errorf("error = %v, want the IPv4-fallback getsockopt failure or the direct-dial rejection", err)
	}
}

func TestDefaultOrigDstFuncRejectsNonTCP(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_, err := defaultOrigDstFunc(a)
	if err == nil || !strings.Contains(err.Error(), "not a TCP connection") {
		t.Errorf("error = %v, want not-a-TCP-connection", err)
	}
}

// conntrackDeleteStub records flushCWConntrack's delete calls and returns a
// scripted outcome.
type conntrackDeleteStub struct {
	calls   []netlink.InetFamily
	filters []int
	deleted uint
	err     error
	// byFamily, when set, overrides the scalar outcome per address family.
	byFamily func(netlink.InetFamily) (uint, error)
}

func (s *conntrackDeleteStub) delete(_ netlink.ConntrackTableType, family netlink.InetFamily, filters ...netlink.CustomConntrackFilter) (uint, error) {
	s.calls = append(s.calls, family)
	s.filters = append(s.filters, len(filters))
	if s.byFamily != nil {
		return s.byFamily(family)
	}
	return s.deleted, s.err
}

// The flush must reach the conntrack delete for valid IPs and report the
// outcome — entries deleted, failures — through its return, and garbage IPs
// must never reach netlink. The delete is stubbed, so this holds with and
// without CAP_NET_ADMIN.
func TestFlushCWConntrackReachesDeleteForValidIPs(t *testing.T) {
	stub := &conntrackDeleteStub{}
	orig := conntrackDeleteFilters
	conntrackDeleteFilters = stub.delete
	t.Cleanup(func() { conntrackDeleteFilters = orig })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	errDelete := errors.New("delete failed")
	tests := []struct {
		name        string
		ips         []string
		stubDeleted uint
		stubErr     error
		wantCalls   []netlink.InetFamily
		wantFilters []int
		wantDeleted int
		wantErr     error
	}{
		{"valid IPv4 reaches the delete", []string{"10.99.88.7"}, 0, nil, []netlink.InetFamily{unix.AF_INET}, []int{1}, 0, nil},
		{"delete failure is returned", []string{"10.99.88.7"}, 0, errDelete, []netlink.InetFamily{unix.AF_INET}, []int{1}, 0, errDelete},
		{"partial delete with failure", []string{"10.99.88.7"}, 1, errDelete, []netlink.InetFamily{unix.AF_INET}, []int{1}, 1, errDelete},
		{"deleted count is returned", []string{"10.99.88.7", "10.99.88.9"}, 2, nil, []netlink.InetFamily{unix.AF_INET}, []int{2}, 2, nil},
		{"dual stack flushes both families", []string{"10.99.88.7", "fd00::5"}, 1, nil, []netlink.InetFamily{unix.AF_INET, unix.AF_INET6}, []int{1, 1}, 2, nil},
		{"unparseable IP never reaches netlink", []string{"not-an-ip"}, 0, nil, nil, nil, 0, nil},
		{"empty list never reaches netlink", nil, 0, nil, nil, nil, 0, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub.calls, stub.filters = nil, nil
			stub.deleted, stub.err = tc.stubDeleted, tc.stubErr
			deleted, err := flushCWConntrack(logger, tc.ips)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
			if deleted != tc.wantDeleted {
				t.Errorf("deleted = %d, want %d", deleted, tc.wantDeleted)
			}
			if !slices.Equal(stub.calls, tc.wantCalls) {
				t.Errorf("delete calls = %v, want %v", stub.calls, tc.wantCalls)
			}
			if !slices.Equal(stub.filters, tc.wantFilters) {
				t.Errorf("filters per call = %v, want %v", stub.filters, tc.wantFilters)
			}
		})
	}
}

// A successful flush that matched no entries must stay observable at debug —
// and silent above it — so this fail-closed cleanup is not silent on its normal
// success path. Pinned by level, not text, to avoid a log oracle.
func TestFlushCWConntrackLogsDebugOnEmptyFlush(t *testing.T) {
	stub := &conntrackDeleteStub{} // deleted 0, err nil: the empty-flush success path
	orig := conntrackDeleteFilters
	conntrackDeleteFilters = stub.delete
	t.Cleanup(func() { conntrackDeleteFilters = orig })

	var buf syncBuffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if _, err := flushCWConntrack(logger, []string{"10.99.88.7"}); err != nil {
		t.Fatalf("flushCWConntrack: %v", err)
	}

	var sawDebug bool
	for _, r := range decodeLogRecords(buf.String()) {
		if r.Level == "DEBUG" {
			sawDebug = true
		} else {
			t.Errorf("empty-flush success logged at %s, want DEBUG only", r.Level)
		}
	}
	if !sawDebug {
		t.Error("empty-flush success emitted no debug log — the cleanup is silent on success")
	}
}

// A dual-stack flush must keep the entries a family already deleted even when a
// later family's delete fails, and surface that failure.
func TestFlushCWConntrackKeepsEarlierFamilyCountOnLaterFailure(t *testing.T) {
	errV6 := errors.New("v6 delete failed")
	stub := &conntrackDeleteStub{byFamily: func(f netlink.InetFamily) (uint, error) {
		if f == unix.AF_INET6 {
			return 0, errV6
		}
		return 2, nil
	}}
	orig := conntrackDeleteFilters
	conntrackDeleteFilters = stub.delete
	t.Cleanup(func() { conntrackDeleteFilters = orig })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	deleted, err := flushCWConntrack(logger, []string{"10.99.88.7", "fd00::5"})
	if !errors.Is(err, errV6) {
		t.Errorf("err = %v, want %v", err, errV6)
	}
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2 — the IPv4 count must survive the IPv6 failure", deleted)
	}
}

// The kernel routes loopback via lo; a working RouteGet+LinkByIndex pair must
// answer (true, nil) for an lo allowlist and (false, nil) otherwise.
func TestDefaultLocalRouteCheckLoopbackStrict(t *testing.T) {
	ok, err := defaultLocalRouteCheck("127.0.0.1", []string{"lo"})
	if err != nil {
		t.Fatalf("defaultLocalRouteCheck(127.0.0.1, lo) error: %v", err)
	}
	if !ok {
		t.Error("route to 127.0.0.1 must use lo")
	}
	ok, err = defaultLocalRouteCheck("127.0.0.1", []string{"definitely-not-an-iface"})
	if err != nil {
		t.Fatalf("unexpected error for non-matching allowlist: %v", err)
	}
	if ok {
		t.Error("route to 127.0.0.1 must not match a bogus allowlist")
	}
}

func TestNtohs(t *testing.T) {
	kernel := [2]byte{0x1f, 0x90} // 8080 in network byte order
	n := binary.NativeEndian.Uint16(kernel[:])
	if got := ntohs(n); got != 8080 {
		t.Errorf("ntohs = %d, want 8080", got)
	}
}
