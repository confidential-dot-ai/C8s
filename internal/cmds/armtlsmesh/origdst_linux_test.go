//go:build linux

package armtlsmesh

import (
	"encoding/binary"
	"net"
	"testing"
)

// The kernel's port is big-endian whatever the host's byte order is.
func TestNtohs(t *testing.T) {
	tests := []struct {
		kernel [2]byte
		want   int
	}{
		{[2]byte{0x00, 0x50}, 80},
		{[2]byte{0x1f, 0x90}, 8080},
		{[2]byte{0x3a, 0x99}, 15001},
		{[2]byte{0xff, 0xff}, 65535},
	}
	for _, tc := range tests {
		if got := ntohs(binary.NativeEndian.Uint16(tc.kernel[:])); got != tc.want {
			t.Errorf("ntohs(%v) = %d, want %d", tc.kernel, got, tc.want)
		}
	}
}

// A connection whose original destination the kernel does not hold names none:
// with conntrack loaded SO_ORIGINAL_DST answers for a connection that was
// never redirected, and forwarding to the answer would make the endpoint dial
// its own listener. The endpoint reads the accepted side of a connection, which
// is the side the kernel's answer names.
func TestDefaultOrigDstFuncRefusesAConnectionItCannotTrace(t *testing.T) {
	unwrapped, _ := net.Pipe()
	defer unwrapped.Close()
	_, direct := tcpPair(t)
	closed, _ := tcpPair(t)
	closed.Close()

	for name, conn := range map[string]net.Conn{
		"not a TCP connection":   unwrapped,
		"dialled directly":       direct,
		"closed before the read": closed,
	} {
		t.Run(name, func(t *testing.T) {
			dst, err := defaultOrigDstFunc(conn)
			if err == nil {
				t.Fatalf("the original destination was reported as %q", dst)
			}
			if dst != "" {
				t.Errorf("refused with a destination: %q", dst)
			}
		})
	}
}
