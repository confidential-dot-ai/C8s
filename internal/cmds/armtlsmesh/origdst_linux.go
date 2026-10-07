//go:build linux

package armtlsmesh

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const soOriginalDst = 80

// defaultOrigDstFunc reads the original destination from a connection that was
// redirected by iptables REDIRECT. Tries IPv6 (SOL_IPV6) first, falls back to
// IPv4 (SOL_IP). Uses SO_ORIGINAL_DST (Linux only).
func defaultOrigDstFunc(conn net.Conn) (string, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("origdst: not a TCP connection")
	}

	raw, err := tc.SyscallConn()
	if err != nil {
		return "", fmt.Errorf("origdst: syscall conn: %w", err)
	}

	// Try IPv6 first.
	dst, err := getOrigDst6(raw)
	if err != nil {
		// Fall back to IPv4.
		dst, err = getOrigDst4(raw)
		if err != nil {
			return "", err
		}
	}
	// With conntrack loaded, SO_ORIGINAL_DST answers even for a connection that
	// was never REDIRECTed: the "original" destination is then the listener
	// itself, and forwarding there would make the proxy dial itself in a loop.
	if dst == tc.LocalAddr().String() {
		return "", fmt.Errorf("origdst: %s was dialed directly, not redirected", dst)
	}
	return dst, nil
}

func getOrigDst4(raw syscall.RawConn) (string, error) {
	var addr syscall.RawSockaddrInet4
	var controlErr error
	err := raw.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(addr))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_IP,
			soOriginalDst,
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			controlErr = errno
		}
	})
	if err != nil {
		return "", fmt.Errorf("origdst: control: %w", err)
	}
	if controlErr != nil {
		return "", fmt.Errorf("origdst: getsockopt IPv4: %w", controlErr)
	}

	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := ntohs(addr.Port)
	return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil
}

func getOrigDst6(raw syscall.RawConn) (string, error) {
	var addr syscall.RawSockaddrInet6
	var controlErr error
	err := raw.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(addr))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_IPV6,
			soOriginalDst,
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			controlErr = errno
		}
	})
	if err != nil {
		return "", fmt.Errorf("origdst: control: %w", err)
	}
	if controlErr != nil {
		return "", fmt.Errorf("origdst: getsockopt IPv6: %w", controlErr)
	}

	ip := net.IP(addr.Addr[:])
	port := ntohs(addr.Port)
	return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil
}

// ntohs converts a port uint16 from the kernel's network byte order representation
// to a host integer. The kernel stores the port big-endian; Go reads the uint16 in
// native endianness, so we write it back natively then reinterpret as big-endian.
func ntohs(n uint16) int {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], n)
	return int(binary.BigEndian.Uint16(b[:]))
}
