// Package connectbroker opens a pod CVM's mesh peer connections from the guest.
//
// The guest forwards nothing from the pod network namespace to an advertised
// peer tuple (ruleset.GuestPolicy). The mesh endpoint instead asks the guest
// for each peer connection over a unix socket in its credential volume; the
// guest connects from its own network namespace, to a signed peer tuple only,
// and hands the connected socket back. Nothing the pod runs can reach a peer
// tuple any other way, so a pod whose capture rules were removed fails to
// reach its peer instead of reaching it in the clear (networking EG5).
package connectbroker

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	// SocketName is the broker socket's name inside the credential volume.
	SocketName = "connect.sock"
	// protocol prefixes every request; the version changes with the wire format.
	protocol = "c8s-mesh-connect/1 "
	// maxRequest bounds one request line: the prefix, an IPv4 tuple and the newline.
	maxRequest = 64
	// replyOK carries one connected socket; every other reply carries none.
	replyOK = "ok\n"
)

// ErrRefused is the broker's answer to a tuple the pod's launch did not
// advertise, or to a caller that is not the mesh endpoint.
var ErrRefused = errors.New("mesh connect refused")

func encodeRequest(dst netip.AddrPort) ([]byte, error) {
	if !dst.IsValid() || !dst.Addr().Is4() || dst.Port() == 0 {
		return nil, fmt.Errorf("%w: peer %s is not an IPv4 tuple", ErrRefused, dst)
	}
	return []byte(protocol + dst.String() + "\n"), nil
}

func decodeRequest(line []byte) (netip.AddrPort, error) {
	text, ok := strings.CutPrefix(string(line), protocol)
	if !ok || !strings.HasSuffix(text, "\n") {
		return netip.AddrPort{}, fmt.Errorf("%w: malformed request", ErrRefused)
	}
	dst, err := netip.ParseAddrPort(strings.TrimSuffix(text, "\n"))
	if err != nil || !dst.Addr().Is4() || dst.Addr().Is4In6() || dst.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("%w: malformed peer tuple", ErrRefused)
	}
	return dst, nil
}
