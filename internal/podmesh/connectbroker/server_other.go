//go:build !linux

package connectbroker

import (
	"errors"
	"net"
	"os"
)

// Listen requires Linux: the broker serves guest pods, and it authenticates its
// caller with SO_PEERCRED.
func Listen(*os.Root, int) (net.Listener, error) {
	return nil, errors.New("mesh connect broker requires Linux")
}

// ownedBy reports false: nothing is served without peer credentials.
func ownedBy(*net.UnixConn, uint32) bool { return false }
