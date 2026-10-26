//go:build !linux

package podstart

import (
	"net"
	"os"
)

func ownedByRoot(os.FileInfo) bool { return false }
func rootPeer(net.Conn) bool       { return false }
