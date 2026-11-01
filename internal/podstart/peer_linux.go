package podstart

import (
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func ownedByRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

func rootPeer(c net.Conn) bool {
	conn, ok := c.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	root := false
	err = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		root = err == nil && cred != nil && cred.Uid == 0
	})
	return err == nil && root
}
