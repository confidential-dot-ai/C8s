//go:build linux

package connectbroker

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// Listen creates the broker socket inside the credential volume held as root,
// connectable by group alone (the mesh endpoint's, in the guest); the owner
// stays the caller, so an unprivileged test can serve its own group. The socket
// is bound through the held directory, not by the volume's path: a kubelet
// volume path is longer than a socket address allows, and the directory the
// caller verified is the one the socket lands in. The volume is a read-only
// mount in the endpoint's container; by kernel semantics connecting to a
// socket needs no write access to its mount.
func Listen(root *os.Root, group int) (net.Listener, error) {
	if old, err := root.Lstat(SocketName); err == nil {
		if old.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("refusing to replace a non-socket at the mesh connect broker path")
		}
		if err := root.Remove(SocketName); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	address := &net.UnixAddr{Name: fmt.Sprintf("/proc/self/fd/%d/%s", dir.Fd(), SocketName), Net: "unix"}
	bound, err := net.ListenUnix("unix", address)
	if err != nil {
		dir.Close()
		return nil, err
	}
	bound.SetUnlinkOnClose(false)
	l := &listener{UnixListener: bound, dir: dir, root: root}
	if err := errors.Join(root.Chown(SocketName, -1, group), root.Chmod(SocketName, 0o660)); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// listener is the broker socket; closing it removes the socket from the volume.
type listener struct {
	*net.UnixListener
	dir  *os.File
	root *os.Root
	once sync.Once
	err  error
}

func (l *listener) Close() error {
	l.once.Do(func() {
		l.err = l.UnixListener.Close()
		if err := l.root.Remove(SocketName); err != nil && !errors.Is(err, os.ErrNotExist) {
			l.err = errors.Join(l.err, err)
		}
		l.err = errors.Join(l.err, l.dir.Close())
	})
	return l.err
}

// ownedBy reports whether the socket's peer process runs as uid.
func ownedBy(conn *net.UnixConn, uid uint32) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	owned := false
	err = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		owned = err == nil && cred != nil && cred.Uid == uid
	})
	return err == nil && owned
}
