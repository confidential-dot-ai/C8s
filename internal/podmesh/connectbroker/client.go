package connectbroker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Dial asks the broker at socket for a connection to dst and returns it. The
// context bounds the request and the guest's own dial; it carries no fallback,
// so a broker that refuses or is absent fails the connection.
func Dial(ctx context.Context, socket string, dst netip.AddrPort) (net.Conn, error) {
	request, err := encodeRequest(dst)
	if err != nil {
		return nil, err
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("mesh connect broker: %w", err)
	}
	conn := raw.(*net.UnixConn)
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	// The broker refuses a caller it does not serve before reading anything, so
	// the write can fail with EPIPE while the refusal already waits in the socket;
	// the reply decides, and the write error stands only when there is none.
	_, writeErr := conn.Write(request)
	reply := make([]byte, 256)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := conn.ReadMsgUnix(reply, oob)
	if err != nil {
		if writeErr != nil {
			err = writeErr
		}
		return nil, fmt.Errorf("mesh connect broker: %w", err)
	}
	fds := receivedFDs(oob[:oobn])
	defer func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}()
	if string(reply[:n]) != replyOK {
		line, _, _ := strings.Cut(string(reply[:n]), "\n")
		return nil, fmt.Errorf("%w: %s", ErrRefused, line)
	}
	if len(fds) != 1 {
		return nil, fmt.Errorf("%w: reply carried %d sockets", ErrRefused, len(fds))
	}
	file := os.NewFile(uintptr(fds[0]), "mesh-peer")
	fds = nil
	defer file.Close()
	peer, err := net.FileConn(file)
	if err != nil {
		return nil, fmt.Errorf("mesh connect broker: %w", err)
	}
	tcp, ok := peer.(*net.TCPConn)
	if !ok {
		peer.Close()
		return nil, fmt.Errorf("%w: reply carried no TCP socket", ErrRefused)
	}
	return tcp, nil
}

func receivedFDs(oob []byte) []int {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	var fds []int
	for _, message := range messages {
		got, err := unix.ParseUnixRights(&message)
		if err != nil {
			continue
		}
		fds = append(fds, got...)
	}
	return fds
}

// readRequest reads one bounded request line.
func readRequest(reader *bufio.Reader) ([]byte, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("%w: request too long", ErrRefused)
		}
		return nil, err
	}
	return line, nil
}
