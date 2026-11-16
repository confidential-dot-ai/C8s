package podstart

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Only a socket nobody answers on may be taken over.
func TestRequireAbandonedRefusesLiveSocket(t *testing.T) {
	socket := filepath.Join(socketDir(t), "gate.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: socket})
	if err != nil {
		t.Fatal(err)
	}
	if err := requireAbandoned(socket); err == nil || !strings.Contains(err.Error(), "another Pod start gate is listening") {
		t.Fatalf("live socket was treated as abandoned: %v", err)
	}
	l.SetUnlinkOnClose(false)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := requireAbandoned(socket); err != nil {
		t.Fatalf("abandoned socket was refused: %v", err)
	}
	missing := filepath.Join(filepath.Dir(socket), "missing.sock")
	if err := requireAbandoned(missing); err == nil || !strings.Contains(err.Error(), "probe the existing Pod start socket") {
		t.Fatalf("unprobeable socket was treated as abandoned: %v", err)
	}
}

func TestListenRefusesUnownedAuthorityPaths(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("covered with root ownership by TestListenRefusesUnsafeAuthorityPaths")
	}
	dir := socketDir(t)
	for name, tt := range map[string]struct {
		path string
		want string
	}{
		"relative":       {"gate.sock", "absolute clean path"},
		"unclean":        {dir + "/./gate.sock", "absolute clean path"},
		"missing parent": {filepath.Join(dir, "missing", "gate.sock"), "no such file"},
		"unowned parent": {filepath.Join(dir, "gate.sock"), "must be root-owned"},
		"parent not dir": {filepath.Join(os.Args[0], "gate.sock"), "must be root-owned"},
	} {
		t.Run(name, func(t *testing.T) {
			l, err := Listen(tt.path)
			if err == nil {
				_ = l.Close()
				t.Fatal("unsafe authority path was accepted")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Listen(%q) = %v, want %q", tt.path, err, tt.want)
			}
		})
	}
	if _, err := os.Lstat(filepath.Join(dir, "gate.sock")); !os.IsNotExist(err) {
		t.Fatalf("refusal created a socket: %v", err)
	}
}

func TestServeReportsListenerFailure(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	err = Serve(context.Background(), l, func(context.Context, Request) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "serve Pod start permissions") {
		t.Fatalf("closed listener served: %v", err)
	}
}
