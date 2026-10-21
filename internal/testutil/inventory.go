package testutil

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// stubResolver is an inventory that vouches for one sandbox. The token route
// binds its caller by peer credentials, which a unix socket supplies; nothing
// here needs to disambiguate.
type stubResolver struct{}

func (stubResolver) SandboxForPeer(workloadclaims.Peer) (workloadclaims.CallerSandbox, error) {
	return workloadclaims.CallerSandbox{
		SandboxID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}, nil
}

func (stubResolver) DigestsForSandbox(string) ([]string, []workloadclaims.SandboxContainer, bool, error) {
	return nil, nil, false, nil
}

// StartInventory serves the sandbox inventory's real token route on a unix
// socket for the test's duration and returns the socket's path.
func StartInventory(t *testing.T) string {
	t.Helper()
	signer, err := workloadclaims.NewSandboxTokenSigner("10.0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "wc.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = workloadclaims.ServeTokens(ctx, l, stubResolver{}, signer) }()
	t.Cleanup(func() { cancel(); l.Close() })
	return sock
}
