// mock-inventory is a fake admission inventory for integration testing: it
// serves the production token route (workloadclaims.ServeTokens) on the baked
// Unix socket, and its sandbox-token signing key over plain HTTP in place of
// the armTLS digests endpoint CDS resolves that key from. Use only in test
// environments.
//
// It asserts one sandbox for every caller. The real inventory binds the caller
// by kernel peer credentials and resolves the PID to a pod; a PID from another
// container's namespace names nothing this mock could resolve.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// sandboxID is shaped like a containerd sandbox ID (64 hex characters), so the
// leaf extension CDS stamps it into carries a production-shaped value.
const sandboxID = "3c8f1d0b7a46e95281cf0a3d6b7e5419f2a8c04d1e6b93758af2c05d9e314b67"

// identityPort is where the signing key is served; mock-cds dials this port on
// the host a token names.
const identityPort = "8500"

// fixedSandbox asserts one sandbox for every caller.
type fixedSandbox struct{ id string }

func (f fixedSandbox) SandboxForPeer(peer workloadclaims.Peer) (workloadclaims.CallerSandbox, error) {
	slog.Info("asserting sandbox for caller", "peer_pid", peer.PID(), "sandbox_id", f.id)
	return workloadclaims.CallerSandbox{SandboxID: f.id}, nil
}

// DigestsForSandbox is never reached: this mock runs the token route only.
func (f fixedSandbox) DigestsForSandbox(string) ([]string, []workloadclaims.SandboxContainer, bool, error) {
	return nil, nil, false, errors.New("mock inventory serves no digests")
}

func main() {
	host, err := containerIP()
	if err != nil {
		slog.Error("no inventory host to sign into tokens", "error", err)
		os.Exit(1)
	}
	signer, err := workloadclaims.NewSandboxTokenSigner(host)
	if err != nil {
		slog.Error("sandbox token signer failed", "error", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(workloadclaims.SidecarSocketDir, 0o755); err != nil {
		slog.Error("failed to create the socket directory", "error", err)
		os.Exit(1)
	}
	socketPath := filepath.Join(workloadclaims.SidecarSocketDir, workloadclaims.SocketName)
	listener, err := workloadclaims.ListenUnix(socketPath, workloadclaims.InventorySocketGID)
	if err != nil {
		slog.Error("failed to bind the inventory socket", "error", err)
		os.Exit(1)
	}

	go func() {
		if err := serveIdentity(identityPort, signer.PublicKeyDER()); err != nil {
			slog.Error("identity endpoint failed", "error", err)
			os.Exit(1)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	slog.Info("mock inventory starting", "socket", socketPath, "identity_port", identityPort,
		"inventory_host", host, "sandbox_id", sandboxID)
	if err := workloadclaims.ServeTokens(ctx, listener, fixedSandbox{id: sandboxID}, signer); err != nil {
		slog.Error("token route failed", "error", err)
		os.Exit(1)
	}
}

// serveIdentity serves the signing key the way the inventory's IdentityPath
// does, minus the armTLS listener: the mock has no evidence to attest it with,
// and mock-cds resolves the key from here before verifying a token.
func serveIdentity(port string, pubDER []byte) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+workloadclaims.IdentityPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(workloadclaims.InventoryIdentity{PublicKey: pubDER})
	})
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	return srv.ListenAndServe()
}

// containerIP is the address a token names as its inventory host: the
// container's first global-unicast IPv4, which on a compose network is the
// address the CDS container reaches it on.
func containerIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("read interface addresses: %w", err)
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ip := ipnet.IP.To4(); ip != nil && ip.IsGlobalUnicast() {
			return ip.String(), nil
		}
	}
	return "", errors.New("no global unicast IPv4 address on any interface")
}
