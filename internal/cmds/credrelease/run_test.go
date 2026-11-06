package credrelease

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/launchbinding"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// freshOperatorPubPEM generates a fresh ECDSA keypair and returns the PKIX
// public-key PEM the initrd would stage.
func freshOperatorPubPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// runnableConfig supplies a measured operator key, on-disk CAs, and a fake
// attestation-api, returning a Config Run can fully start from.
func runnableConfig(t *testing.T) Config {
	t.Helper()
	stubMeasuredOperatorKey(t, freshOperatorPubPEM(t))
	dir := t.TempDir()
	clientCert, clientKey, _ := namedCA(t, dir, "client-ca")
	serverCert, _, _ := namedCA(t, dir, "server-ca")
	return Config{
		ListenAddr:        "127.0.0.1:0",
		AttestationAPIURL: stubAttester(t, teetypes.PlatformTDX).URL(),
		Platform:          "tdx",
		ClientCACert:      clientCert,
		ClientCAKey:       clientKey,
		ServerCACert:      serverCert,
		CertTTL:           defaultCertTTL,
		CertOrg:           defaultCertOrg,
		CertCN:            defaultCertCN,
		LogCertTTL:        defaultLogCertTTL,
		LogCertOrg:        defaultLogCertOrg,
		LogCertCN:         defaultLogCertCN,
	}
}

// TestRunStartupErrors walks Run's fail-closed startup ladder: missing
// platform, unmeasured key, unreadable CA, and a non-ECDSA key.
func TestRunStartupErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  func(t *testing.T) Config
	}{
		{
			name: "platform required",
			cfg: func(t *testing.T) Config {
				return Config{Platform: ""}
			},
		},
		{
			name: "platform value validated before privileged reads",
			cfg: func(t *testing.T) Config {
				return Config{Platform: "foo"}
			},
		},
		{
			name: "no measured operator key",
			cfg: func(t *testing.T) Config {
				stubMeasuredOperatorKeyError(t, launchbinding.ErrNoOperatorKey)
				return Config{Platform: "tdx"}
			},
		},
		{
			name: "cluster CA unreadable",
			cfg: func(t *testing.T) Config {
				stubMeasuredOperatorKey(t, freshOperatorPubPEM(t))
				missing := filepath.Join(t.TempDir(), "missing")
				return Config{Platform: "tdx", ClientCACert: missing, ClientCAKey: missing, ServerCACert: missing}
			},
		},
		{
			name: "measured key is not an ECDSA PKIX PEM",
			cfg: func(t *testing.T) Config {
				cfg := runnableConfig(t)
				// Measured (RTMR matches) but unusable for operatorauth.
				stubMeasuredOperatorKey(t, []byte("measured but not a key"))
				return cfg
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := Run(context.Background(), tc.cfg(t)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// TestRunServesAndShutsDown starts the full service (fake attestation-api,
// temp CAs, measured key), waits for it to accept connections, then cancels
// the context and expects a clean shutdown.
func TestRunServesAndShutsDown(t *testing.T) {
	cfg := runnableConfig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ListenAddr = ln.Addr().String()
	cfg.listener = ln

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		// The listener accepts before Run serves; a handshake needs the server.
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", cfg.ListenAddr,
			&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // reachability only
		if err == nil {
			_ = conn.Close()
			break
		}
		select {
		case err := <-done:
			t.Fatalf("Run exited before serving: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("server never started accepting connections")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run after cancel = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

// TestRunReturnsListenError: with the port already taken, Run surfaces the
// bind error. The listener is opened before the serve goroutine starts (so the
// accept cap can wrap it), so this returns on the synchronous path. Everything
// else in the config is startable, so the only possible failure is the bind.
func TestRunReturnsListenError(t *testing.T) {
	cfg := runnableConfig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cfg.ListenAddr = ln.Addr().String() // already bound

	if err := Run(context.Background(), cfg); err == nil {
		t.Error("Run with an already-bound listen address returned nil, want bind error")
	}
}

// TestAttestFitsServeBudget: /attest must finish inside the write window
// armtls.Serve leaves for attestation, or a slow quote truncates the answer.
func TestAttestFitsServeBudget(t *testing.T) {
	if attestTimeout > armtls.ServeAttestBudget {
		t.Errorf("attestTimeout = %s exceeds armtls.ServeAttestBudget = %s", attestTimeout, armtls.ServeAttestBudget)
	}
}
