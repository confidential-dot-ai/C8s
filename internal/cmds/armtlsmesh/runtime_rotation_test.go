//go:build linux

package armtlsmesh

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

type rotationTestEnvironment struct{ proxy *Proxy }

func (e rotationTestEnvironment) configure(*meshRuntime) *Proxy {
	return e.proxy
}

func (rotationTestEnvironment) start(context.Context, *meshRuntime) {
}

func TestMeshRuntimeRotationFailuresIdentifyCertificateRole(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, err := newMeshRuntime(&armtls.ServerConfig{
			Platform: "sev-snp", ClientPolicy: &armtls.VerifyPolicy{},
			AttestFunc: func(context.Context, string) (string, error) {
				return "", errors.New("attestation unavailable")
			},
		}, testLogger(), 0)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go r.serverCertMgr.RunRotation(ctx)
		go r.clientCertMgr.RunRotation(ctx)
		synctest.Wait()
		for _, role := range []string{"server", "client"} {
			if got := registryValue(t, r.metrics, "armtls_mesh_cert_rotation_failures_total", map[string]string{"role": role}); got != 1 {
				t.Errorf("%s rotation failures = %v, want 1", role, got)
			}
		}
		if r.serverCertMgr.CertReady() || r.clientCertMgr.CertReady() {
			t.Error("failed initial provisioning must leave both certificates unready")
		}
		cancel()
		synctest.Wait()
	})
}

func TestMeshRuntimeRotatesBothCertificatesWithoutBidirectionalTraffic(t *testing.T) {
	for _, traffic := range []string{"idle", "inbound only", "outbound only"} {
		t.Run(traffic, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const ttl = 4 * time.Minute
				r, err := newMeshRuntime(&armtls.ServerConfig{
					Platform: "sev-snp", CertTTL: ttl, RotationTimeout: time.Second,
					AttestFunc: func(context.Context, string) (string, error) {
						return "test evidence", nil
					},
					ClientPolicy: &armtls.VerifyPolicy{},
				}, testLogger(), 0)
				if err != nil {
					t.Fatal(err)
				}
				r.health = newHealthServer(r.metrics, r.serverCertMgr, r.clientCertMgr, 10, time.Second, time.Second)
				r.healthListener = newRotationIdleListener()
				env := rotationTestEnvironment{proxy: &Proxy{
					inboundLn: newRotationIdleListener(), outboundLn: newRotationIdleListener(), drainTimeout: time.Second,
				}}
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() {
					done <- r.run(ctx, env)
				}()
				defer func() {
					cancel()
					select {
					case err := <-done:
						if err != nil {
							t.Errorf("runtime shutdown: %v", err)
						}
					case <-time.After(5 * time.Second):
						t.Error("runtime did not stop")
					}
				}()
				synctest.Wait()
				if rotationReadiness(r) != http.StatusOK {
					t.Fatal("runtime did not become ready")
				}
				initialServerExpiry := r.serverCertMgr.CertExpiry()
				initialClientExpiry := r.clientCertMgr.CertExpiry()
				// This test exercises certificate rotation independently of attestation verification.
				serverTLS, clientTLS := r.serverTLS.Clone(), r.clientTLS.Clone()
				serverTLS.VerifyPeerCertificate, clientTLS.VerifyPeerCertificate = nil, nil
				peerTLS := &tls.Config{
					Certificates: []tls.Certificate{junkClientCert(t)},
					ClientAuth:   tls.RequireAnyClientCert, InsecureSkipVerify: true,
				}
				var exchange func()
				switch traffic {
				case "inbound only":
					exchange = func() {
						rotationHandshake(t, serverTLS, peerTLS)
					}
				case "outbound only":
					exchange = func() {
						rotationHandshake(t, peerTLS, clientTLS)
					}
				}
				deadline := time.Now().Add(ttl + time.Minute)
				for time.Now().Before(deadline) {
					if status := rotationReadiness(r); status != http.StatusOK {
						t.Fatalf("readiness became %d during %s traffic", status, traffic)
					}
					if exchange != nil {
						exchange()
					}
					time.Sleep(15 * time.Second)
					synctest.Wait()
				}
				if status := rotationReadiness(r); status != http.StatusOK {
					t.Fatalf("readiness after initial certificate lifetime = %d", status)
				}
				if !r.serverCertMgr.CertExpiry().After(initialServerExpiry) {
					t.Error("server certificate was not renewed")
				}
				if !r.clientCertMgr.CertExpiry().After(initialClientExpiry) {
					t.Error("client certificate was not renewed")
				}
			})
		})
	}
}

type rotationIdleListener struct {
	closed chan struct{}
	once   sync.Once
}

func newRotationIdleListener() *rotationIdleListener {
	return &rotationIdleListener{closed: make(chan struct{})}
}

func (l *rotationIdleListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *rotationIdleListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
	})
	return nil
}

func (*rotationIdleListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

func rotationReadiness(r *meshRuntime) int {
	response := httptest.NewRecorder()
	r.health.mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ready", nil))
	return response.Code
}

func rotationHandshake(t *testing.T, server, client *tls.Config) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- tls.Server(serverConn, server).HandshakeContext(ctx)
	}()
	clientErr := tls.Client(clientConn, client).HandshakeContext(ctx)
	serverErr := <-serverDone
	if clientErr != nil || serverErr != nil {
		t.Fatalf("TLS handshake: client = %v, server = %v", clientErr, serverErr)
	}
}
