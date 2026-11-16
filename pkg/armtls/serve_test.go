package armtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// freeAddr reserves a loopback port and releases it for Serve to bind.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestServeBindsServingKeyToConnection: a handler under Serve sees the key
// of the certificate its own connection was served with.
func TestServeBindsServingKeyToConnection(t *testing.T) {
	addr := freeAddr(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := ServingKey(r.Context())
		if key == nil {
			http.Error(w, "no serving key", http.StatusInternalServerError)
			return
		}
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(der)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, addr, handler, testServerConfig())
	}()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // the test compares the served key, not the chain
		},
	}
	defer client.CloseIdleConnections()
	var resp *http.Response
	deadline := time.Now().Add(10 * time.Second)
	for {
		var err error
		if resp, err = client.Get("https://" + addr + "/"); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("Serve exited before serving: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never answered: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %s: %s", resp.Status, body)
	}
	want, err := x509.MarshalPKIXPublicKey(resp.TLS.PeerCertificates[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, want) {
		t.Error("ServingKey differs from the key of the certificate the client saw")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve after cancel = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after context cancel")
	}
}

// TestServeFailsBeforeBinding: a certificate that cannot be provisioned
// fails Serve before the address is bound.
// ServeListener serves the listener it is given: the port a test bound is
// the port the server answers on, and nothing else is bound.
func TestServeListenerServesTheGivenListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ServeListener(ctx, ln, "127.0.0.1:1", http.NotFoundHandler(), testServerConfig())
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", ln.Addr().String(),
			&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // reachability only
		if err == nil {
			_ = conn.Close()
			break
		}
		select {
		case err := <-done:
			t.Fatalf("ServeListener exited before serving: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("server never accepted on the given listener")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("ServeListener after cancel = %v, want nil", err)
	}
}

func TestServeFailsBeforeBinding(t *testing.T) {
	addr := freeAddr(t)
	cfg := testServerConfig()
	cfg.AttestFunc = func(context.Context, string) (string, error) { return "", errors.New("attestation down") }
	if err := Serve(context.Background(), addr, nil, cfg); err == nil {
		t.Fatal("Serve with a failing attester returned nil")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("address still bound after a failed warm-up: %v", err)
	}
	_ = ln.Close()
}

// TestServerBoundsConnectionResources: Serve's callers bind every interface,
// so each bound costs an unauthenticated peer something it would otherwise
// get free. Asserted because a regression is silent.
func TestServerBoundsConnectionResources(t *testing.T) {
	if maxServeConns <= 0 {
		t.Errorf("maxServeConns = %d, want a positive accept cap", maxServeConns)
	}
	srv := newServer(":0", nil)
	if srv.WriteTimeout <= srv.ReadTimeout+ServeAttestBudget {
		t.Errorf("WriteTimeout = %s leaves no response time after body read and attestation", srv.WriteTimeout)
	}
	if srv.MaxHeaderBytes <= 0 || srv.MaxHeaderBytes > 64<<10 {
		t.Errorf("MaxHeaderBytes = %d, want a bound well under Go's 1MiB default", srv.MaxHeaderBytes)
	}
	for name, got := range map[string]time.Duration{
		"ReadHeaderTimeout": srv.ReadHeaderTimeout,
		"ReadTimeout":       srv.ReadTimeout,
		"WriteTimeout":      srv.WriteTimeout,
		"IdleTimeout":       srv.IdleTimeout,
	} {
		if got <= 0 {
			t.Errorf("%s is unset; a parked connection holds a goroutine open", name)
		}
	}
}

func TestServingKeyOutsideServe(t *testing.T) {
	if key := ServingKey(context.Background()); key != nil {
		t.Errorf("ServingKey outside Serve = %v, want nil", key)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := ServingKey(WithServingKey(context.Background(), &priv.PublicKey)); got != &priv.PublicKey {
		t.Errorf("ServingKey(WithServingKey(k)) = %v, want k", got)
	}
}
