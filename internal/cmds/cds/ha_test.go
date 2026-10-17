package cds

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

func leafFrom(t *testing.T, ca *issuer.CA) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "workload"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshake reports whether a client presenting cert completes a handshake
// with a server using cfg.
func handshake(t *testing.T, cfg *tls.Config, cert tls.Certificate) error {
	t.Helper()
	c, s := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		srv := tls.Server(s, cfg)
		errc <- srv.HandshakeContext(ctx)
		srv.Close()
	}()
	cli := tls.Client(c, &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	_ = cli.HandshakeContext(ctx)
	cli.Close()
	return <-errc
}

// TestFollowMeshCA: after a rotation, a leaf of the old mesh CA no longer
// passes client verification (review #2), and the new one does.
func TestFollowMeshCA(t *testing.T) {
	ca1, ca2 := mustTestCA(t), mustTestCA(t)
	serverCert := leafFrom(t, ca1)
	base := &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.VerifyClientCertIfGiven}
	var current atomic.Pointer[issuer.CA]
	current.Store(ca1)
	cfg := followMeshCA(base, func() (*issuer.CA, error) {
		if ca := current.Load(); ca != nil {
			return ca, nil
		}
		return nil, errors.New("not serving")
	})
	old := leafFrom(t, ca1)
	if err := handshake(t, cfg, old); err != nil {
		t.Fatalf("leaf of the current CA refused: %v", err)
	}
	current.Store(ca2)
	if err := handshake(t, cfg, old); err == nil {
		t.Fatal("leaf of the rotated-away CA accepted")
	}
	if err := handshake(t, cfg, leafFrom(t, ca2)); err != nil {
		t.Fatalf("leaf of the new CA refused: %v", err)
	}
	current.Store(nil)
	if err := handshake(t, cfg, leafFrom(t, ca2)); err == nil {
		t.Fatal("client certificate accepted while the replica cannot issue")
	}
}

func mustTestCA(t *testing.T) *issuer.CA {
	t.Helper()
	ca, err := issuer.NewCAWithCurve("test", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}
