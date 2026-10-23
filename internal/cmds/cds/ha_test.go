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
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
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
	ca1, ca2 := testMeshCA(t).Current().CA, testMeshCA(t).Current().CA
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

// A replica reusing its database file (a container restart keeps the pod's
// volume) starts from an empty store, so the Raft log is not applied on top
// of the rows the earlier process left (BUG: divergent ETag and history).
func TestResetHAAllowlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	fresh, err := allowlist.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_, want, err := fresh.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	al, err := pkgallowlist.ParseJSON([]byte(anySeed(map[string]string{"web": digestA})))
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.StartJournal(); err != nil {
		t.Fatal(err)
	}
	if err := fresh.ReplaceAll(al); err != nil {
		t.Fatal(err)
	}
	fresh.Close()
	reused, err := allowlist.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reused.Close()
	if err := resetHAAllowlist(&reused); err != nil {
		t.Fatal(err)
	}
	doc, version, err := reused.LoadAll()
	if err != nil || len(doc.Workloads) != 0 || version != want {
		t.Fatalf("after reset: %d workloads, version %q (want %q): %v", len(doc.Workloads), version, want, err)
	}
	if h, err := reused.History(); err != nil || len(h) != 0 {
		t.Fatalf("history after reset: %d entries, %v", len(h), err)
	}
}

func TestHAConfigFileRefusesFlagTrustRoots(t *testing.T) {
	for _, h := range []haConfig{
		{configFile: "/x", clusterID: "evil"},
		{configFile: "/x", pins: []string{"evil"}},
		{configFile: "/x", operatorKey: "/evil.pem"},
		{configFile: "/x", measurement: "evil"},
		{configFile: "/x", recoveryKeyPEM: []byte("evil")},
	} {
		if err := loadHAConfigFile(&h); err == nil || !strings.Contains(err.Error(), "excludes") {
			t.Errorf("%+v: %v", h, err)
		}
	}
}

func TestYieldIfHA(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "cds-mode")
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if err := yieldIfHA(write("singleton\n")); err != nil {
		t.Fatalf("singleton cluster: %v", err)
	}
	if err := yieldIfHA(write("ha\n")); !errors.Is(err, errYield) {
		t.Fatalf("HA cluster: %v", err)
	}
	for _, bad := range []string{"", "maybe"} {
		if err := yieldIfHA(write(bad)); err == nil || errors.Is(err, errYield) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	if err := yieldIfHA(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
}
