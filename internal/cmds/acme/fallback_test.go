package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFiles(t *testing.T) {
	dir := t.TempDir()
	domains := filepath.Join(dir, "hostnames")
	email := filepath.Join(dir, "acme-email")
	url := filepath.Join(dir, "acme-directory-url")
	writeFile(t, domains, "a.example.com\nb.example.com\n")
	writeFile(t, email, "ops@example.com\n")
	writeFile(t, url, "")

	cfg := validTestConfig()
	cfg.domains = nil
	cfg.domainsFile, cfg.emailFile, cfg.directoryURLFile = domains, email, url
	fallback, err := loadFiles(&cfg)
	if err != nil || fallback {
		t.Fatalf("loadFiles = %v, %v; want ACME mode", fallback, err)
	}
	if !slices.Equal(cfg.domains, []string{"a.example.com", "b.example.com"}) || cfg.email != "ops@example.com" || cfg.directoryURL != letsEncryptDirectoryURL {
		t.Fatalf("loaded %+v", cfg)
	}

	cfg = validTestConfig()
	cfg.domainsFile = domains
	if _, err := loadFiles(&cfg); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("--domains with --domains-file: %v", err)
	}

	writeFile(t, domains, "")
	cfg = validTestConfig()
	cfg.domains = nil
	cfg.domainsFile = domains
	if _, err := loadFiles(&cfg); err == nil {
		t.Fatal("empty domains file without --fallback-cert-dir was accepted")
	}
	cfg.fallbackCertDir = dir
	if fallback, err := loadFiles(&cfg); err != nil || !fallback {
		t.Fatalf("empty domains file = %v, %v; want fallback mode", fallback, err)
	}
}

func writePair(t *testing.T, dir, cn string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, keyFile), string(keyPEM))
	writeFile(t, filepath.Join(dir, certFile), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
}

func TestCopyFallbackPair(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	if _, err := copyFallbackPair(src, dst); err == nil {
		t.Fatal("missing source pair was accepted")
	}
	writePair(t, src, "mesh-1")
	if changed, err := copyFallbackPair(src, dst); err != nil || !changed {
		t.Fatalf("first copy = %v, %v", changed, err)
	}
	if changed, err := copyFallbackPair(src, dst); err != nil || changed {
		t.Fatalf("unchanged copy = %v, %v", changed, err)
	}
	info, err := os.Stat(filepath.Join(dst, keyFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode: %v %v", info, err)
	}
	// A torn pair (cert renewed, key not yet) is not copied.
	other := t.TempDir()
	writePair(t, other, "mesh-2")
	cert, _ := os.ReadFile(filepath.Join(other, certFile))
	writeFile(t, filepath.Join(src, certFile), string(cert))
	if _, err := copyFallbackPair(src, dst); err == nil {
		t.Fatal("torn pair was copied")
	}
	writePair(t, src, "mesh-3")
	if changed, err := copyFallbackPair(src, dst); err != nil || !changed {
		t.Fatalf("renewed copy = %v, %v", changed, err)
	}
}

func TestRunFallbackReloadsOnChange(t *testing.T) {
	oldInterval, oldRetry := fallbackInterval, fallbackRetry
	fallbackInterval, fallbackRetry = 10*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { fallbackInterval, fallbackRetry = oldInterval, oldRetry })

	for _, restart := range []bool{false, true} {
		name := "fresh start"
		if restart {
			name = "sidecar restart"
		}
		t.Run(name, func(t *testing.T) {
			src, dst := t.TempDir(), t.TempDir()
			if restart {
				// emptyDir and nginx survive a sidecar restart. A renewal may
				// already be waiting when the replacement sidecar starts.
				writePair(t, src, "already-served")
				if _, err := copyFallbackPair(src, dst); err != nil {
					t.Fatal(err)
				}
			}
			writePair(t, src, "mesh-1")
			var reloads atomic.Int32
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			cfg := config{certDir: dst, fallbackCertDir: src}
			reload := func() { reloads.Add(1) }
			go func() { done <- runFallback(ctx, cfg, slog.Default(), reload) }()
			t.Cleanup(func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			})

			waitFor(t, func() bool { return reloads.Load() >= 1 })
			writePair(t, src, "mesh-2")
			waitFor(t, func() bool { return reloads.Load() >= 2 })
		})
	}
}

func TestRunFallbackUnchangedPairDoesNotReload(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	writePair(t, src, "already-served")
	if _, err := copyFallbackPair(src, dst); err != nil {
		t.Fatal(err)
	}
	// A cancelled context lets the loop check the existing pair once, then exit.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := config{certDir: dst, fallbackCertDir: src}
	if err := runFallback(ctx, cfg, slog.Default(), func() { t.Error("unchanged pair reloaded nginx") }); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatal("condition not reached")
}
