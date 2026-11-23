package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/issuer"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/webhook"
)

func TestWebhookCertRotatorReissuesLeaf(t *testing.T) {
	ca, err := issuer.NewCA("test webhook", webhook.WebhookCATTL)
	if err != nil {
		t.Fatal(err)
	}
	certDir := t.TempDir()
	hostnames := []string{"c8s-webhook.c8s-system.svc"}

	// Initial leaf.
	if err := webhook.BootstrapServingCert(ca, hostnames, certDir); err != nil {
		t.Fatal(err)
	}
	crtPath := filepath.Join(certDir, "tls.crt")
	first, err := os.ReadFile(crtPath)
	if err != nil {
		t.Fatal(err)
	}

	// Tiny leaf TTL ⇒ interval = TTL*2/3 ≈ 40ms, so rotation happens quickly.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = webhookCertRotator(ca, hostnames, certDir, 60*time.Millisecond, logr.Discard())(ctx)
		close(done)
	}()

	// Wait until the cert file is re-minted (distinct bytes).
	deadline := time.After(5 * time.Second)
	var rotated []byte
	for {
		cur, err := os.ReadFile(crtPath)
		if err == nil && !bytes.Equal(cur, first) {
			rotated = cur
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for the webhook serving cert to rotate")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("rotator did not stop after cancel")
	}

	// The rotated leaf must still chain to the same CA (the bundle is unchanged).
	block, _ := pem.Decode(rotated)
	if block == nil {
		t.Fatal("rotated tls.crt is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: hostnames[0]}); err != nil {
		t.Fatalf("rotated leaf does not verify against the stable CA: %v", err)
	}
}
