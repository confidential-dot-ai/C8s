package webhook

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

func TestBootstrapServingCertWritesLeafToCertDir(t *testing.T) {
	ca, err := issuer.NewCA("test webhook", WebhookCATTL)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	hostnames := []string{"c8s-webhook.c8s-system.svc", "c8s-webhook.c8s-system.svc.cluster.local"}

	if err := BootstrapServingCert(ca, hostnames, dir); err != nil {
		t.Fatalf("BootstrapServingCert: %v", err)
	}

	crtPEM, err := os.ReadFile(filepath.Join(dir, "tls.crt"))
	if err != nil {
		t.Fatalf("tls.crt not written into the given certDir: %v", err)
	}
	block, _ := pem.Decode(crtPEM)
	if block == nil {
		t.Fatal("tls.crt is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(leaf.DNSNames, hostnames) {
		t.Fatalf("leaf DNSNames = %v, want %v", leaf.DNSNames, hostnames)
	}
	if leaf.Subject.CommonName != hostnames[0] {
		t.Fatalf("leaf CN = %q, want the first hostname %q", leaf.Subject.CommonName, hostnames[0])
	}

	// The leaf validity is the 30-day serving TTL the in-process rotator
	// re-mints under.
	wantTTL, err := time.ParseDuration("720h")
	if err != nil {
		t.Fatal(err)
	}
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got != wantTTL {
		t.Fatalf("leaf validity = %v, want %v", got, wantTTL)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: hostnames[0]}); err != nil {
		t.Fatalf("leaf does not verify against the issuing CA: %v", err)
	}

	keyPEM, err := os.ReadFile(filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatalf("tls.key not written: %v", err)
	}
	if keyBlock, _ := pem.Decode(keyPEM); keyBlock == nil {
		t.Fatal("tls.key is not PEM")
	}
}

func TestBootstrapServingCertRejectsBadInput(t *testing.T) {
	ca, err := issuer.NewCA("test webhook", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		ca        *issuer.CA
		hostnames []string
		wantErr   string
	}{
		{"nil ca", nil, []string{"a.b.svc"}, "ca is nil"},
		{"no hostnames", ca, nil, "at least one hostname"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := BootstrapServingCert(tc.ca, tc.hostnames, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestPatchCABundle(t *testing.T) {
	scheme := k8sruntime.NewScheme()
	if err := admissionv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cfg := &admissionv1.MutatingWebhookConfiguration{
		Name: "c8s-mutating",
		Webhooks: []admissionv1.MutatingWebhook{
			{Name: "pods.c8s.dev"},
			{Name: "other.c8s.dev"},
		},
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cfg).Build()
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")

	if err := PatchCABundle(context.Background(), fc, "c8s-mutating", caPEM); err != nil {
		t.Fatalf("PatchCABundle: %v", err)
	}
	var got admissionv1.MutatingWebhookConfiguration
	if err := fc.Get(context.Background(), types.NamespacedName{Name: "c8s-mutating"}, &got); err != nil {
		t.Fatal(err)
	}
	for _, wh := range got.Webhooks {
		if !bytes.Equal(wh.ClientConfig.CABundle, caPEM) {
			t.Fatalf("webhook %q caBundle = %q, want the patched CA PEM", wh.Name, wh.ClientConfig.CABundle)
		}
	}

	// Idempotent: a second patch with the same bundle is a no-op.
	if err := PatchCABundle(context.Background(), fc, "c8s-mutating", caPEM); err != nil {
		t.Fatalf("re-patch: %v", err)
	}

	if err := PatchCABundle(context.Background(), fc, "missing", caPEM); err == nil {
		t.Fatal("PatchCABundle on a missing configuration = nil, want error")
	}
}

func TestPatchValidatingCABundle(t *testing.T) {
	scheme := k8sruntime.NewScheme()
	if err := admissionv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cfg := &admissionv1.ValidatingWebhookConfiguration{
		Name: "c8s-validating",
		Webhooks: []admissionv1.ValidatingWebhook{
			{Name: "pods-validate.c8s.dev"},
		},
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cfg).Build()
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")

	if err := PatchValidatingCABundle(context.Background(), fc, "c8s-validating", caPEM); err != nil {
		t.Fatalf("PatchValidatingCABundle: %v", err)
	}
	var got admissionv1.ValidatingWebhookConfiguration
	if err := fc.Get(context.Background(), types.NamespacedName{Name: "c8s-validating"}, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Webhooks[0].ClientConfig.CABundle, caPEM) {
		t.Fatalf("caBundle = %q, want the patched CA PEM", got.Webhooks[0].ClientConfig.CABundle)
	}

	// Idempotent, and a missing configuration is an error: the API server must
	// never be left trusting a stale bundle silently.
	if err := PatchValidatingCABundle(context.Background(), fc, "c8s-validating", caPEM); err != nil {
		t.Fatalf("re-patch: %v", err)
	}
	if err := PatchValidatingCABundle(context.Background(), fc, "missing", caPEM); err == nil {
		t.Fatal("PatchValidatingCABundle on a missing configuration = nil, want error")
	}
}
