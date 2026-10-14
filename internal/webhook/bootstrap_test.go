package webhook

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

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

// testCAPEM returns a self-signed CA certificate PEM valid until notAfter,
// carrying pod in its CommonName the way the operator's webhook CA does.
func testCAPEM(t *testing.T, pod string, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "c8s-webhook webhook " + pod},
		NotBefore:             notAfter.Add(-2 * time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newBundleClient(t *testing.T, bundle []byte) client.Client {
	t.Helper()
	scheme := k8sruntime.NewScheme()
	if err := admissionv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cfg := &admissionv1.MutatingWebhookConfiguration{
		Name: "c8s-mutating",
		Webhooks: []admissionv1.MutatingWebhook{
			{Name: "pods.c8s.dev", ClientConfig: admissionv1.WebhookClientConfig{CABundle: bundle}},
			{Name: "other.c8s.dev", ClientConfig: admissionv1.WebhookClientConfig{CABundle: bundle}},
		},
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(cfg).Build()
}

// assertBundle fails unless every webhook's caBundle is exactly want, in order.
func assertBundle(t *testing.T, c client.Client, want ...[]byte) string {
	t.Helper()
	var got admissionv1.MutatingWebhookConfiguration
	if err := c.Get(context.Background(), types.NamespacedName{Name: "c8s-mutating"}, &got); err != nil {
		t.Fatal(err)
	}
	wantBundle := bytes.Join(want, nil)
	for _, wh := range got.Webhooks {
		if !bytes.Equal(wh.ClientConfig.CABundle, wantBundle) {
			t.Fatalf("webhook %q caBundle has %d certs, want %d in order:\n%s",
				wh.Name, len(parseBundle(wh.ClientConfig.CABundle)), len(want), wh.ClientConfig.CABundle)
		}
	}
	return got.ResourceVersion
}

// A rolling-out pod adds its CA in front of the old pod's instead of
// replacing it: the old pod is the only Ready endpoint until the new one is.
func TestAppendCABundle(t *testing.T) {
	ctx := context.Background()
	live := time.Now().Add(time.Hour)
	a, b := testCAPEM(t, "pod-a", live), testCAPEM(t, "pod-b", live)

	fc := newBundleClient(t, nil)
	if err := AppendCABundle(ctx, fc, "c8s-mutating", a); err != nil {
		t.Fatalf("AppendCABundle onto an empty bundle: %v", err)
	}
	assertBundle(t, fc, a)

	if err := AppendCABundle(ctx, fc, "c8s-mutating", b); err != nil {
		t.Fatalf("AppendCABundle: %v", err)
	}
	rv := assertBundle(t, fc, b, a)

	// Re-appending a CA already there is a no-op, not a reorder or an Update.
	for _, ca := range [][]byte{b, a} {
		if err := AppendCABundle(ctx, fc, "c8s-mutating", ca); err != nil {
			t.Fatalf("re-append: %v", err)
		}
	}
	if got := assertBundle(t, fc, b, a); got != rv {
		t.Fatalf("re-append updated the configuration (resourceVersion %s -> %s)", rv, got)
	}

	if err := AppendCABundle(ctx, fc, "missing", b); err == nil {
		t.Fatal("AppendCABundle on a missing configuration = nil, want error")
	}
	if err := AppendCABundle(ctx, fc, "c8s-mutating", []byte("not pem")); err == nil {
		t.Fatal("AppendCABundle with a non-certificate CA = nil, want error")
	}
}

// A crash-looping new pod mints a CA per container restart. Each replaces
// that pod's previous entry in place, so the live old pod's CA is never
// pushed out of the bundle however often the new pod restarts.
func TestAppendCABundleCrashLoopKeepsOldPodCA(t *testing.T) {
	ctx := context.Background()
	live := time.Now().Add(time.Hour)
	old := testCAPEM(t, "pod-old", live)

	fc := newBundleClient(t, old)
	var cur []byte
	for range MaxCABundleCerts + 2 {
		cur = testCAPEM(t, "pod-new", live)
		if err := AppendCABundle(ctx, fc, "c8s-mutating", cur); err != nil {
			t.Fatalf("AppendCABundle: %v", err)
		}
		assertBundle(t, fc, cur, old)
	}

	// The old pod's container restarting mid-rollout replaces its entry in
	// place, behind the new pod's, so its prune cannot drop the new pod.
	restarted := testCAPEM(t, "pod-old", live)
	if err := AppendCABundle(ctx, fc, "c8s-mutating", restarted); err != nil {
		t.Fatalf("AppendCABundle: %v", err)
	}
	assertBundle(t, fc, cur, restarted)
	if err := PruneCABundle(ctx, fc, "c8s-mutating", restarted); err != nil {
		t.Fatalf("PruneCABundle: %v", err)
	}
	assertBundle(t, fc, cur, restarted)
}

// Expired and unparseable entries are dropped, and the bundle is capped.
func TestAppendCABundleDropsDeadEntriesAndCaps(t *testing.T) {
	ctx := context.Background()
	live := time.Now().Add(time.Hour)
	expired := testCAPEM(t, "pod-expired", time.Now().Add(-time.Minute))
	garbage := []byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")
	a := testCAPEM(t, "pod-a", live)

	fc := newBundleClient(t, bytes.Join([][]byte{expired, garbage, a}, nil))
	n := testCAPEM(t, "pod-n", live)
	if err := AppendCABundle(ctx, fc, "c8s-mutating", n); err != nil {
		t.Fatalf("AppendCABundle: %v", err)
	}
	assertBundle(t, fc, n, a)

	// Many distinct pods that never prune keep prepending; the oldest pods'
	// entries fall off.
	order := [][]byte{n, a}
	for i := range MaxCABundleCerts {
		next := testCAPEM(t, fmt.Sprintf("pod-%d", i), live)
		if err := AppendCABundle(ctx, fc, "c8s-mutating", next); err != nil {
			t.Fatalf("AppendCABundle: %v", err)
		}
		order = append([][]byte{next}, order...)
	}
	assertBundle(t, fc, order[:MaxCABundleCerts]...)
}

// A write landing between the Get and the Update (helm, an admission
// controller, the pruner) is retried rather than failing the caller.
func TestAppendCABundleRetriesConflict(t *testing.T) {
	scheme := k8sruntime.NewScheme()
	if err := admissionv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cfg := &admissionv1.MutatingWebhookConfiguration{
		Name:     "c8s-mutating",
		Webhooks: []admissionv1.MutatingWebhook{{Name: "pods.c8s.dev"}},
	}
	updates := 0
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cfg).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				updates++
				if updates == 1 {
					return apierrors.NewConflict(admissionv1.Resource("mutatingwebhookconfigurations"), obj.GetName(), errors.New("modified"))
				}
				return c.Update(ctx, obj, opts...)
			},
		}).Build()

	a := testCAPEM(t, "pod-a", time.Now().Add(time.Hour))
	if err := AppendCABundle(context.Background(), fc, "c8s-mutating", a); err != nil {
		t.Fatalf("AppendCABundle after one conflict: %v", err)
	}
	if updates != 2 {
		t.Fatalf("Update calls = %d, want 2 (one conflict, one retry)", updates)
	}
	var got admissionv1.MutatingWebhookConfiguration
	if err := fc.Get(context.Background(), types.NamespacedName{Name: "c8s-mutating"}, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Webhooks[0].ClientConfig.CABundle, a) {
		t.Fatalf("caBundle = %q, want the appended CA", got.Webhooks[0].ClientConfig.CABundle)
	}
}

// Pruning drops the CAs of pods that predate this one, but keeps those in
// front of it: a pod that rolled out after this one must stay trusted.
func TestPruneCABundle(t *testing.T) {
	ctx := context.Background()
	live := time.Now().Add(time.Hour)
	a, b, c := testCAPEM(t, "pod-a", live), testCAPEM(t, "pod-b", live), testCAPEM(t, "pod-c", live)

	fc := newBundleClient(t, bytes.Join([][]byte{c, b, a}, nil))
	if err := PruneCABundle(ctx, fc, "c8s-mutating", b); err != nil {
		t.Fatalf("PruneCABundle: %v", err)
	}
	assertBundle(t, fc, c, b)

	if err := PruneCABundle(ctx, fc, "c8s-mutating", c); err != nil {
		t.Fatalf("PruneCABundle: %v", err)
	}
	rv := assertBundle(t, fc, c)
	if err := PruneCABundle(ctx, fc, "c8s-mutating", c); err != nil {
		t.Fatalf("re-prune: %v", err)
	}
	if got := assertBundle(t, fc, c); got != rv {
		t.Fatalf("re-prune updated the configuration (resourceVersion %s -> %s)", rv, got)
	}

	// A CA missing from the bundle is an error, never a silent overwrite.
	err := PruneCABundle(ctx, fc, "c8s-mutating", a)
	if err == nil || !strings.Contains(err.Error(), "not in the caBundle") {
		t.Fatalf("PruneCABundle with an absent CA = %v, want not-in-bundle error", err)
	}
	assertBundle(t, fc, c)

	if err := PruneCABundle(ctx, fc, "missing", c); err == nil {
		t.Fatal("PruneCABundle on a missing configuration = nil, want error")
	}
}
