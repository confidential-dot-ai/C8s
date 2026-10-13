package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// testWebhookCAPEM mints a CA named the way bootstrapWebhookPKI names the
// webhook CA of pod.
func testWebhookCAPEM(t *testing.T, pod string) []byte {
	t.Helper()
	ca, err := issuer.NewCA("c8s-webhook webhook "+pod, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return certutil.EncodeCertPEM(ca.Cert.Raw)
}

func stubPodName(t *testing.T, name string) {
	t.Helper()
	orig := podName
	podName = func() (string, error) { return name, nil }
	t.Cleanup(func() { podName = orig })
}

func webhookConfigWithBundle(bundle []byte) *admissionv1.MutatingWebhookConfiguration {
	cfg := mutatingWebhookConfig("c8s-mutating")
	for i := range cfg.Webhooks {
		cfg.Webhooks[i].ClientConfig.CABundle = bundle
	}
	return cfg
}

func caBundles(t *testing.T, c client.Client) [][]byte {
	t.Helper()
	var got admissionv1.MutatingWebhookConfiguration
	if err := c.Get(context.Background(), types.NamespacedName{Name: "c8s-mutating"}, &got); err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, wh := range got.Webhooks {
		out = append(out, wh.ClientConfig.CABundle)
	}
	return out
}

// bundleCNs returns the CommonNames of a PEM bundle's certificates, in order.
func bundleCNs(t *testing.T, bundle []byte) []string {
	t.Helper()
	var cns []string
	for {
		var block *pem.Block
		block, bundle = pem.Decode(bundle)
		if block == nil {
			return cns
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		cns = append(cns, cert.Subject.CommonName)
	}
}

// A restarted operator must keep the previous pod's CA in the caBundle: during
// a rollout that pod is still the only Ready endpoint, serving a leaf under it.
// The new pod crash-looping mints a CA per restart; each must replace that
// pod's own entry, never push the old pod's out.
func TestBootstrapWebhookPKIKeepsPreviousCA(t *testing.T) {
	stubWebhookCertDir(t)
	stubPodName(t, "pod-new")
	old := testWebhookCAPEM(t, "pod-old")
	fc := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(webhookConfigWithBundle(old)).Build()
	stubDirectClient(t, fc, nil)

	opts := Options{
		WebhookConfigName:       "c8s-mutating",
		WebhookServiceName:      "c8s-webhook",
		WebhookServiceNamespace: "c8s-system",
		LeaderElection:          true,
	}
	for range 6 {
		if err := bootstrapWebhookPKI(context.Background(), newTestManager(t), opts); err != nil {
			t.Fatalf("bootstrapWebhookPKI: %v", err)
		}
		for _, bundle := range caBundles(t, fc) {
			got := bundleCNs(t, bundle)
			want := []string{"c8s-webhook webhook pod-new", "c8s-webhook webhook pod-old"}
			if len(got) != 2 || got[0] != want[0] || got[1] != want[1] || !bytes.HasSuffix(bundle, old) {
				t.Fatalf("caBundle CNs = %v, want %v with the old pod's CA intact", got, want)
			}
		}
	}
}

// The pruner waits for this pod's webhook to serve, then drops the older CA.
func TestWebhookCABundlePrunerWaitsThenPrunes(t *testing.T) {
	cur, old := testWebhookCAPEM(t, "pod-new"), testWebhookCAPEM(t, "pod-old")
	fc := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(webhookConfigWithBundle(append(append([]byte{}, cur...), old...))).Build()

	var calls atomic.Int32
	started := func(*http.Request) error {
		if calls.Add(1) < 3 {
			if got := caBundles(t, fc)[0]; bytes.Equal(got, cur) {
				t.Error("caBundle pruned before the webhook server started")
			}
			return errors.New("webhook server has not been started yet")
		}
		return nil
	}

	rec := newLogRecorder()
	runPrunerToCompletion(t, webhookCABundlePruner(started, fc, "c8s-mutating", cur, time.Millisecond, rec.logger()))

	for _, bundle := range caBundles(t, fc) {
		if !bytes.Equal(bundle, cur) {
			t.Fatalf("caBundle = %q, want only the current CA", bundle)
		}
	}
	if _, ok := rec.find("pruned superseded webhook CAs from the caBundle"); !ok {
		t.Fatal("no success log entry")
	}
}

// A bundle overwritten since bootstrap (a helm-set webhook.caBundle) lost this
// pod's CA; the pruner puts it back rather than leave the webhook untrusted.
func TestWebhookCABundlePrunerRestoresOwnCA(t *testing.T) {
	cur := testWebhookCAPEM(t, "pod-new")
	fc := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(webhookConfigWithBundle(testWebhookCAPEM(t, "helm-set"))).Build()

	runPrunerToCompletion(t, webhookCABundlePruner(func(*http.Request) error { return nil },
		fc, "c8s-mutating", cur, time.Millisecond, newLogRecorder().logger()))

	for _, bundle := range caBundles(t, fc) {
		if !bytes.Equal(bundle, cur) {
			t.Fatalf("caBundle = %q, want only the current CA restored", bundle)
		}
	}
}

func runPrunerToCompletion(t *testing.T, pruner func(context.Context) error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- pruner(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("pruner = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pruner did not finish")
	}
}

// A failing prune is logged and retried, never returned: an error would stop
// the manager and take the webhook down with it.
func TestWebhookCABundlePrunerRetriesUntilCancelled(t *testing.T) {
	// No MutatingWebhookConfiguration: every attempt fails.
	fc := fake.NewClientBuilder().WithScheme(scheme).Build()
	cur := testWebhookCAPEM(t, "pod-new")

	rec := newLogRecorder()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- webhookCABundlePruner(func(*http.Request) error { return nil },
			fc, "c8s-mutating", cur, time.Millisecond, rec.logger())(ctx)
	}()
	for range 2 {
		if e := waitLogEntry(t, rec); e.err == nil {
			t.Fatalf("entry = %+v, want a prune failure", e)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("pruner = %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pruner did not stop after cancel")
	}
}
