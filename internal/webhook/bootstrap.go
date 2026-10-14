package webhook

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

// DefaultCertDir is controller-runtime's webhook-server default.
const DefaultCertDir = "/tmp/k8s-webhook-server/serving-certs"

// ServingTLSTTL bounds how long a bootstrapped serving cert (the leaf) is valid
// for. The operator re-mints it before expiry in-process (see the cert-rotator
// runnable in the controller runner), so the webhook no longer depends on a pod
// restart to stay valid — an unrotated leaf would otherwise expire and, with a
// fail-closed admission webhook, block all in-scope Pod creation.
const ServingTLSTTL = 30 * 24 * time.Hour

// WebhookCATTL is the validity of the webhook's ephemeral CA. It is long-lived
// so the CA bundle patched onto the MutatingWebhookConfiguration stays stable
// for the operator pod's lifetime while short-lived leaves rotate under it —
// keeping caBundle churn (and the leaf/bundle mismatch it can cause during a
// rollout) out of the steady state. The CA is still re-minted on operator
// restart, which adds it to the bundle (AppendCABundle) and later prunes the
// previous one (PruneCABundle).
const WebhookCATTL = 10 * 365 * 24 * time.Hour

// BootstrapServingCert mints a webhook serving cert from the mesh CA and
// writes it into certDir. Hostnames must include every DNS name the API
// server might use to reach the webhook Service; at minimum the in-cluster
// Service DNS. Passing an empty certDir uses DefaultCertDir.
func BootstrapServingCert(ca *issuer.CA, hostnames []string, certDir string) error {
	if ca == nil {
		return fmt.Errorf("ca is nil")
	}
	if len(hostnames) == 0 {
		return fmt.Errorf("at least one hostname required")
	}
	if certDir == "" {
		certDir = DefaultCertDir
	}

	res, err := ca.Issue(issuer.Request{
		CommonName: hostnames[0],
		DNSNames:   hostnames,
		TTL:        ServingTLSTTL,
	})
	if err != nil {
		return fmt.Errorf("issue webhook serving cert: %w", err)
	}

	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", certDir, err)
	}
	if err := fileutil.WriteAtomic(filepath.Join(certDir, "tls.key"), res.KeyPEM, 0o600); err != nil {
		return fmt.Errorf("write tls.key: %w", err)
	}
	if err := fileutil.WriteAtomic(filepath.Join(certDir, "tls.crt"), res.CertPEM, 0o644); err != nil {
		return fmt.Errorf("write tls.crt: %w", err)
	}
	return nil
}

// MaxCABundleCerts caps how many CAs AppendCABundle leaves in a caBundle.
// There is one entry per pod, so normally at most two (the rolling-out pod's
// and the one it replaces); the cap only bounds growth across many distinct
// pods that never pruned, such as rollouts without leader election.
const MaxCABundleCerts = 16

// AppendCABundle adds caPEM to .webhooks[*].clientConfig.caBundle on the named
// MutatingWebhookConfiguration and keeps the CAs already there, so the API
// server trusts this pod's serving cert without dropping trust in the pod it
// replaces. During a rollout the old pod stays the only Ready endpoint until
// the new one is Ready, so overwriting the bundle would fail every admission
// call in between.
//
// A CA is identified by its subject CommonName, which the caller makes unique
// per pod. An entry with caPEM's CommonName belongs to an earlier container of
// this same pod, which is dead, so it is replaced in place. Otherwise caPEM
// goes in front. The bundle is thus ordered newest pod first, and a crash-
// looping pod keeps one entry instead of pushing a live pod's out. Expired or
// unparseable entries are dropped, and the oldest pods' entries past
// MaxCABundleCerts.
func AppendCABundle(ctx context.Context, c client.Client, configName string, caPEM []byte) error {
	ca, err := singleCert(caPEM)
	if err != nil {
		return err
	}
	now := time.Now()
	return updateCABundles(ctx, c, configName, func(bundle []byte) ([]byte, error) {
		var out []*x509.Certificate
		replaced := false
		for _, cert := range parseBundle(bundle) {
			if now.After(cert.NotAfter) {
				continue
			}
			if cert.Equal(ca) || (ca.Subject.CommonName != "" && cert.Subject.CommonName == ca.Subject.CommonName) {
				if !replaced {
					out = append(out, ca)
					replaced = true
				}
				continue
			}
			out = append(out, cert)
		}
		if !replaced {
			out = append([]*x509.Certificate{ca}, out...)
		}
		if len(out) > MaxCABundleCerts {
			out = out[:MaxCABundleCerts]
		}
		return encodeBundle(out), nil
	})
}

// PruneCABundle drops the CAs behind caPEM from the caBundle that
// AppendCABundle built, once the pods that served under them are gone. Those
// are the pods that first added a CA before this pod did. CAs in front of
// caPEM are kept: a pod that rolled out after this one must stay trusted. It
// fails if caPEM is not in a bundle, rather than silently leaving the webhook
// untrusted by the API server.
func PruneCABundle(ctx context.Context, c client.Client, configName string, caPEM []byte) error {
	ca, err := singleCert(caPEM)
	if err != nil {
		return err
	}
	return updateCABundles(ctx, c, configName, func(bundle []byte) ([]byte, error) {
		certs := parseBundle(bundle)
		for i, cert := range certs {
			if cert.Equal(ca) {
				return encodeBundle(certs[:i+1]), nil
			}
		}
		return nil, fmt.Errorf("webhook CA is not in the caBundle")
	})
}

// updateCABundles rewrites each webhook's caBundle on the named
// MutatingWebhookConfiguration through edit, and skips the Update when
// nothing changed. A conflict re-reads and re-edits: helm, an admission
// controller or this operator's own pruner can write the object between the
// Get and the Update, and failing setupManager on that would restart the pod
// and mint yet another CA.
func updateCABundles(ctx context.Context, c client.Client, configName string, edit func([]byte) ([]byte, error)) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var cfg admissionv1.MutatingWebhookConfiguration
		if err := c.Get(ctx, types.NamespacedName{Name: configName}, &cfg); err != nil {
			return fmt.Errorf("get MutatingWebhookConfiguration %q: %w", configName, err)
		}
		changed := false
		for i := range cfg.Webhooks {
			bundle, err := edit(cfg.Webhooks[i].ClientConfig.CABundle)
			if err != nil {
				return fmt.Errorf("MutatingWebhookConfiguration %q webhook %q: %w", configName, cfg.Webhooks[i].Name, err)
			}
			if bytes.Equal(cfg.Webhooks[i].ClientConfig.CABundle, bundle) {
				continue
			}
			cfg.Webhooks[i].ClientConfig.CABundle = bundle
			changed = true
		}
		if !changed {
			return nil
		}
		if err := c.Update(ctx, &cfg); err != nil {
			return fmt.Errorf("update MutatingWebhookConfiguration %q: %w", configName, err)
		}
		return nil
	})
}

func singleCert(caPEM []byte) (*x509.Certificate, error) {
	certs := parseBundle(caPEM)
	if len(certs) != 1 {
		return nil, fmt.Errorf("webhook CA PEM holds %d certificates, want 1", len(certs))
	}
	return certs[0], nil
}

// parseBundle returns the parseable CERTIFICATE blocks of a PEM bundle in order.
func parseBundle(bundle []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, bundle = pem.Decode(bundle)
		if block == nil {
			return certs
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
}

func encodeBundle(certs []*x509.Certificate) []byte {
	var out []byte
	for _, cert := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return out
}
