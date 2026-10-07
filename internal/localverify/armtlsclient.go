package localverify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// NewARMTLSHTTPClient returns an http.Client whose TLS handshake verifies the
// peer's armTLS attestation extension against measurements (empty accepts any
// attested peer — callers warn). The in-process counterpart of
// armtls.NewVerifyingHTTPClient, sharing its transport (armtls.HTTPClient).
// verify is [Verify] in production, a stub in tests; verifyTimeout bounds
// each handshake's verification, KDS fetch included.
func NewARMTLSHTTPClient(measurements [][]byte, verify VerifyFunc, verifyTimeout time.Duration) *http.Client {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // attestation, not PKI, authenticates the peer — verified below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("localverify: no peer certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("localverify: parse peer cert: %w", err)
			}
			// Authenticate the certificate body before touching the evidence:
			// validity within the shared skew window (the nonce-free evidence
			// has no other freshness bound) and, for a self-issued leaf, its
			// own signature under its attested key. Cheap, and it keeps an
			// expired cert from costing an evidence verification.
			//
			// Peers on this path are self-signed armTLS leaves (this client
			// verifies no chain and holds no CA), so the classification must
			// come back BodySelfSigned. Assert it instead of discarding it: a
			// CA-vouched leaf here would have had NOTHING authenticate its
			// body — no signature is checked when issuer != subject — so its
			// window, subject and stamps would be whatever the producer of
			// the bytes chose, under a genuine attestation extension.
			body, err := certutil.AuthenticateLeafBody(cert, time.Now())
			if err != nil {
				return fmt.Errorf("localverify: peer certificate: %w", err)
			}
			if body != certutil.BodySelfSigned {
				return fmt.Errorf("localverify: peer certificate is not self-signed (issuer != subject) and this client verifies no issuing chain, so nothing authenticates its body")
			}
			platform, evidence, erd, err := CertEnvelope(cert)
			if err != nil {
				return fmt.Errorf("localverify: peer attestation: %w", err)
			}
			// VerifyPeerCertificate carries no context; bound explicitly.
			ctx := context.Background()
			if verifyTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, verifyTimeout)
				defer cancel()
			}
			if _, err := verify(ctx, platform, evidence, Params{
				Measurements:       measurements,
				ExpectedReportData: erd,
			}); err != nil {
				return fmt.Errorf("localverify: peer attestation failed: %w", err)
			}
			return nil
		},
	}
	return armtls.HTTPClient(tlsCfg)
}
