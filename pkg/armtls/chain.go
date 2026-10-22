package armtls

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// VerifyChain verifies a peer's certificate chain against roots on the armTLS
// chain path alone and returns the parsed leaf. rawCerts is the peer chain as
// crypto/tls hands it to VerifyPeerCertificate, leaf first. There is no
// embedded-evidence fallback, so a caller that then reads a CA-vouched stamp
// (CheckWorkloadPin) reads one the mesh CA signed. A nil roots is an error,
// never the system pool.
func VerifyChain(rawCerts [][]byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if len(rawCerts) == 0 {
		return nil, errors.New("armtls: no peer certificate")
	}
	if roots == nil {
		return nil, errors.New("armtls: no trust anchors")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, fmt.Errorf("armtls: parse peer cert: %w", err)
	}
	if err := verifyChain(leaf, rawCerts[1:], roots, now); err != nil {
		return nil, fmt.Errorf("armtls: peer chain: %w", err)
	}
	return leaf, nil
}

// verifyChain requires a chain to roots under any extended key usage, judging
// every certificate in it at now+certutil.LeafValiditySkew, then the leaf
// alone at now (certutil.CheckValidity).
func verifyChain(leaf *x509.Certificate, rawIntermediates [][]byte, roots *x509.CertPool, now time.Time) error {
	intermediates := x509.NewCertPool()
	for _, raw := range rawIntermediates {
		if ic, err := x509.ParseCertificate(raw); err == nil {
			intermediates.AddCert(ic)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   now.Add(certutil.LeafValiditySkew),
	}); err != nil {
		return err
	}
	return certutil.CheckValidity(leaf, now)
}
