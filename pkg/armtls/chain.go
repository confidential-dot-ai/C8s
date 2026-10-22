package armtls

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// VerifyChain verifies a peer's certificate chain against roots on the armTLS
// chain path alone and returns the parsed leaf. rawCerts is the peer chain as
// crypto/tls hands it to VerifyPeerCertificate, leaf first. peerPurpose is the
// TLS purpose the peer's role requires: the leaf must carry it, every issuer
// above it must permit it, and every certificate of the chain must be valid at
// now. The leaf's key must be ECDSA P-256 or P-384. There is no
// embedded-evidence fallback, so a caller that then reads a CA-vouched stamp
// (CheckWorkloadPin) reads one the mesh CA signed. A nil roots is an error,
// never the system pool.
func VerifyChain(rawCerts [][]byte, roots *x509.CertPool, peerPurpose x509.ExtKeyUsage, now time.Time) (*x509.Certificate, error) {
	return verifyPeerChain(rawCerts, roots, peerPurpose, now, "armtls: peer chain")
}

// verifyPeerChain is the chain path VerifyChain and the mesh handshake
// callback share. chainContext names the caller in a chain-building failure;
// the parse, key-type and purpose refusals are returned as they are.
func verifyPeerChain(rawCerts [][]byte, roots *x509.CertPool, peerPurpose x509.ExtKeyUsage, now time.Time, chainContext string) (*x509.Certificate, error) {
	if roots == nil {
		return nil, errors.New("armtls: no trust anchors")
	}
	leaf, intermediates, err := parsePeerChain(rawCerts)
	if err != nil {
		return nil, err
	}
	if err := checkPeerKeyType(leaf); err != nil {
		return nil, err
	}
	if err := checkPeerPurpose(leaf, peerPurpose); err != nil {
		return nil, err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{peerPurpose},
		CurrentTime:   now,
	}); err != nil {
		return nil, fmt.Errorf("%s: %w", chainContext, err)
	}
	return leaf, nil
}
