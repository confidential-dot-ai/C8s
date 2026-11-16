// Package pendingattestation configures a TLS client for a peer PKI says
// nothing about: before trusting it the caller must bind what it received to an
// attested leaf or an operator signature, and no handshake may be resumed (a
// resumed TLS 1.3 handshake carries no CertificateVerify).
package pendingattestation

import "crypto/tls"

// TLSConfig returns a fresh config for one such peer; an empty serverName
// leaves SNI to crypto/tls.
func TLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // unauthenticated peer: see this package's doc
		ServerName:         serverName,
	}
}
