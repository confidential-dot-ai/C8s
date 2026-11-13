package verify

import "crypto/tls"

// tlsPendingAttestation is the client config for a peer that PKI says nothing
// about: the caller authenticates what it received — an attested leaf bound to
// PeerCertificates[0], or an operator signature over the payload. No
// ClientSessionCache: a resumed TLS 1.3 handshake carries no CertificateVerify.
func tlsPendingAttestation(serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // unauthenticated peer: see this function's doc
		ServerName:         serverName,
	}
}
