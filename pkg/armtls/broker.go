package armtls

import (
	"crypto/x509"
	"encoding/asn1"
	"slices"
)

// OIDCDSBroker is the extended key usage of a Trust Authority broker certificate: a leaf
// the mesh CA issues to one Trust Authority replica's broker key, which signs secret
// release statements to an external key management service
// (docs/pod-secrets.md). It is the certificate's only extended key usage, so
// no TLS stack accepts the certificate for server or client authentication.
var OIDCDSBroker = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 10}

// IsCDSBroker reports whether cert carries the Trust Authority broker key usage. It says
// nothing about who signed cert: check the chain first.
func IsCDSBroker(cert *x509.Certificate) bool {
	return slices.ContainsFunc(cert.UnknownExtKeyUsage, OIDCDSBroker.Equal)
}
