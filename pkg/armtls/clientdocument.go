// Client document digest: SHA-256 of the opaque document a client attached to
// a Pod CVM, stamped by CDS as an X.509 extension in the CA-signed area. The
// guest reports it in its Pod claims, which the issuance quote binds, so the
// stamp says the leaf's pod was assigned exactly that document. Like the
// sandbox ID, the mesh CA signature vouches for it, never the hardware
// evidence.

package armtls

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

// OIDClientDocumentDigest identifies the client-document-digest extension:
//
//	1.3.6.1.4.1.66378.1.9 - client document digest
//
// .8 is reserved: an earlier build stamped an assigned workload ID under it.
var OIDClientDocumentDigest = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 9}

// MarshalClientDocumentDigestExtension encodes h as the non-critical
// client-document-digest extension, a DER OCTET STRING of 32 bytes.
func MarshalClientDocumentDigestExtension(h []byte) (pkix.Extension, error) {
	if len(h) != sha256.Size {
		return pkix.Extension{}, errors.New("armtls: client document digest must be 32 bytes")
	}
	value, err := asn1.Marshal(h)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("armtls: marshal client document digest: %w", err)
	}
	return pkix.Extension{Id: OIDClientDocumentDigest, Value: value}, nil
}

// clientDocumentDigestFromCert returns the stamped digest, or nil when the
// certificate carries none. A malformed or repeated extension is an error.
func clientDocumentDigestFromCert(cert *x509.Certificate) ([]byte, error) {
	var h []byte
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDClientDocumentDigest) {
			continue
		}
		if h != nil {
			return nil, errors.New("armtls: certificate carries more than one client document digest")
		}
		var value []byte
		rest, err := asn1.Unmarshal(ext.Value, &value)
		if err != nil || len(rest) != 0 || len(value) != sha256.Size {
			return nil, errors.New("armtls: malformed client document digest extension")
		}
		// Only the one DER encoding parses, so two extension values never
		// name the same digest.
		if canonical, _ := asn1.Marshal(value); !bytes.Equal(canonical, ext.Value) {
			return nil, errors.New("armtls: client document digest is not canonical DER")
		}
		h = value
	}
	return h, nil
}

// ClientDocumentDigest returns the client document digest CDS stamped on
// cert. It reports false when the certificate carries none or carries a
// malformed one. The value is a CDS statement: read it only from a leaf whose
// chain to the mesh CA has been verified.
func ClientDocumentDigest(cert *x509.Certificate) ([]byte, bool) {
	h, err := clientDocumentDigestFromCert(cert)
	return h, err == nil && h != nil
}

// AgentLabel is the DNS label an agent is reached under: the lowercase,
// unpadded RFC 4648 base32 of the first 16 bytes of its client document
// digest, 26 characters.
func AgentLabel(h []byte) string {
	if len(h) < 16 {
		return ""
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:16]))
}
