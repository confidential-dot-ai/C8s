// Pod sandbox ID: the CRI sandbox identifier of the pod a leaf was issued to,
// stamped by CDS as an X.509 extension in the signed area after verifying the
// requester's inventory-signed sandbox token (docs/armtls.md, "Sandbox
// identity").

package armtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"regexp"
)

// OIDSandboxID identifies the pod-sandbox-ID extension (see extension.go for
// the 1.3.6.1.4.1.66378 arc):
//
//	1.3.6.1.4.1.66378.1.4 - pod sandbox ID extension
var OIDSandboxID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 4}

// sandboxIDPattern bounds a sandbox ID to what CRI runtimes emit (containerd:
// 64 hex chars), with headroom for other runtimes.
var sandboxIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// ValidateSandboxID rejects anything that is not a plausible CRI sandbox ID.
func ValidateSandboxID(id string) error {
	if !sandboxIDPattern.MatchString(id) {
		return fmt.Errorf("armtls: sandbox ID must match %s", sandboxIDPattern)
	}
	return nil
}

// MarshalSandboxIDExtension encodes id as the non-critical sandbox-ID
// extension, a DER IA5String.
func MarshalSandboxIDExtension(id string) (pkix.Extension, error) {
	if err := ValidateSandboxID(id); err != nil {
		return pkix.Extension{}, err
	}
	value, err := asn1.MarshalWithParams(id, "ia5")
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("armtls: marshal sandbox ID: %w", err)
	}
	return pkix.Extension{Id: OIDSandboxID, Value: value}, nil
}

// SandboxIDFromCert returns the certificate's sandbox ID, or "" when the
// certificate carries no sandbox-ID extension. A present but malformed
// extension is an error, never an empty result.
func SandboxIDFromCert(cert *x509.Certificate) (string, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDSandboxID) {
			continue
		}
		var id string
		rest, err := asn1.UnmarshalWithParams(ext.Value, &id, "ia5")
		if err != nil {
			return "", fmt.Errorf("armtls: unmarshal sandbox ID extension: %w", err)
		}
		if len(rest) > 0 {
			return "", fmt.Errorf("armtls: %d trailing bytes after sandbox ID extension", len(rest))
		}
		if err := ValidateSandboxID(id); err != nil {
			return "", err
		}
		return id, nil
	}
	return "", nil
}
