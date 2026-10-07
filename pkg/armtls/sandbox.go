// Pod sandbox ID: the CRI sandbox identifier of the pod a leaf was issued to,
// stamped by CDS as an X.509 extension in the signed area after verifying the
// requester's inventory-signed sandbox token (docs/armtls.md, "Sandbox
// identity").

package armtls

import (
	"bytes"
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

// ValidateSandboxID rejects an ID outside the extension's charset and length:
// 1 to 128 characters of [A-Za-z0-9._-].
func ValidateSandboxID(id string) error {
	if !sandboxIDPattern.MatchString(id) {
		return fmt.Errorf("armtls: sandbox ID must match %s", sandboxIDPattern)
	}
	return nil
}

// MarshalSandboxIDExtension encodes id as the non-critical sandbox-ID
// extension, a DER UTF8String.
func MarshalSandboxIDExtension(id string) (pkix.Extension, error) {
	if err := ValidateSandboxID(id); err != nil {
		return pkix.Extension{}, err
	}
	value, err := asn1.MarshalWithParams(id, "utf8")
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("armtls: marshal sandbox ID: %w", err)
	}
	return pkix.Extension{Id: OIDSandboxID, Value: value}, nil
}

// unmarshalSandboxID decodes an extension value, requiring the one canonical
// encoding: a DER UTF8String inside the pattern, byte-exact against
// re-encoding — no two distinct extension values may parse to the same ID.
func unmarshalSandboxID(der []byte) (string, error) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return "", fmt.Errorf("armtls: unmarshal sandbox ID extension: %w", err)
	}
	if !isUTF8String(raw) {
		return "", fmt.Errorf("armtls: sandbox ID extension is class %d tag %#x, want UTF8String (tag %#x)", raw.Class, raw.Tag, asn1.TagUTF8String)
	}
	if !sandboxIDPattern.Match(raw.Bytes) {
		return "", fmt.Errorf("armtls: sandbox ID must match %s", sandboxIDPattern)
	}
	id := string(raw.Bytes)
	if !isCanonicalDER(id, der) {
		return "", fmt.Errorf("armtls: sandbox ID extension is not the canonical DER UTF8String encoding of its own value")
	}
	return id, nil
}

func isUTF8String(raw asn1.RawValue) bool {
	return raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagUTF8String && !raw.IsCompound
}

// isCanonicalDER rejects a non-minimal length, a constructed string and
// trailing bytes in one comparison: only one encoding re-marshals to der.
func isCanonicalDER(id string, der []byte) bool {
	reencoded, err := asn1.MarshalWithParams(id, "utf8")
	return err == nil && bytes.Equal(reencoded, der)
}

// SandboxIDFromCert returns the certificate's sandbox ID, or "" when the
// certificate carries no sandbox-ID extension. A present but malformed or
// duplicated extension is an error, never an empty result — a verifier must
// not read damage as absence.
func SandboxIDFromCert(cert *x509.Certificate) (string, error) {
	var (
		id   string
		seen bool
	)
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDSandboxID) {
			continue
		}
		if seen {
			return "", fmt.Errorf("armtls: certificate carries more than one sandbox-ID extension")
		}
		decoded, err := unmarshalSandboxID(ext.Value)
		if err != nil {
			return "", err
		}
		id, seen = decoded, true
	}
	return id, nil
}
