// Component set: the release whose component entries admitted every c8s
// component container the leaf's pod runs, stamped by CDS as an X.509
// extension in the CA-signed area (docs/armtls.md, "Sandbox identity").
//
// This is a statement BY CDS about the policy it judged the pod under, decided
// after the requester's evidence is frozen, so the mesh CA signature vouches
// for it and never the hardware evidence. The digest names the set's bytes, so
// a relying party holding the same document can tell which release's entries
// admitted the pod.

package armtls

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"regexp"
)

// OIDComponentSet identifies the component-set extension (see
// matchedworkload.go for the 1.3.6.1.4.1.66378 arc):
//
//	1.3.6.1.4.1.66378.1.11 - component set extension
var OIDComponentSet = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 11}

// componentVersionPattern is the version grammar a component set is keyed by:
// MAJOR.MINOR.PATCH, each a decimal number without a leading zero.
var componentVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// ComponentSet names the component set a leaf's pod is on.
type ComponentSet struct {
	// Version is the release the set is keyed by.
	Version string
	// Digest is SHA-256 of the set's normalized entries, exactly 32 bytes.
	Digest []byte
}

// componentSetASN1 is the DER encoding:
//
//	ComponentSet ::= SEQUENCE {
//	    version UTF8String,        -- MAJOR.MINOR.PATCH
//	    digest  OCTET STRING (32)  -- SHA-256 of the set's entries
//	}
type componentSetASN1 struct {
	Version string `asn1:"utf8"`
	Digest  []byte
}

// Validate rejects a value this package must neither emit nor accept.
func (c *ComponentSet) Validate() error {
	if !componentVersionPattern.MatchString(c.Version) {
		return fmt.Errorf("armtls: component set version %q is not MAJOR.MINOR.PATCH", c.Version)
	}
	if len(c.Digest) != sha256.Size {
		return fmt.Errorf("armtls: component set digest must be %d bytes, got %d", sha256.Size, len(c.Digest))
	}
	return nil
}

// MarshalComponentSetExtension encodes c as the non-critical component-set
// extension.
func MarshalComponentSetExtension(c *ComponentSet) (pkix.Extension, error) {
	if err := c.Validate(); err != nil {
		return pkix.Extension{}, err
	}
	value, err := asn1.Marshal(componentSetASN1{Version: c.Version, Digest: c.Digest})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("armtls: marshal component set: %w", err)
	}
	return pkix.Extension{Id: OIDComponentSet, Value: value}, nil
}

// UnmarshalComponentSet decodes a DER-encoded component-set extension value,
// requiring the one canonical encoding: minimal DER, no trailing bytes or
// fields, byte-exact against re-encoding.
func UnmarshalComponentSet(der []byte) (*ComponentSet, error) {
	var raw componentSetASN1
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("armtls: unmarshal component set: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("armtls: %d trailing bytes after component-set extension", len(rest))
	}
	reencoded, err := asn1.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("armtls: re-encode component set: %w", err)
	}
	if !bytes.Equal(reencoded, der) {
		return nil, fmt.Errorf("armtls: component-set extension is not the canonical encoding (%d bytes, canonical is %d)", len(der), len(reencoded))
	}
	set := &ComponentSet{Version: raw.Version, Digest: raw.Digest}
	if err := set.Validate(); err != nil {
		return nil, err
	}
	return set, nil
}

// ComponentSetFromCert returns the certificate's component-set stamp, or nil
// when the certificate carries none. A present but malformed or duplicated
// extension is an error, never nil — a verifier must not read damage as
// absence. The caller must have verified cert against the mesh CA first: on a
// self-issued leaf the stamp is whatever the peer chose.
func ComponentSetFromCert(cert *x509.Certificate) (*ComponentSet, error) {
	var found *ComponentSet
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDComponentSet) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("armtls: certificate carries more than one component-set extension")
		}
		set, err := UnmarshalComponentSet(ext.Value)
		if err != nil {
			return nil, err
		}
		found = set
	}
	return found, nil
}
