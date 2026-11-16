// Matched workload: the single allowlist entry whose (digest, argv) policy the
// pod's attested container inventory uniquely matched at issuance, stamped by
// CDS as an X.509 extension in the CA-signed area (docs/armtls.md, "Matched
// workload").
//
// This is a statement BY CDS, not by the requester: the match happens on the
// CDS side after the requester's evidence is frozen, so it lives outside the
// requester's REPORTDATA by construction. Like the sandbox ID, the mesh CA
// signature — never the hardware evidence — is what vouches for it, and it is
// enforceable only where a CA chain has been verified.
//
// The stamp names exactly one entry. allowlist.MatchWorkload is argv-aware and
// returns one entry or an error, and identical-composition entries are a lint
// error, so an ambiguous set never earns a stamp. The allowlist version and
// canonical digest pin WHICH policy document the match was decided under, so a
// relying party holding the same canonical bytes can detect skew between the
// policy it pinned and the one CDS enforced.

package armtls

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"regexp"

	"github.com/confidential-dot-ai/c8s/pkg/workloadname"
)

// OIDMatchedWorkload identifies the matched-workload extension (see
// extension.go for the 1.3.6.1.4.1.66378 arc):
//
//	1.3.6.1.4.1.66378.1.5 - matched workload extension
var OIDMatchedWorkload = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 5}

// matchedWorkloadVersion is the only encoding version this package emits or
// parses. An unknown version fails closed wherever workload identity is read.
const matchedWorkloadVersion = 1

// allowlistDigestSize is the exact length of the canonical-allowlist SHA-256.
const allowlistDigestSize = 32

// allowlistVersionPattern is the canonical positive decimal integer the store's
// monotonic version counter emits: 1–20 ASCII digits, no leading zero.
var allowlistVersionPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

// MatchedWorkload names the allowlist entry a leaf's attested container set
// uniquely matched at issuance, and the exact policy snapshot the match was
// decided under.
type MatchedWorkload struct {
	// Name is the matched entry name (allowlist workload-name grammar,
	// at most workloadname.MaxLen bytes).
	Name string
	// AllowlistVersion is the store's monotonic version counter at the
	// snapshot the match used — a canonical positive decimal integer.
	AllowlistVersion string
	// AllowlistDigest is SHA-256 of Allowlist.Canonical() of that snapshot,
	// exactly 32 bytes.
	AllowlistDigest []byte
}

// matchedWorkloadASN1 is the DER encoding:
//
//	MatchedWorkload ::= SEQUENCE {
//	    formatVersion    INTEGER,           -- exactly 1
//	    name             IA5String,         -- 1..63 bytes, workload-name grammar
//	    allowlistVersion IA5String,         -- 1..20 decimal digits, no leading zero
//	    allowlistDigest  OCTET STRING (32)  -- SHA-256(Allowlist.Canonical())
//	}
type matchedWorkloadASN1 struct {
	FormatVersion    int
	Name             string `asn1:"ia5"`
	AllowlistVersion string `asn1:"ia5"`
	AllowlistDigest  []byte
}

// Validate rejects a value this package must neither emit nor accept.
func (m *MatchedWorkload) Validate() error {
	if !workloadname.Valid(m.Name) {
		return fmt.Errorf("armtls: matched-workload name %q is not a valid workload entry name (1..%d bytes, [A-Za-z0-9][A-Za-z0-9._-]*)", m.Name, workloadname.MaxLen)
	}
	if !allowlistVersionPattern.MatchString(m.AllowlistVersion) {
		return fmt.Errorf("armtls: matched-workload allowlist version %q is not a canonical positive decimal integer", m.AllowlistVersion)
	}
	if len(m.AllowlistDigest) != allowlistDigestSize {
		return fmt.Errorf("armtls: matched-workload allowlist digest must be %d bytes, got %d", allowlistDigestSize, len(m.AllowlistDigest))
	}
	return nil
}

// MarshalMatchedWorkloadExtension encodes m as the non-critical
// matched-workload extension.
func MarshalMatchedWorkloadExtension(m *MatchedWorkload) (pkix.Extension, error) {
	if err := m.Validate(); err != nil {
		return pkix.Extension{}, err
	}
	value, err := asn1.Marshal(matchedWorkloadASN1{
		FormatVersion:    matchedWorkloadVersion,
		Name:             m.Name,
		AllowlistVersion: m.AllowlistVersion,
		AllowlistDigest:  m.AllowlistDigest,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("armtls: marshal matched workload: %w", err)
	}
	return pkix.Extension{Id: OIDMatchedWorkload, Value: value}, nil
}

// UnmarshalMatchedWorkload decodes a DER-encoded matched-workload extension
// value, requiring the one canonical encoding: minimal DER, no trailing bytes
// or fields, byte-exact against re-encoding — no two distinct extension values
// may parse to the same MatchedWorkload.
func UnmarshalMatchedWorkload(der []byte) (*MatchedWorkload, error) {
	var raw matchedWorkloadASN1
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("armtls: unmarshal matched workload: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("armtls: %d trailing bytes after matched-workload extension", len(rest))
	}
	if raw.FormatVersion != matchedWorkloadVersion {
		return nil, fmt.Errorf("armtls: unsupported matched-workload version %d (supported: %d)", raw.FormatVersion, matchedWorkloadVersion)
	}
	reencoded, err := asn1.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("armtls: re-encode matched workload: %w", err)
	}
	if !bytes.Equal(reencoded, der) {
		return nil, fmt.Errorf("armtls: matched-workload extension is not the exact v%d encoding (%d bytes, canonical is %d)", matchedWorkloadVersion, len(der), len(reencoded))
	}
	m := &MatchedWorkload{
		Name:             raw.Name,
		AllowlistVersion: raw.AllowlistVersion,
		AllowlistDigest:  raw.AllowlistDigest,
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// MatchedWorkloadFromCert returns the certificate's matched-workload stamp, or
// nil when the certificate carries none. A present but malformed or duplicated
// extension is an error, never nil — a verifier must not read damage as
// absence. The caller must have verified cert against the mesh CA first: on a
// self-issued leaf the stamp is whatever the peer chose.
func MatchedWorkloadFromCert(cert *x509.Certificate) (*MatchedWorkload, error) {
	var found *MatchedWorkload
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDMatchedWorkload) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("armtls: certificate carries more than one matched-workload extension")
		}
		m, err := UnmarshalMatchedWorkload(ext.Value)
		if err != nil {
			return nil, err
		}
		found = m
	}
	return found, nil
}
