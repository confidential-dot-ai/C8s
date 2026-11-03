// Assigned workload ID: the tenant identity of a pod CVM, stamped by CDS as an
// X.509 extension after verifying the guest's claims (docs/armtls.md, "Pod CVM
// issuance"). The value is the pod's confidential.ai/cw annotation as the
// provider signed it into the assignment; the guest carries it in its claims,
// so the quote vouches for it before CDS stamps it.

package armtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/workloadname"
)

// OIDAssignedWorkloadID identifies the assigned-workload-ID extension (see
// extension.go for the 1.3.6.1.4.1.66378 arc):
//
//	1.3.6.1.4.1.66378.1.8 - assigned workload ID extension
var OIDAssignedWorkloadID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 8}

// ValidateWorkloadID rejects a workload ID outside the workload-name grammar
// that confidential.ai/cw, allowlist entries and the matched-workload stamp
// share (pkg/workloadname): one identity, one grammar.
func ValidateWorkloadID(id string) error {
	if !workloadname.Valid(id) {
		return fmt.Errorf("armtls: workload ID %q is not a valid workload name (1..%d bytes, [A-Za-z0-9][A-Za-z0-9._-]*)", id, workloadname.MaxLen)
	}
	return nil
}

// MarshalAssignedWorkloadIDExtension encodes id as the non-critical
// assigned-workload-ID extension, a DER UTF8String.
func MarshalAssignedWorkloadIDExtension(id string) (pkix.Extension, error) {
	if err := ValidateWorkloadID(id); err != nil {
		return pkix.Extension{}, err
	}
	value, err := asn1.MarshalWithParams(id, "utf8")
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("armtls: marshal workload ID: %w", err)
	}
	return pkix.Extension{Id: OIDAssignedWorkloadID, Value: value}, nil
}

// unmarshalWorkloadID decodes an extension value the way unmarshalSandboxID
// does: one canonical DER UTF8String in the workload-name grammar, byte-exact
// against re-encoding.
func unmarshalWorkloadID(der []byte) (string, error) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return "", fmt.Errorf("armtls: unmarshal workload ID extension: %w", err)
	}
	if !isUTF8String(raw) {
		return "", fmt.Errorf("armtls: workload ID extension is class %d tag %#x, want UTF8String (tag %#x)", raw.Class, raw.Tag, asn1.TagUTF8String)
	}
	id := string(raw.Bytes)
	if err := ValidateWorkloadID(id); err != nil {
		return "", err
	}
	if !isCanonicalDER(id, der) {
		return "", fmt.Errorf("armtls: workload ID extension is not the canonical DER UTF8String encoding of its own value")
	}
	return id, nil
}

// AssignedWorkloadIDFromCert returns the certificate's assigned workload ID,
// or "" when the certificate carries no assigned-workload-ID extension. A
// present but malformed or duplicated extension is an error, never an empty
// result: a relying party that expects a tenant must not read damage as
// absence.
func AssignedWorkloadIDFromCert(cert *x509.Certificate) (string, error) {
	var (
		id   string
		seen bool
	)
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDAssignedWorkloadID) {
			continue
		}
		if seen {
			return "", fmt.Errorf("armtls: certificate carries more than one assigned-workload-ID extension")
		}
		decoded, err := unmarshalWorkloadID(ext.Value)
		if err != nil {
			return "", err
		}
		id = decoded
		seen = true
	}
	return id, nil
}

// RequireSameAssignedWorkload is the AcceptPeer of a pod CVM's mesh endpoint:
// the peer must carry exactly the assigned workload ID of the endpoint's own
// leaf, in both roles. One tenant's pods mesh with each other and with nothing
// else, so two tenants running the same image cannot substitute certificates,
// and a leaf without the stamp is refused where a tenant is expected. An
// endpoint whose own leaf carries no ID admits only peers without one.
func RequireSameAssignedWorkload(own string) func(Peer) error {
	return func(peer Peer) error {
		switch {
		case peer.AssignedWorkloadID == own:
			return nil
		case own == "":
			return fmt.Errorf("armtls: mesh peer %s is assigned to workload %q and this endpoint's leaf is assigned to none", peer.SandboxID, peer.AssignedWorkloadID)
		case peer.AssignedWorkloadID == "":
			return fmt.Errorf("armtls: mesh peer %s carries no assigned workload ID and this endpoint's leaf is assigned to %q", peer.SandboxID, own)
		default:
			return fmt.Errorf("armtls: mesh peer %s is assigned to workload %q, not %q", peer.SandboxID, peer.AssignedWorkloadID, own)
		}
	}
}
