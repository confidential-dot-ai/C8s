package ratls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	agratls "github.com/confidential-dot-ai/attestation-go/ratls"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// The RA-TLS extension, its wire format and its verification live in
// attestation-go/ratls. What follows is the C8s spelling of that surface, kept
// because many call sites and the docs use these names. New code can take the
// library names directly.

// Attestation is the TEE evidence an RA-TLS certificate extension carries.
type Attestation = agratls.Attestation

// TEEType is the hardware TEE family an extension records. The extension
// carries the family, so this is teetypes.Family under the C8s name.
type TEEType = teetypes.Family

const (
	// TEETypeSEVSNP is AMD SEV-SNP: snp, az-snp, gcp-snp.
	TEETypeSEVSNP = teetypes.FamilySNP
	// TEETypeTDX is Intel TDX: tdx, az-tdx, gcp-tdx.
	TEETypeTDX = teetypes.FamilyTDX

	// SNPReportSize is the exact size of an AMD SEV-SNP attestation report
	// (ATTESTATION_REPORT, AMD SEV-SNP ABI Specification).
	SNPReportSize = agratls.SNPReportSize

	// SNPMeasurementSize is the size of an SEV-SNP launch measurement
	// (SHA-384 digest = 48 bytes).
	SNPMeasurementSize = runtimemeasure.Size
)

// OID arc: 1.3.6.1.4.1.66378 is the C8s Private Enterprise Number. The library
// assigns no identifier of its own: attestation-go/ratls owns the extension
// format, C8s owns the OID it is carried under.
//
//	1.3.6.1.4.1.66378.1   - confidential TEE attestation arc
//	1.3.6.1.4.1.66378.1.1 - RA-TLS attestation extension
//	1.3.6.1.4.1.66378.1.2 - attestation-evidence audit digest (certutil)
//	1.3.6.1.4.1.66378.1.4 - pod sandbox ID extension (sandbox.go)
//	1.3.6.1.4.1.66378.1.5 - matched workload extension (matchedworkload.go)
//
// .1.3 was the RA-TLS config-claims extension; it is retired, not reusable.
var (
	OIDConfidentialTEE  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1}
	OIDRATLSAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 1}
)

// MarshalExtension encodes att as the X.509 extension under OIDRATLSAttestation.
func MarshalExtension(att *Attestation) (pkix.Extension, error) {
	return att.MarshalExtension(OIDRATLSAttestation)
}

// ExtractAttestation parses the extension under OIDRATLSAttestation out of a
// certificate, failing with ErrNoAttestation when there is none.
func ExtractAttestation(cert *x509.Certificate) (*Attestation, error) {
	return agratls.ExtractAttestation(cert, OIDRATLSAttestation)
}

var (
	// ReportDataForKey computes the REPORTDATA binding a public key (and an
	// optional nonce) to a TEE report: SHA-384, zero-padded to 64 bytes.
	ReportDataForKey = agratls.ReportDataForKey

	// UnmarshalExtension decodes a DER-encoded attestation extension.
	UnmarshalExtension = agratls.UnmarshalExtension

	// NormalizeSEVSNPReport returns the raw AMD report, unwrapping the Hyper-V
	// HCL envelope an Azure guest's vTPM puts around it.
	NormalizeSEVSNPReport = agratls.NormalizeSEVSNPReport
)
