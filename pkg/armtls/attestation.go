package armtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io/fs"
	"time"

	agarmtls "github.com/confidential-dot-ai/attestation-go/armtls"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/policymeasure"
)

// The armTLS extension, its wire format and its verification live in
// attestation-go/armtls. What follows is the C8s spelling of that surface, kept
// because many call sites and the docs use these names. New code can take the
// library names directly.

// Attestation is the TEE evidence an armTLS certificate extension carries.
type Attestation = agarmtls.Attestation

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
	SNPReportSize = agarmtls.SNPReportSize

	// SNPMeasurementSize is the size of an SEV-SNP launch measurement
	// (SHA-384 digest = 48 bytes).
	SNPMeasurementSize = runtimemeasure.Size

	// MaxRuntimeExtensions caps Attestation.RuntimeExtensions: a longer list
	// cannot be encoded, and verifiers refuse it.
	MaxRuntimeExtensions = agarmtls.MaxRuntimeExtensions
)

// OID arc: 1.3.6.1.4.1.66378 is the C8s Private Enterprise Number. The library
// assigns no identifier of its own: attestation-go/armtls owns the extension
// format, C8s owns the OID it is carried under.
//
//	1.3.6.1.4.1.66378.1   - confidential TEE attestation arc
//	1.3.6.1.4.1.66378.1.1 - armTLS attestation extension
//	1.3.6.1.4.1.66378.1.2 - attestation-evidence audit digest (certutil)
//	1.3.6.1.4.1.66378.1.4 - pod sandbox ID extension (sandbox.go)
//	1.3.6.1.4.1.66378.1.5 - matched workload extension (matchedworkload.go)
//
// .1.3 was the armTLS config-claims extension; it is retired, not reusable.
var (
	OIDConfidentialTEE   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1}
	OIDARMTLSAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 1}
)

// MarshalExtension encodes att as the X.509 extension under OIDARMTLSAttestation.
func MarshalExtension(att *Attestation) (pkix.Extension, error) {
	return att.MarshalExtension(OIDARMTLSAttestation)
}

// WithRuntimeExtensions returns att carrying this node's [RuntimeExtensions]
// when it is TDX evidence without a list of its own, so peers can replay
// RTMR[3]; otherwise att itself. Producers call it after obtaining the
// evidence.
func WithRuntimeExtensions(att *Attestation) (*Attestation, error) {
	if att.Family != TEETypeTDX || att.RuntimeExtensions != nil {
		return att, nil
	}
	list, err := RuntimeExtensions()
	if err != nil {
		return nil, err
	}
	withList := *att
	withList.RuntimeExtensions = list
	return &withList, nil
}

// runtimeJournals are where this node's measured-policy journal may be; the
// first that exists wins. Var so tests can move it.
var runtimeJournals = []string{policymeasure.NodeJournal, policymeasure.SidecarJournal}

// RuntimeExtensions returns the RTMR[3] runtime extensions this node
// journaled, nil when it journals none. Call it after obtaining the evidence:
// the journal records before it extends, so it may run ahead of the quote,
// which verifiers allow for, but must not lag it.
func RuntimeExtensions() ([]string, error) {
	for _, path := range runtimeJournals {
		if list, err := ReadJournal(path); err != nil || list != nil {
			return list, err
		}
	}
	return nil, nil
}

// ReadJournal is [runtimemeasure.ReadJournal] retrying a permission error:
// after a failed extend the plugin rewrites the journal 0600 and restores 0644
// right after. A missing journal is nil, nil.
func ReadJournal(path string) ([]string, error) {
	var err error
	for attempt := range journalReadAttempts {
		var list []string
		if list, err = runtimemeasure.ReadJournal(path); !errors.Is(err, fs.ErrPermission) {
			return list, err
		}
		if attempt < journalReadAttempts-1 {
			time.Sleep(journalRetryDelay)
		}
	}
	return nil, err
}

const (
	journalReadAttempts = 5
	journalRetryDelay   = 20 * time.Millisecond
)

// ExtractAttestation parses the extension under OIDARMTLSAttestation out of a
// certificate, failing with ErrNoAttestation when there is none.
func ExtractAttestation(cert *x509.Certificate) (*Attestation, error) {
	return agarmtls.ExtractAttestation(cert, OIDARMTLSAttestation)
}

var (
	// ReportDataForKey computes the REPORTDATA binding a public key (and an
	// optional nonce) to a TEE report: SHA-384, zero-padded to 64 bytes.
	ReportDataForKey = agarmtls.ReportDataForKey

	// UnmarshalExtension decodes a DER-encoded attestation extension.
	UnmarshalExtension = agarmtls.UnmarshalExtension

	// NormalizeSEVSNPReport returns the raw AMD report, unwrapping the Hyper-V
	// HCL envelope an Azure guest's vTPM puts around it.
	NormalizeSEVSNPReport = agarmtls.NormalizeSEVSNPReport
)
