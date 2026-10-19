package armtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"testing"

	agarmtls "github.com/confidential-dot-ai/attestation-go/armtls"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
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
func WithRuntimeExtensions(att *Attestation) *Attestation {
	if att.Family != TEETypeTDX || att.RuntimeExtensions != nil {
		return att
	}
	withList := *att
	withList.RuntimeExtensions = RuntimeExtensions()
	return &withList
}

// The measured-policy journal lists the allowlist policies a TDX node extends
// into RTMR[3], in the NRI plugin's runtime directory. NodeJournal is its path
// on the node and in pods that mount the runtime directory at its host path;
// SidecarJournal is its path in sidecars the plugin mounts the directory into.
//
// Its one writer, the node's policy measurer, keeps this contract, which every
// reader relies on:
//   - one canonical digest per line, in extend order, recorded before it is
//     extended, so the list may run ahead of a quote but never lags it;
//   - each digest extended at most once per boot, so the list replays the
//     register exactly;
//   - owned by root with mode 0644 at all times, so non-root readers such as
//     cds-attest and get-cert can read it;
//   - on a tmpfs, so it lives exactly as long as the register;
//   - at most [MaxRuntimeExtensions] entries per boot. Producers send no list
//     beyond that, and verifiers reject the node until it reboots.
//
// Readers read it after the evidence, so the measurer and its readers start
// in any order.
const (
	MeasuredPoliciesJournal = "measured-policies"
	NodeJournal             = "/run/nri-image-policy/" + MeasuredPoliciesJournal
	SidecarJournal          = "/run/c8s/workload-claims/" + MeasuredPoliciesJournal
)

// runtimeJournals are where this node's measured-policy journal may be; the
// first non-empty one wins. Test binaries start with none, so no test reads
// the host's journal; tests in this package move it.
var runtimeJournals = defaultRuntimeJournals()

func defaultRuntimeJournals() []string {
	if testing.Testing() {
		return nil
	}
	return []string{NodeJournal, SidecarJournal}
}

// readJournal reads one journal. Var so tests can fail it.
var readJournal = runtimemeasure.ReadJournal

// ReadRuntimeExtensions reads the measured-policy journal at path: nil when it
// does not exist, an error when it cannot be read or holds more than
// [MaxRuntimeExtensions] entries. Every producer of the list reads through it.
func ReadRuntimeExtensions(path string) ([]string, error) {
	list, err := readJournal(path)
	if err != nil {
		return nil, err
	}
	if len(list) > MaxRuntimeExtensions {
		return nil, fmt.Errorf("journal lists %d measured policies, over the per-boot cap of %d", len(list), MaxRuntimeExtensions)
	}
	return list, nil
}

// RuntimeExtensions returns the RTMR[3] runtime extensions this node
// journaled, nil when it journals none. Call it after obtaining the evidence:
// the journal records before it extends, so it may run ahead of the quote,
// which verifiers allow for, but must not lag it.
//
// An unusable journal is logged and yields nil: a verifier that needs the
// list then fails closed, and one that does not still accepts the evidence.
func RuntimeExtensions() []string {
	for _, path := range runtimeJournals {
		list, err := ReadRuntimeExtensions(path)
		if err != nil {
			slog.Warn("armtls: evidence omits the measured policies", "path", path, "error", err)
			return nil
		}
		if list != nil {
			slog.Info("armtls: evidence lists the measured policies", "path", path, "policies", len(list))
			return list
		}
	}
	return nil
}

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
