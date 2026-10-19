package armtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sync"

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

// WithRuntimeExtensions returns att carrying the policies in journal when it
// is TDX evidence without a list of its own, so peers can replay RTMR[3];
// otherwise att itself. Producers call it after obtaining the evidence. A nil
// journal adds no list.
func WithRuntimeExtensions(att *Attestation, journal *Journal) *Attestation {
	if journal == nil || att.Family != TEETypeTDX || att.RuntimeExtensions != nil {
		return att
	}
	withList := *att
	withList.RuntimeExtensions = journal.Policies()
	return &withList
}

// The measured-policy journal lists the allowlist policies a TDX node extends
// into RTMR[3]. Its one writer is the policy measurer in nri-image-policy,
// which keeps it in the plugin's runtime directory (workload_claims.socket_dir,
// the chart's nriImagePolicy.hostPaths.runtimeDir); the measurer's tests pin
// this contract. NodeJournal is its path on the node and in pods that mount that
// directory at its host path; workloadclaims.MeasuredPoliciesJournal is its
// path in the sidecars the plugin mounts the directory into.
//
// Every reader relies on this contract:
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
)

// ReadRuntimeExtensions reads the measured-policy journal at path: nil when it
// does not exist, an error when it cannot be read or holds more than
// [MaxRuntimeExtensions] entries.
func ReadRuntimeExtensions(path string) ([]string, error) {
	list, err := runtimemeasure.ReadJournal(path)
	if err != nil {
		return nil, err
	}
	if len(list) > MaxRuntimeExtensions {
		return nil, fmt.Errorf("journal %s lists %d measured policies, over the per-boot cap of %d", path, len(list), MaxRuntimeExtensions)
	}
	return list, nil
}

// Journal is a measured-policy journal that producers read on every use. A
// nil *Journal holds no list. It is safe for concurrent use.
type Journal struct {
	path string

	mu       sync.Mutex
	reported string // the last read error logged
	absent   bool   // the missing journal was logged
}

// NewJournal returns the journal at path, or nil when path is empty.
func NewJournal(path string) *Journal {
	if path == "" {
		return nil
	}
	return &Journal{path: path}
}

// Policies returns the RTMR[3] runtime extensions the node journaled, nil
// when it journals none. Call it after obtaining the evidence: the journal
// records before it extends, so it may run ahead of the quote, which verifiers
// allow for, but must not lag it.
//
// An unusable journal yields nil: a verifier that needs the list then fails
// closed, and one that does not still accepts the evidence. Such a journal
// usually stays unusable until reboot, so each distinct error is logged once.
// A missing journal is normal before the node's first measure but also means
// a wrong path or mount, so it is logged once at Info.
func (j *Journal) Policies() []string {
	if j == nil {
		return nil
	}
	list, err := ReadRuntimeExtensions(j.path)
	j.mu.Lock()
	defer j.mu.Unlock()
	if err == nil {
		j.reported = ""
		if list == nil && !j.absent {
			if _, statErr := os.Stat(j.path); errors.Is(statErr, fs.ErrNotExist) {
				j.absent = true
				slog.Info("armtls: no measured-policy journal; evidence lists no measured policies until it appears", "path", j.path)
			}
		}
		return list
	}
	if msg := err.Error(); msg != j.reported {
		j.reported = msg
		slog.Warn("armtls: evidence omits the measured policies", "error", err)
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
