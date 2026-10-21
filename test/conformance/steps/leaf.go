package steps

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/attestation-go/armtls"
	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

// The non-critical extensions a leaf carries under the C8s arc
// 1.3.6.1.4.1.66378.1: the certificate evidence copied from the CSR (.1,
// oidARMTLSAttestation in cds.go), the digest of the evidence the CDS
// verified (.2), the sandbox ID the inventory bound (.4) and the matched
// workload (.5).
var (
	oidEvidenceDigest    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 2}
	oidSandboxID         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 4}
	oidMatchedWorkload   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 5}
	errNoMatchedWorkload = errors.New("the leaf carries no matched workload")
)

// leaf is a certificate a pod, a requester or the CDS itself presents, with
// the chain it came in and when it was first seen.
type leaf struct {
	cert  *x509.Certificate
	chain []*x509.Certificate
	raw   []byte
	seen  time.Time
}

// parseLeaf reads a PEM chain, leaf first; nil when the bytes hold none.
func parseLeaf(raw []byte) (*leaf, error) {
	chain, err := certificates(raw)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, nil
	}
	return &leaf{cert: chain[0], chain: chain, raw: raw, seen: time.Now()}, nil
}

func (l *leaf) serial() string { return l.cert.SerialNumber.Text(16) }

// extension returns the value of the leaf's extension with oid, if present.
func (l *leaf) extension(oid asn1.ObjectIdentifier) ([]byte, bool) {
	for _, ext := range l.cert.Extensions {
		if ext.Id.Equal(oid) {
			return ext.Value, true
		}
	}
	return nil, false
}

// matchedWorkload is the .5 extension's DER: the format version, the entry
// name, the served allowlist's version and the SHA-256 of its canonical bytes.
type matchedWorkload struct {
	FormatVersion    int
	Name             string `asn1:"ia5"`
	AllowlistVersion string `asn1:"ia5"`
	AllowlistDigest  []byte
}

func (l *leaf) matched() (*matchedWorkload, error) {
	value, ok := l.extension(oidMatchedWorkload)
	if !ok {
		return nil, errNoMatchedWorkload
	}
	var m matchedWorkload
	rest, err := asn1.Unmarshal(value, &m)
	if err != nil {
		return nil, fmt.Errorf("the matched workload extension: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("the matched workload extension has %d trailing bytes", len(rest))
	}
	return &m, nil
}

// sandboxID is the .4 extension, or empty when the leaf carries none.
func (l *leaf) sandboxID() (string, error) {
	value, ok := l.extension(oidSandboxID)
	if !ok {
		return "", nil
	}
	var id string
	if _, err := asn1.UnmarshalWithParams(value, &id, "utf8"); err != nil {
		return "", fmt.Errorf("the sandbox ID extension: %w", err)
	}
	return id, nil
}

// certificateEvidence is the report data of the .1 extension, if the
// certificate carries evidence.
func (l *leaf) certificateEvidence() ([]byte, error) {
	att, err := armtls.ExtractAttestation(l.cert, oidARMTLSAttestation)
	if err != nil {
		return nil, fmt.Errorf("the certificate evidence: %w", err)
	}
	return reportDataOf(att)
}

// reportDataOf is the 64 bytes of report data the evidence commits to. The
// library reads them off a raw SEV-SNP report; evidence in an envelope, as
// every other platform's is, carries them in a quote or report the library
// leaves to its verifiers, read here instead.
func reportDataOf(att *armtls.Attestation) ([]byte, error) {
	if data, ok := att.ReportData(); ok {
		return data, nil
	}
	envelope, ok := att.EmbeddedEvidence()
	if !ok {
		return nil, errors.New("the certificate evidence carries no report data")
	}
	switch envelope.Platform.Family() {
	case teetypes.FamilySNP:
		var evidence snp.SnpEvidence
		if err := json.Unmarshal(envelope.Evidence, &evidence); err != nil {
			return nil, fmt.Errorf("the SEV-SNP evidence: %w", err)
		}
		raw, err := base64.StdEncoding.DecodeString(evidence.AttestationReport)
		if err != nil {
			return nil, fmt.Errorf("the SEV-SNP report: %w", err)
		}
		report, err := armtls.NormalizeSEVSNPReport(raw)
		if err != nil {
			return nil, err
		}
		if len(report) < snp.ReportDataOffset+64 {
			return nil, fmt.Errorf("the SEV-SNP report is %d bytes, too short for report data", len(report))
		}
		return report[snp.ReportDataOffset : snp.ReportDataOffset+64], nil
	case teetypes.FamilyTDX:
		var evidence tdx.TdxEvidence
		if err := json.Unmarshal(envelope.Evidence, &evidence); err != nil {
			return nil, fmt.Errorf("the TDX evidence: %w", err)
		}
		raw, err := base64.StdEncoding.DecodeString(evidence.Quote)
		if err != nil {
			return nil, fmt.Errorf("the TDX quote: %w", err)
		}
		parsed, err := tdxabi.QuoteToProto(raw)
		if err != nil {
			return nil, fmt.Errorf("the TDX quote: %w", err)
		}
		quote, ok := parsed.(*tdxpb.QuoteV4)
		if !ok {
			return nil, fmt.Errorf("the TDX quote is a %T, whose report data this suite does not read", parsed)
		}
		return quote.GetTdQuoteBody().GetReportData(), nil
	}
	return nil, fmt.Errorf("the %s evidence carries report data this suite does not read", envelope.Platform)
}

// commitsToOwnKey: the report data of the certificate's evidence begins with
// SHA-384 of the certificate's own public key.
func (l *leaf) commitsToOwnKey() error {
	data, err := l.certificateEvidence()
	if err != nil {
		return err
	}
	want, err := armtls.ReportDataForKey(l.cert.PublicKey, nil)
	if err != nil {
		return err
	}
	const anchor = sha512.Size384
	if len(data) < anchor || !bytes.Equal(data[:anchor], want[:anchor]) {
		return errors.New("the report data of the certificate evidence does not begin with SHA-384 of the certificate's public key")
	}
	return nil
}

// certifies reports whether cert's public key is pub.
func certifies(cert *x509.Certificate, pub crypto.PublicKey) (bool, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return false, err
	}
	return bytes.Equal(der, cert.RawSubjectPublicKeyInfo), nil
}

// parsePrivateKey reads the one EC private key of a PEM file, as get-cert
// writes it.
func parsePrivateKey(raw []byte) (*ecdsa.PrivateKey, error) {
	for rest := raw; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no private key in the file")
		}
		switch block.Type {
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			ec, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("the private key is %T, not ECDSA", key)
			}
			return ec, nil
		}
	}
}
