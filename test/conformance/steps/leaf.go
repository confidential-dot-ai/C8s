package steps

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/attestation-go/armtls"
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

// leaf is a certificate a pod or a requester holds, with the chain it came
// in and when it was first seen.
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
	if _, err := asn1.UnmarshalWithParams(value, &id, "ia5"); err != nil {
		return "", fmt.Errorf("the sandbox ID extension: %w", err)
	}
	return id, nil
}

// certificateEvidence is the .1 extension's report data, if the leaf
// carries certificate evidence.
func (l *leaf) certificateEvidence() ([]byte, error) {
	value, ok := l.extension(oidARMTLSAttestation)
	if !ok {
		return nil, errors.New("the leaf carries no certificate evidence")
	}
	att, err := armtls.UnmarshalExtension(value)
	if err != nil {
		return nil, fmt.Errorf("the certificate evidence: %w", err)
	}
	data, ok := att.ReportData()
	if !ok {
		return nil, errors.New("the certificate evidence carries no report data")
	}
	return data, nil
}

// certifies reports whether the leaf's public key is pub.
func (l *leaf) certifies(pub crypto.PublicKey) (bool, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return false, err
	}
	return bytes.Equal(der, l.cert.RawSubjectPublicKeyInfo), nil
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
