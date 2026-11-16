// Package secretbroker is the wire of pod secret release through the CDS
// broker (docs/pod-secrets.md). A pod CVM asks CDS for a secret by name over
// mutual TLS with its CDS-issued leaf; CDS states which verified pod asks,
// signs that statement with its broker key and forwards it to the key
// management service (KMS) its measured configuration names. The KMS decides
// and returns the value, which CDS relays without keeping it.
package secretbroker

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

const (
	// PodRoute is the CDS route a pod CVM requests a secret on.
	PodRoute = "/pod-secrets"
	// StatementVersion and ReleaseVersion version the two documents CDS sends
	// a KMS; a KMS refuses any version it does not implement.
	StatementVersion = "c8s-secret-statement/v1"
	ReleaseVersion   = "c8s-secret-release/v1"
	// MaxValue bounds a released secret value.
	MaxValue = 64 << 10
	// MaxStatementAge is how far a statement's issued_at may lie from the
	// KMS's clock, either way.
	MaxStatementAge = 5 * time.Minute
	// NonceSize is the length of a statement nonce.
	NonceSize = 32

	statementDomain = StatementVersion + "\x00"
	maxSecretName   = 128
)

// PodRequest is the body of POST PodRoute.
type PodRequest struct {
	Secret         string `json:"secret"`
	ClientDocument []byte `json:"client_document"`
}

// PodResponse answers a released PodRequest.
type PodResponse struct {
	Value []byte `json:"value"`
}

// Workload is the allowlist entry CDS matched the pod to, as its leaf states.
type Workload struct {
	Name             string `json:"name"`
	AllowlistVersion string `json:"allowlist_version"`
	AllowlistDigest  string `json:"allowlist_digest"`
}

// Statement is what CDS asserts about one request: the verified pod asking,
// the client document digest its leaf carries, and the secret it asks for.
type Statement struct {
	Version              string    `json:"version"`
	Pod                  string    `json:"pod"`
	Workload             *Workload `json:"workload,omitempty"`
	ClientDocumentDigest string    `json:"client_document_digest"`
	Secret               string    `json:"secret"`
	IssuedAt             time.Time `json:"issued_at"`
	Nonce                []byte    `json:"nonce"`
}

// ReleaseRequest is the body CDS POSTs to the KMS. Statement is the exact
// signed bytes; BrokerChain is DER, the broker certificate first and the mesh
// CA certificate last.
type ReleaseRequest struct {
	Version        string   `json:"version"`
	Statement      []byte   `json:"statement"`
	Signature      []byte   `json:"signature"`
	BrokerChain    [][]byte `json:"broker_chain"`
	ClientDocument []byte   `json:"client_document"`
}

// ReleaseResponse is the KMS's 200 answer.
type ReleaseResponse struct {
	Version string `json:"version"`
	Value   []byte `json:"value"`
}

// Refusal is the body of any other KMS answer, and of a CDS refusal to the pod.
type Refusal struct {
	Error string `json:"error"`
}

// ValidSecretName holds a secret name to 1 to 128 characters of
// [A-Za-z0-9._-], never "." or "..": the guest uses it as a file name.
func ValidSecretName(name string) error {
	if name == "" || len(name) > maxSecretName || name == "." || name == ".." {
		return fmt.Errorf("invalid secret name")
	}
	for _, c := range []byte(name) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return fmt.Errorf("invalid secret name")
		}
	}
	return nil
}

// NewStatement returns the encoded statement for one request.
func NewStatement(pod string, workload *Workload, clientDocumentDigest []byte, secret string, now time.Time) ([]byte, error) {
	if err := ValidSecretName(secret); err != nil {
		return nil, err
	}
	if len(clientDocumentDigest) != sha256.Size {
		return nil, fmt.Errorf("client document digest must be SHA-256")
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return json.Marshal(Statement{
		Version: StatementVersion, Pod: pod, Workload: workload,
		ClientDocumentDigest: hex.EncodeToString(clientDocumentDigest),
		Secret:               secret, IssuedAt: now.UTC().Truncate(time.Second), Nonce: nonce,
	})
}

// SignStatement signs statement with a broker key: ECDSA over
// SHA-256("c8s-secret-statement/v1" || 0x00 || statement), ASN.1 encoded.
func SignStatement(key *ecdsa.PrivateKey, statement []byte) ([]byte, error) {
	digest := statementDigest(statement)
	return ecdsa.SignASN1(rand.Reader, key, digest[:])
}

func statementDigest(statement []byte) [sha256.Size]byte {
	return sha256.Sum256(append([]byte(statementDomain), statement...))
}

// Verifier is the KMS side of a release request. MeshCAKey is SHA-256 of
// the DER SubjectPublicKeyInfo of the CDS mesh CA the KMS trusts.
type Verifier struct {
	MeshCAKey [sha256.Size]byte
	Now       func() time.Time
}

// Verify authenticates req as a statement by a broker of the pinned CDS and
// returns it. It checks the broker chain, the statement signature, that the
// client document hashes to the stated digest and that the statement is
// current. It does not remember nonces: a KMS that must refuse a replay
// within MaxStatementAge keeps them.
func (v Verifier) Verify(req ReleaseRequest) (Statement, error) {
	if req.Version != ReleaseVersion {
		return Statement{}, fmt.Errorf("unsupported release version %q", req.Version)
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	broker, err := v.verifyChain(req.BrokerChain, now)
	if err != nil {
		return Statement{}, err
	}
	pub, ok := broker.PublicKey.(*ecdsa.PublicKey)
	digest := statementDigest(req.Statement)
	if !ok || !ecdsa.VerifyASN1(pub, digest[:], req.Signature) {
		return Statement{}, errors.New("statement signature does not verify under the broker key")
	}
	var s Statement
	dec := json.NewDecoder(bytes.NewReader(req.Statement))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil || dec.More() {
		return Statement{}, errors.New("malformed statement")
	}
	if s.Version != StatementVersion {
		return Statement{}, fmt.Errorf("unsupported statement version %q", s.Version)
	}
	if err := ValidSecretName(s.Secret); err != nil {
		return Statement{}, err
	}
	if len(s.Nonce) != NonceSize || s.Pod == "" {
		return Statement{}, errors.New("statement lacks a pod or a nonce")
	}
	docDigest := sha256.Sum256(req.ClientDocument)
	if s.ClientDocumentDigest != hex.EncodeToString(docDigest[:]) {
		return Statement{}, errors.New("client document does not match the stated digest")
	}
	if age := now.Sub(s.IssuedAt); age > MaxStatementAge || age < -MaxStatementAge {
		return Statement{}, errors.New("statement is not current")
	}
	return s, nil
}

// verifyChain requires exactly [broker, mesh CA]: the CA by its pinned key,
// the broker signed by it, valid now and carrying the broker key usage.
func (v Verifier) verifyChain(chain [][]byte, now time.Time) (*x509.Certificate, error) {
	if len(chain) != 2 {
		return nil, errors.New("broker chain must be the broker and the mesh CA certificate")
	}
	broker, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("broker certificate: %w", err)
	}
	ca, err := x509.ParseCertificate(chain[1])
	if err != nil {
		return nil, fmt.Errorf("mesh CA certificate: %w", err)
	}
	if sha256.Sum256(ca.RawSubjectPublicKeyInfo) != v.MeshCAKey {
		return nil, errors.New("broker chain is not under the pinned mesh CA key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := broker.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("broker certificate: %w", err)
	}
	if !armtls.IsCDSBroker(broker) {
		return nil, errors.New("certificate is not a CDS broker certificate")
	}
	return broker, nil
}
