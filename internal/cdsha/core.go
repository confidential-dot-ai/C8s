package cdsha

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

// Core is the cluster state every replica agrees on through the Raft log:
// the operator's authority, the replica pin set, and the mesh CA. Nothing
// here is ever written outside the attested replicas, so it needs no
// signature of its own; the log is its history.
type Core struct {
	ClusterID      string   `json:"cluster_id"`
	Epoch          uint64   `json:"epoch"` // decrees applied
	RootCert       []byte   `json:"root_cert,omitempty"`
	Measurements   []string `json:"measurements,omitempty"` // replica pin set, sorted lowercase hex
	OperatorPubKey []byte   `json:"operator_pubkey"`        // PKIX DER; nil means decrees are rejected
	AppliedDecrees []string `json:"applied_decrees,omitempty"`
	// GenesisAtMS is when the cluster was born. Single-use operator tokens
	// issued before it are refused: no replica can know whether they were
	// spent in an earlier life of the cluster.
	GenesisAtMS int64 `json:"genesis_at_ms,omitempty"`
}

// Joined reports whether the cluster has a mesh CA (Genesis applied).
func (c Core) Joined() bool { return len(c.RootCert) > 0 }

// Pins reports whether measurement is in the replica pin set.
func (c Core) Pins(measurement string) bool { return slices.Contains(c.Measurements, measurement) }

func (c Core) clone() Core {
	c.RootCert = slices.Clone(c.RootCert)
	c.Measurements = slices.Clone(c.Measurements)
	c.OperatorPubKey = slices.Clone(c.OperatorPubKey)
	c.AppliedDecrees = slices.Clone(c.AppliedDecrees)
	return c
}

// caFromDER rebuilds the mesh CA from its certificate and PKCS#8 key, and
// checks the two belong together.
func caFromDER(certDER, keyDER []byte) (*issuer.CA, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("mesh CA certificate: %w", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("mesh CA key: %w", err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("mesh CA key is not ECDSA")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("mesh CA key does not match its certificate")
	}
	return &issuer.CA{Cert: cert, Key: key}, nil
}
