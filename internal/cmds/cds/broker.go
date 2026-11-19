package cds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/secretbroker"
)

// brokerCertTTL is the lifetime of a broker certificate. One is reissued when
// half of it has passed or the mesh CA certificate changed.
const brokerCertTTL = time.Hour

// meshCA is the CA a CDS issues under; the second answer reports whether it
// may issue now.
type meshCA interface {
	Current() (issuer.CurrentCA, bool)
}

// ownCA is the mesh CA a CDS mints at its start, which it always issues under.
type ownCA struct {
	*issuer.MeshCA
}

func (o ownCA) Current() (issuer.CurrentCA, bool) {
	return o.MeshCA.Current(), true
}

// secretBroker holds this replica's broker key, generated in memory at start
// and never shared with another replica, and the certificate the mesh CA
// issued it. A KMS trusts a statement because that certificate chains to the
// mesh CA key it pinned (docs/pod-secrets.md).
type secretBroker struct {
	key  *ecdsa.PrivateKey
	mesh meshCA

	mu      sync.Mutex
	chain   [][]byte
	renewAt time.Time
}

func newSecretBroker(mesh meshCA) (*secretBroker, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate broker key: %w", err)
	}
	return &secretBroker{key: key, mesh: mesh}, nil
}

// sign returns the signature over statement and the broker chain, broker
// certificate first and the mesh CA certificate it was issued under last.
func (b *secretBroker) sign(statement []byte) ([]byte, [][]byte, error) {
	chain, err := b.currentChain(time.Now())
	if err != nil {
		return nil, nil, err
	}
	signature, err := secretbroker.SignStatement(b.key, statement)
	if err != nil {
		return nil, nil, err
	}
	return signature, chain, nil
}

func (b *secretBroker) currentChain(now time.Time) ([][]byte, error) {
	signing, issuing := b.mesh.Current()
	if !issuing {
		return nil, fmt.Errorf("this CDS holds no mesh CA to certify its broker key")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.chain != nil && now.Before(b.renewAt) && string(b.chain[1]) == string(signing.CA.Cert.Raw) {
		return b.chain, nil
	}
	der, err := signing.CA.SignBroker(&b.key.PublicKey, brokerCertTTL)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	b.chain = [][]byte{der, signing.CA.Cert.Raw}
	b.renewAt = cert.NotBefore.Add(brokerCertTTL / 2)
	return b.chain, nil
}
