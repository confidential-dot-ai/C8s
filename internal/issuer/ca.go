package issuer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// MeshCA holds one mesh CA key for the lifetime of the process and publishes
// exactly one certificate issued under it.
type MeshCA struct {
	commonName string
	validity   time.Duration
	key        *ecdsa.PrivateKey

	// renew serializes minting and publishing, so two renewals cannot
	// interleave and leave the older certificate current.
	renew   sync.Mutex
	current atomic.Pointer[CurrentCA]
}

// CurrentCA is the published certificate: the CA that signs leaves under it
// and its PEM encoding for distribution.
type CurrentCA struct {
	CA      *CA
	CertPEM []byte
}

// NewMeshCA generates the process's mesh CA key and publishes a first
// certificate under it.
func NewMeshCA(commonName string, validity time.Duration) (*MeshCA, error) {
	if commonName == "" {
		return nil, fmt.Errorf("mesh ca: common name is required")
	}
	if validity <= 0 {
		return nil, fmt.Errorf("mesh ca: validity must be positive, got %v", validity)
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate mesh ca key: %w", err)
	}

	mesh := &MeshCA{
		commonName: commonName,
		validity:   validity,
		key:        key,
	}
	if _, err := mesh.RenewCertificate(); err != nil {
		return nil, err
	}
	return mesh, nil
}

// Current reads the published certificate; one read serves a whole issuance.
func (m *MeshCA) Current() CurrentCA {
	return *m.current.Load()
}

// RenewCertificate self-signs a new certificate under the retained key and
// publishes it. It refuses one whose subject or subject key identifier differs
// from the certificate it replaces, because leaves issued under that one are
// matched to their issuer by both.
func (m *MeshCA) RenewCertificate() (CurrentCA, error) {
	m.renew.Lock()
	defer m.renew.Unlock()

	serial, err := certutil.GenerateSerial()
	if err != nil {
		return CurrentCA{}, fmt.Errorf("generate mesh ca serial: %w", err)
	}
	tmpl := certutil.NewCATemplate(serial, m.commonName, time.Now().Add(m.validity))
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &m.key.PublicKey, m.key)
	if err != nil {
		return CurrentCA{}, fmt.Errorf("self-sign mesh ca: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return CurrentCA{}, fmt.Errorf("parse freshly-signed mesh ca: %w", err)
	}
	if outgoing := m.current.Load(); outgoing != nil {
		if err := sameIssuerIdentity(outgoing.CA.Cert, cert); err != nil {
			return CurrentCA{}, err
		}
	}

	renewed := &CurrentCA{
		CA: &CA{
			Cert: cert,
			Key:  m.key,
		},
		CertPEM: certutil.EncodeCertPEM(certDER),
	}
	m.current.Store(renewed)
	return *renewed, nil
}

// sameIssuerIdentity reports whether a renewed CA certificate still names the
// issuer that live leaves were signed by.
func sameIssuerIdentity(outgoing, renewed *x509.Certificate) error {
	if !bytes.Equal(outgoing.RawSubject, renewed.RawSubject) {
		return fmt.Errorf("renewed mesh ca changed its subject")
	}
	if !bytes.Equal(outgoing.SubjectKeyId, renewed.SubjectKeyId) {
		return fmt.Errorf("renewed mesh ca changed its subject key identifier")
	}
	return nil
}
