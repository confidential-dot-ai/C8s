package routing

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/credvolume"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// MeshCredential is one credential generation as a backend connection uses
// it: the leaf the router presents and the mesh CAs published with it.
type MeshCredential struct {
	Certificate *tls.Certificate
	MeshCAs     []*x509.Certificate
}

// CredentialSource returns the router's mesh credential. It is called on every
// backend dial and handshake, so a published generation takes effect without a
// restart.
type CredentialSource func() (MeshCredential, error)

// MeshIdentity is the router's own mesh identity, read from the credential
// volume get-cert publishes on. Each read resolves the generation pointer once,
// so the leaf a handshake presents and the mesh CAs it trusts are the ones
// published together. It is safe for concurrent use.
type MeshIdentity struct {
	volume credvolume.Volume
}

// NewMeshIdentity names the credential volume the three reader paths lie on.
// It reads nothing, so a router comes up before get-cert has published and
// while CDS is down; each credential is resolved when a connection needs one.
func NewMeshIdentity(certFile, keyFile, caFile string) (*MeshIdentity, error) {
	volume, err := credvolume.For(certFile, keyFile, caFile)
	if err != nil {
		return nil, err
	}
	return &MeshIdentity{volume: volume}, nil
}

func (m *MeshIdentity) read() (MeshCredential, error) {
	set, err := m.volume.Read()
	if err != nil {
		return MeshCredential{}, err
	}
	pair, err := tls.X509KeyPair(set.ChainPEM, set.KeyPEM)
	if err != nil {
		return MeshCredential{}, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return MeshCredential{}, fmt.Errorf("parse client leaf: %w", err)
	}
	pair.Leaf = leaf
	cas, err := certutil.ParsePEMCertificates(set.CAPEM)
	if err != nil {
		return MeshCredential{}, fmt.Errorf("mesh CA bundle: %w", err)
	}
	return MeshCredential{Certificate: &pair, MeshCAs: cas}, nil
}

// Credential implements CredentialSource. It never hands a handshake a
// credential whose leaf is outside its validity window, and a withdrawn
// pointer or a generation it refuses leaves it with nothing.
func (m *MeshIdentity) Credential() (MeshCredential, error) {
	cred, err := m.read()
	if err != nil {
		return MeshCredential{}, fmt.Errorf("mesh credential: %w", err)
	}
	if err := certutil.CheckValidity(cred.Certificate.Leaf, time.Now()); err != nil {
		return MeshCredential{}, fmt.Errorf("mesh credential: %w", err)
	}
	return cred, nil
}

// MeshCAs implements CASource from the published generation.
func (m *MeshIdentity) MeshCAs() ([]*x509.Certificate, error) {
	cred, err := m.Credential()
	if err != nil {
		return nil, err
	}
	return cred.MeshCAs, nil
}

// PointerPath is where this identity resolves the generation pointer.
func (m *MeshIdentity) PointerPath() string {
	return m.volume.PointerPath()
}
