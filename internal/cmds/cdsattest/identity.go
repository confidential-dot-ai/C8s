package cdsattest

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

type meshIdentity struct {
	leaf      *x509.Certificate
	ca        *x509.Certificate
	private   *ecdsa.PrivateKey
	bundlePEM []byte
}

// loadMeshIdentity reads all three files for every attestation request so a
// get-cert rotation is observed without restarting the sidecar. A transient
// rotation mismatch or an expired credential fails this request closed; the
// next request can retry after the three files converge on one valid
// credential generation.
func loadMeshIdentity(certFile, keyFile, caFile string) (*meshIdentity, error) {
	if certFile == "" || keyFile == "" || caFile == "" {
		return nil, fmt.Errorf("mesh identity cert, key, and CA files are required")
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read mesh identity cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read mesh identity key: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read mesh identity CA: %w", err)
	}
	return parseMeshIdentity(certPEM, keyPEM, caPEM)
}

// parseMeshIdentity validates one credential generation. X509KeyPair verifies
// that the private key matches the leaf.
func parseMeshIdentity(certPEM, keyPEM, caPEM []byte) (*meshIdentity, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load mesh identity keypair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("mesh identity certificate file has no leaf")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse mesh identity leaf: %w", err)
	}
	private, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("mesh identity private key must be ECDSA, got %T", pair.PrivateKey)
	}
	// CheckSignatureFrom does not check validity periods; enforce them so a
	// failed rotation fails closed here instead of at the client.
	now := time.Now()
	if err := checkValidity(now, leaf, "leaf"); err != nil {
		return nil, err
	}

	caCerts, err := certutil.ParsePEMCertificates(caPEM)
	if err != nil {
		return nil, fmt.Errorf("parse mesh identity CA bundle: %w", err)
	}
	var issuer *x509.Certificate
	for _, candidate := range caCerts {
		if leaf.CheckSignatureFrom(candidate) == nil {
			issuer = candidate
			break
		}
	}
	if issuer == nil {
		return nil, fmt.Errorf("mesh identity leaf is not signed by any configured mesh CA")
	}
	if err := checkValidity(now, issuer, "CA"); err != nil {
		return nil, err
	}

	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw})...)
	return &meshIdentity{leaf: leaf, ca: issuer, private: private, bundlePEM: bundle}, nil
}

// checkValidity delegates to the repo-wide validity window
// (certutil.CheckValidity: bounded NotBefore skew, hard NotAfter), adding the
// role so a leaf failure reads differently from a CA failure.
func checkValidity(now time.Time, cert *x509.Certificate, role string) error {
	if err := certutil.CheckValidity(cert, now); err != nil {
		return fmt.Errorf("mesh identity %s: %w", role, err)
	}
	return nil
}

func (m *meshIdentity) bind(mode types.FrontDoorMode, xwingEK, xwingCT, sessionID, nonce, stateDigest []byte) ([]byte, *types.MeshIdentityProof, error) {
	transcriptHash, err := overenc.IdentityTranscriptHash(mode, xwingEK, xwingCT, sessionID, nonce, m.leaf.Raw, m.ca.Raw, stateDigest)
	if err != nil {
		return nil, nil, err
	}
	proof, err := m.prove(transcriptHash)
	if err != nil {
		return nil, nil, err
	}
	return transcriptHash, proof, nil
}

// bindServingLeaf is the attest-lb sibling of bind: it commits the exact outer
// serving leaf alongside the mesh identity and signs that transcript. No
// session key exists on this path — the TLS handshake itself proves possession
// of the serving-leaf key.
func (m *meshIdentity) bindServingLeaf(mode types.FrontDoorMode, servingLeafDER, nonce, stateDigest []byte) ([]byte, *types.MeshIdentityProof, error) {
	transcriptHash, err := overenc.LBTranscriptHash(mode, nonce, servingLeafDER, m.leaf.Raw, m.ca.Raw, stateDigest)
	if err != nil {
		return nil, nil, err
	}
	proof, err := m.prove(transcriptHash)
	if err != nil {
		return nil, nil, err
	}
	return transcriptHash, proof, nil
}

// prove signs a transcript hash with the mesh leaf key. The transcript's
// leading domain tag separates the two endpoints' signatures.
func (m *meshIdentity) prove(transcriptHash []byte) (*types.MeshIdentityProof, error) {
	digest := sha512.Sum384(transcriptHash)
	signature, err := ecdsa.SignASN1(rand.Reader, m.private, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign mesh identity proof: %w", err)
	}
	leafHash := sha256.Sum256(m.leaf.Raw)
	caHash := sha256.Sum256(m.ca.Raw)
	return &types.MeshIdentityProof{
		Algorithm:    types.MeshIdentityProofECDSASHA384,
		LeafSHA256:   base64.RawURLEncoding.EncodeToString(leafHash[:]),
		MeshCASHA256: base64.RawURLEncoding.EncodeToString(caHash[:]),
		Signature:    base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}
