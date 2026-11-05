//go:build linux

package snpaccept

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsrecovery"
)

// CustodyCopy protects the existing authority and capsule wrapping key under
// another chip's root. It adds neither a policy nor a commit point. The image
// can only delegate to its exact approved CDS launch, whose WALAuthority still
// checks the committed policy before every CDS key release. Possession of this
// copy is not evidence of freshness or of retirement of a custody image.
type CustodyCopy struct {
	Version    int        `json:"version"`
	Parameters Parameters `json:"parameters"`
	Ciphertext []byte     `json:"ciphertext"`
}

func copyCipher(root, launch []byte) (cipher.AEAD, []byte, error) {
	if len(root) != 32 {
		return nil, nil, errors.New("hardware root required for custody copy")
	}
	hash := sha256.Sum256(launch)
	key, err := hkdf.Key(sha256.New, root, hash[:], "c8s/cds-snp-acceptance/custody-copy/v1", 32)
	if err != nil {
		return nil, nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	return aead, hash[:], err
}

func copyContext(launchHash []byte, p Parameters) []byte {
	b, _ := json.Marshal(p)
	return append(append([]byte("c8s/cds-snp-acceptance/custody-copy/v1\x00"), launchHash...), b...)
}

func sealCopy(root, launch []byte, p Parameters, signer ed25519.PrivateKey, wrap []byte) (*CustodyCopy, error) {
	if len(signer) != ed25519.PrivateKeySize || len(wrap) != 32 {
		return nil, errors.New("existing custody material required")
	}
	aead, hash, err := copyCipher(root, launch)
	if err != nil {
		return nil, err
	}
	material := make([]byte, 64)
	defer clear(material)
	copy(material, signer[:ed25519.SeedSize])
	copy(material[ed25519.SeedSize:], wrap)
	return &CustodyCopy{Version: 1, Parameters: p, Ciphertext: aead.Seal(nil, nil, material, copyContext(hash, p))}, nil
}

func openCopy(root, launch []byte, c CustodyCopy, authority ed25519.PublicKey) (ed25519.PrivateKey, []byte, error) {
	aead, hash, err := copyCipher(root, launch)
	if err != nil {
		return nil, nil, err
	}
	if c.Version != 1 || len(c.Ciphertext) != 64+aead.Overhead() || len(authority) != ed25519.PublicKeySize {
		return nil, nil, errors.New("invalid bounded custody copy")
	}
	material, err := aead.Open(nil, nil, c.Ciphertext, copyContext(hash, c.Parameters))
	if err != nil {
		return nil, nil, errors.New("custody copy hardware or launch binding refused")
	}
	defer clear(material)
	signer := ed25519.NewKeyFromSeed(material[:ed25519.SeedSize])
	if !bytes.Equal(signer.Public().(ed25519.PublicKey), authority) {
		clear(signer)
		return nil, nil, errors.New("custody copy differs from measured recovery authority")
	}
	return signer, bytes.Clone(material[ed25519.SeedSize:]), nil
}

func (h *Hardware) copyAuthority() (ed25519.PublicKey, string, error) {
	config, err := cdsconfig.Parse(h.Launch)
	if err != nil || config.HA == nil || config.HA.ObjectWALPilot == nil {
		return nil, "", errors.New("measured recovery authority required")
	}
	w := config.HA.ObjectWALPilot
	public, err := cdsrecovery.ParseAuthority(w.RecoveryAuthority)
	return public, w.Prefix, err
}

// EnrollCopy receives custody only through the existing recipient-bound,
// signed encrypted channel. The host cannot supply plaintext key material.
// Only ciphertext and an attested public receipt leave this guest.
func (h *Hardware) EnrollCopy(ctx context.Context, relay *Relay) (*CustodyCopy, *DerivationIdentity, error) {
	public, prefix, err := h.copyAuthority()
	if err != nil {
		return nil, nil, err
	}
	recipient, request, err := NewCustodyRecipient(ctx, h)
	if err != nil {
		return nil, nil, err
	}
	b, err := json.Marshal(request)
	if err != nil {
		return nil, nil, err
	}
	response, err := relay.Exchange(ctx, StorageRequest{Method: "CUSTODY", Path: "/pilot/" + prefix + "/custody", Data: b})
	if err != nil {
		return nil, nil, err
	}
	if response.Status != 200 || len(response.Data) > 16<<10 {
		return nil, nil, errors.New("attested custody copy transfer refused")
	}
	var grant CustodyGrant
	if err := json.Unmarshal(response.Data, &grant); err != nil {
		return nil, nil, err
	}
	signer, wrap, err := recipient.Open(grant, public)
	if err != nil {
		return nil, nil, err
	}
	defer clear(signer)
	defer clear(wrap)
	p := Parameters{h.ReportInfo.GuestSvn, h.ReportInfo.CommittedTcb}
	root, err := h.root(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	defer clear(root)
	c, err := sealCopy(root, h.Launch, p, signer, wrap)
	if err != nil {
		return nil, nil, err
	}
	identity, err := h.CopyIdentity(ctx, *c)
	return c, identity, err
}

func (h *Hardware) copyMaterial(ctx context.Context, c CustodyCopy) (ed25519.PrivateKey, []byte, error) {
	public, _, err := h.copyAuthority()
	if err != nil {
		return nil, nil, err
	}
	if c.Version != 1 || len(c.Ciphertext) != 92 {
		return nil, nil, errors.New("invalid bounded custody copy")
	}
	root, err := h.root(ctx, c.Parameters)
	if err != nil {
		return nil, nil, err
	}
	defer clear(root)
	return openCopy(root, h.Launch, c, public)
}

func (h *Hardware) CopyIdentity(ctx context.Context, c CustodyCopy) (*DerivationIdentity, error) {
	signer, wrap, err := h.copyMaterial(ctx, c)
	if err != nil {
		return nil, err
	}
	defer clear(signer)
	defer clear(wrap)
	identity, err := h.PublicIdentity(ctx, c.Parameters)
	if err != nil {
		return nil, err
	}
	// The root is this chip's, but the recovered authority is the original
	// enrolled authority pinned in this guest's measured launch.
	identity.AuthorityPublic = identity.ExpectedAuthority
	return identity, nil
}

func (h *Hardware) DelegateCopy(ctx context.Context, c CustodyCopy, q *CustodyRequest, collateral Collateral) (*CustodyGrant, error) {
	if err := checkCustodyRequest(q); err != nil {
		return nil, err
	}
	signer, wrap, err := h.copyMaterial(ctx, c)
	if err != nil {
		return nil, err
	}
	defer clear(signer)
	defer clear(wrap)
	return h.delegateMaterial(ctx, signer, wrap, q, collateral)
}
