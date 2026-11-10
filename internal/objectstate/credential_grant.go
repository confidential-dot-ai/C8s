package objectstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
)

const (
	CredentialsPath         = "/object-state/recovery/credentials"
	MaxCredentialGrantBytes = 64 << 10
	maxCredentialCiphertext = 32 << 10
)

// CredentialGrant is independently signed and encrypted for one incarnation.
// Its cryptographic domains cannot authorize the one-shot recovery-key grant.
type CredentialGrant RecoveryGrant

func (g CredentialGrant) Check() error {
	if len(g.RequestHash) != sha512.Size384 || len(g.KEM) != overenc.XWingCTBytes ||
		g.Record.Seq != 1 || len(g.Record.CT) < 16 || len(g.Record.CT) > maxCredentialCiphertext ||
		len(g.Signature) != ed25519.SignatureSize {
		return errors.New("object state: malformed credential grant")
	}
	return nil
}

// OpenCredentials does not consume or reset the state-key recipient. The
// control actor installs its result through CredentialProvider's expiration floor.
func (r *Recipient) OpenCredentials(
	grant CredentialGrant,
	authority ed25519.PublicKey,
) (TemporaryCredentials, error) {
	if err := grant.Check(); err != nil {
		return TemporaryCredentials{}, err
	}
	if len(authority) != ed25519.PublicKeySize ||
		!bytes.Equal(
			grant.RequestHash,
			r.request.Digest(),
		) ||
		!ed25519.Verify(
			authority,
			credentialSignedBytes(grant),
			grant.Signature,
		) {
		return TemporaryCredentials{}, errors.New("object state: credential recipient or authority mismatch")
	}
	shared, err := r.key.Decapsulate(grant.KEM)
	if err != nil {
		return TemporaryCredentials{}, err
	}
	defer clear(shared)
	channel, err := overenc.NewClientChannel(
		shared,
		credentialTranscript(grant),
		r.request.Nonce,
	)
	if err != nil {
		return TemporaryCredentials{}, err
	}
	plaintext, err := channel.OpenResponse(
		grant.Record,
		1,
	)
	if err != nil {
		return TemporaryCredentials{}, errors.New("object state: invalid encrypted credentials")
	}
	defer clear(plaintext)
	var credentials TemporaryCredentials
	if err := decodeRecovery(
		plaintext,
		&credentials,
	); err != nil {
		return TemporaryCredentials{}, errors.New("object state: invalid credential payload")
	}
	if err := credentials.Check(time.Now()); err != nil {
		return TemporaryCredentials{}, err
	}
	return credentials, nil
}

func credentialTranscript(grant CredentialGrant) []byte {
	hash := sha512.New384()
	hash.Write([]byte("c8s/object-state/v1/credential-channel\x00"))
	hash.Write(grant.RequestHash)
	hash.Write(grant.KEM)
	return hash.Sum(nil)
}

func credentialSignedBytes(grant CredentialGrant) []byte {
	grant.Signature = nil
	body, _ := json.Marshal(grant)
	return append(
		[]byte("c8s/object-state/v1/credential-grant\x00"),
		body...,
	)
}

func sealCredentials(
	request RecoveryRequest,
	credentials TemporaryCredentials,
	signer ed25519.PrivateKey,
) (*CredentialGrant, error) {
	if err := request.Check(); err != nil {
		return nil, err
	}
	if err := checkRecoverySigner(signer); err != nil {
		return nil, err
	}
	if err := credentials.Check(time.Now()); err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(credentials)
	if err != nil || len(plaintext) > maxCredentialCiphertext-16 {
		clear(plaintext)
		return nil, errors.New("object state: credential payload exceeds its bound")
	}
	defer clear(plaintext)
	kem, shared, err := overenc.Encapsulate(request.PublicKey)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	grant := CredentialGrant{
		RequestHash: request.Digest(),
		KEM:         kem,
	}
	channel, err := overenc.NewServerChannel(
		shared,
		credentialTranscript(grant),
		request.Nonce,
	)
	if err != nil {
		return nil, err
	}
	grant.Record, err = channel.SealResponse(
		plaintext,
		1,
	)
	if err != nil {
		return nil, err
	}
	grant.Signature = ed25519.Sign(
		signer,
		credentialSignedBytes(grant),
	)
	return &grant, nil
}

// ReleaseCredentials repeats native recipient verification and fresh policy
// checks. Issuing and renewing the temporary session is the custodian's job.
func ReleaseCredentials(
	ctx context.Context,
	expected RecoveryIdentity,
	origin string,
	source RecoveryPolicySource,
	credentials TemporaryCredentials,
	signer ed25519.PrivateKey,
) (*CredentialGrant, error) {
	return releaseCredentials(
		ctx,
		expected,
		origin,
		source,
		credentials,
		signer,
		fetchRecoveryRecipient,
	)
}

func releaseCredentials(
	ctx context.Context,
	expected RecoveryIdentity,
	origin string,
	source RecoveryPolicySource,
	credentials TemporaryCredentials,
	signer ed25519.PrivateKey,
	fetch recoveryRecipientFetcher,
) (*CredentialGrant, error) {
	if err := checkRecoverySigner(signer); err != nil {
		return nil, err
	}
	if err := credentials.Check(time.Now()); err != nil {
		return nil, err
	}
	request, err := authorizeRecoveryRecipient(
		ctx,
		expected,
		origin,
		source,
		fetch,
	)
	if err != nil {
		return nil, err
	}
	return sealCredentials(
		request,
		credentials,
		signer,
	)
}
