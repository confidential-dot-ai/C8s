package objectstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
)

func testCredentialGrant(
	t *testing.T,
	recipient *Recipient,
	credentials TemporaryCredentials,
	signer ed25519.PrivateKey,
) CredentialGrant {
	t.Helper()
	grant, err := sealCredentials(
		recipient.Request(),
		credentials,
		signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	return *grant
}

func TestCredentialGrantsPreserveOneShotRecoveryAndBindIncarnation(t *testing.T) {
	identity, signer, material := recoveryFixture(t)
	authority := signer.Public().(ed25519.PublicKey)
	recipient := testRecoveryRecipient(
		t,
		identity,
	)
	credentials := testCredentials(time.Now().Add(15 * time.Minute))
	grant := testCredentialGrant(
		t,
		recipient,
		credentials,
		signer,
	)
	stateGrant := testRecoveryGrant(
		t,
		recipient,
		material,
		signer,
	)
	if _, err := recipient.Open(
		RecoveryGrant(grant),
		authority,
	); err == nil {
		t.Fatal("credential grant was accepted as state recovery")
	}
	if _, err := recipient.OpenCredentials(
		CredentialGrant(stateGrant),
		authority,
	); err == nil {
		t.Fatal("state grant was accepted as credentials")
	}
	transplant := CredentialGrant(stateGrant)
	transplant.Signature = ed25519.Sign(
		signer,
		credentialSignedBytes(transplant),
	)
	if _, err := recipient.OpenCredentials(
		transplant,
		authority,
	); err == nil {
		t.Fatal("credential signature domain bypassed the distinct encryption domain")
	}
	other := testRecoveryRecipient(
		t,
		identity,
	)
	if _, err := other.OpenCredentials(
		grant,
		authority,
	); err == nil {
		t.Fatal("credentials were released to another incarnation")
	}
	wrongAuthority, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recipient.OpenCredentials(
		grant,
		wrongAuthority,
	); err == nil {
		t.Fatal("credentials were accepted from another authority")
	}
	opened, err := recipient.OpenCredentials(
		grant,
		authority,
	)
	if err != nil || opened.AccessKeyID != credentials.AccessKeyID || !opened.ExpiresAt.Equal(credentials.ExpiresAt) {
		t.Fatal("valid credentials did not open")
	}
	recovered, err := recipient.Open(
		stateGrant,
		authority,
	)
	if err != nil || !bytes.Equal(
		recovered.Key,
		material.Key,
	) {
		t.Fatal("credential issuance consumed the state-key grant")
	}
	clear(recovered.Key)
	renewed := testCredentials(credentials.ExpiresAt.Add(15 * time.Minute))
	renewed.AccessKeyID = "renewed-access"
	second := testCredentialGrant(
		t,
		recipient,
		renewed,
		signer,
	)
	if bytes.Equal(
		second.KEM,
		grant.KEM,
	) {
		t.Fatal("credential renewal reused an encapsulation")
	}
	opened, err = recipient.OpenCredentials(
		second,
		authority,
	)
	if err != nil || opened.AccessKeyID != renewed.AccessKeyID {
		t.Fatal("state-key consumption prevented credential renewal")
	}
	if _, err := recipient.Open(
		stateGrant,
		authority,
	); !errors.Is(
		err,
		ErrRecipientUsed,
	) {
		t.Fatal("credential renewal restored state-key permission")
	}
}

func TestCredentialGrantRejectsTamperingAndOversize(t *testing.T) {
	identity, signer, _ := recoveryFixture(t)
	authority := signer.Public().(ed25519.PublicKey)
	for name, change := range map[string]func(*CredentialGrant){
		"signature": func(g *CredentialGrant) { g.Signature[0] ^= 1 },
		"recipient": func(g *CredentialGrant) { g.RequestHash[0] ^= 1 },
		"encapsulation": func(g *CredentialGrant) {
			g.KEM[0] ^= 1
			g.Signature = ed25519.Sign(
				signer,
				credentialSignedBytes(*g),
			)
		},
		"ciphertext": func(g *CredentialGrant) {
			g.Record.CT[0] ^= 1
			g.Signature = ed25519.Sign(
				signer,
				credentialSignedBytes(*g),
			)
		},
		"sequence": func(g *CredentialGrant) { g.Record.Seq++ },
		"oversize": func(g *CredentialGrant) {
			g.Record.CT = make(
				[]byte,
				maxCredentialCiphertext+1,
			)
		},
	} {
		t.Run(
			name,
			func(t *testing.T) {
				recipient := testRecoveryRecipient(
					t,
					identity,
				)
				credentials := testCredentials(time.Now().Add(15 * time.Minute))
				bad := testCredentialGrant(
					t,
					recipient,
					credentials,
					signer,
				)
				change(&bad)
				if _, err := recipient.OpenCredentials(
					bad,
					authority,
				); err == nil {
					t.Fatal("modified credentials were accepted")
				}
				good := testCredentialGrant(
					t,
					recipient,
					credentials,
					signer,
				)
				if _, err := recipient.OpenCredentials(
					good,
					authority,
				); err != nil {
					t.Fatal("invalid grant prevented a valid renewal")
				}
			},
		)
	}
}

func testCredentialPayload(
	t *testing.T,
	recipient *Recipient,
	payload any,
	signer ed25519.PrivateKey,
) CredentialGrant {
	t.Helper()
	request := recipient.Request()
	kem, shared, err := overenc.Encapsulate(request.PublicKey)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	grant.Record, err = channel.SealResponse(
		plain,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	grant.Signature = ed25519.Sign(
		signer,
		credentialSignedBytes(grant),
	)
	return grant
}

func TestCredentialPayloadCannotCarryStateAuthority(t *testing.T) {
	identity, signer, _ := recoveryFixture(t)
	recipient := testRecoveryRecipient(
		t,
		identity,
	)
	valid := testCredentials(time.Now().Add(15 * time.Minute))
	for _, extra := range []string{
		"key",
		"allow_initialize",
	} {
		payload := map[string]any{
			"access_key_id":     valid.AccessKeyID,
			"secret_access_key": valid.SecretAccessKey,
			"session_token":     valid.SessionToken,
			"expires_at":        valid.ExpiresAt,
			extra:               true,
		}
		grant := testCredentialPayload(
			t,
			recipient,
			payload,
			signer,
		)
		if _, err := recipient.OpenCredentials(
			grant,
			signer.Public().(ed25519.PublicKey),
		); err == nil {
			t.Fatal("credential payload accepted state-key or initialization authority")
		}
	}
	expired := valid
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	grant := testCredentialPayload(
		t,
		recipient,
		expired,
		signer,
	)
	if _, err := recipient.OpenCredentials(
		grant,
		signer.Public().(ed25519.PublicKey),
	); err == nil {
		t.Fatal("expired signed credentials were opened")
	}
	request := recipient.Request()
	request.Identity.ClusterID = "different-cluster"
	rebound, err := sealCredentials(
		request,
		valid,
		signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recipient.OpenCredentials(
		*rebound,
		signer.Public().(ed25519.PublicKey),
	); err == nil {
		t.Fatal("same recipient key accepted credentials under a different identity")
	}
}

func TestCredentialReleaseChecksCurrentPolicyAfterAttestation(t *testing.T) {
	for _, name := range []string{
		"stable",
		"changed",
		"unreadable",
		"canceled",
	} {
		t.Run(
			name,
			func(t *testing.T) {
				identity, signer, _ := recoveryFixture(t)
				policy := testRecoveryPolicy(&identity)
				recipient := testRecoveryRecipient(
					t,
					identity,
				)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				reads, fetched := 0, false
				source := recoveryPolicyFunc(func(context.Context) (RecoveryPolicy, error) {
					reads++
					if reads == 2 {
						if !fetched {
							t.Fatal("final policy read did not follow attestation")
						}
						switch name {
						case "changed":
							policy.Revision = "new-policy"
						case "unreadable":
							return RecoveryPolicy{}, ErrNotFound
						case "canceled":
							cancel()
						}
					}
					return policy, nil
				})
				grant, err := releaseCredentials(
					ctx,
					identity,
					"https://cds.example",
					source,
					testCredentials(time.Now().Add(15*time.Minute)),
					signer,
					func(
						context.Context,
						RecoveryIdentity,
						string,
						RecoveryPolicy,
					) (RecoveryRequest, error) {
						fetched = true
						return recipient.Request(), nil
					},
				)
				if reads != 2 || !fetched {
					t.Fatal("credential issuance skipped fresh recipient or policy verification")
				}
				if name != "stable" {
					if grant != nil || err == nil {
						t.Fatal("credential release ignored changed or unavailable policy")
					}
					return
				}
				if err != nil || grant == nil {
					t.Fatal("stable policy failed credential issuance")
				}
				if _, err := recipient.OpenCredentials(
					*grant,
					signer.Public().(ed25519.PublicKey),
				); err != nil {
					t.Fatal(err)
				}
			},
		)
	}
}

func TestMissingStatePreventsCredentialAndKeyRelease(t *testing.T) {
	identity, signer, material := recoveryFixture(t)
	fetched := false
	source := recoveryPolicyFunc(func(context.Context) (RecoveryPolicy, error) {
		return RecoveryPolicy{}, ErrNotFound
	})
	fetch := func(
		context.Context,
		RecoveryIdentity,
		string,
		RecoveryPolicy,
	) (RecoveryRequest, error) {
		fetched = true
		return RecoveryRequest{}, nil
	}
	credentialGrant, credentialErr := releaseCredentials(
		t.Context(),
		identity,
		"https://cds.example",
		source,
		testCredentials(time.Now().Add(15*time.Minute)),
		signer,
		fetch,
	)
	stateGrant, stateErr := releaseRecovery(
		t.Context(),
		identity,
		"https://cds.example",
		source,
		material,
		signer,
		fetch,
	)
	if credentialGrant != nil || stateGrant != nil || fetched ||
		!errors.Is(
			credentialErr,
			ErrNotFound,
		) || !errors.Is(
		stateErr,
		ErrNotFound,
	) {
		t.Fatal("missing current state allowed credential or state-key release")
	}
}
