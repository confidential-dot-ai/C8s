package objectstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func TestRecoveryRecipientRequiresNonMigratableAttestedPeer(t *testing.T) {
	identity, _, _ := recoveryFixture(t)
	recipient := testRecoveryRecipient(
		t,
		identity,
	)
	launch := []byte("fixed recipient launch")
	launchHash := sha256.Sum256(launch)
	digest := bytes.Repeat(
		[]byte{0x49},
		48,
	)
	for _, test := range []struct {
		name    string
		policy  any
		allowed bool
	}{
		{
			"fixed",
			map[string]any{"migrate_ma": false},
			true,
		},
		{
			"migratable",
			map[string]any{"migrate_ma": true},
			false,
		},
		{
			"missing",
			nil,
			false,
		},
		{
			"malformed",
			map[string]any{"migrate_ma": "false"},
			false,
		},
		{"invalid signature", map[string]any{"migrate_ma": false}, false},
		{"missing collateral", map[string]any{"migrate_ma": false}, false},
	} {
		t.Run(
			test.name,
			func(t *testing.T) {
				verdict := teetypes.VerificationResult{
					Platform: teetypes.PlatformSNP, SignatureValid: true, CollateralVerified: true,
					ReportDataMatch: teetypes.Ptr(true), InitDataMatch: teetypes.Ptr(true),
					Claims: teetypes.Claims{LaunchDigest: hex.EncodeToString(digest), InitData: launchHash[:]},
				}
				verdict.Claims.PlatformData = map[string]any{"policy": test.policy}
				verdict.SignatureValid = test.name != "invalid signature"
				verdict.CollateralVerified = test.name != "missing collateral"
				native, err := armtls.NewNativeVerifierWithEngine(teetypes.SnpTcb{Bootloader: 12, Snp: 28, Microcode: 28}, func(_ context.Context, _ teetypes.AttestationEvidence, params teetypes.VerifyParams, options teeverify.Options) (*teetypes.VerificationResult, error) {
					if len(params.ExpectedReportData) != 48 || !options.SNP.CheckRevocations || params.MinTCB == nil {
						t.Fatal("recipient lost strict native gates")
					}
					return &verdict, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				key, _, err := armtls.GenerateKeyPair()
				if err != nil {
					t.Fatal(err)
				}
				report := make([]byte, armtls.SNPReportSize)
				report[0x1f0], report[0x1f1], report[0x1f6], report[0x1f7] = 255, 255, 255, 255
				cert, err := armtls.CreateAttestedCert(
					key,
					&armtls.Attestation{
						Family: armtls.TEETypeSEVSNP,
						Report: report,
					},
					nil,
				)
				if err != nil {
					t.Fatal(err)
				}
				var requests atomic.Int32
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					requests.Add(1)
					if r.URL.Path != RequestPath {
						t.Error("unexpected recovery path")
					}
					_ = json.NewEncoder(w).Encode(recipient.Request())
				}))
				server.TLS = &tls.Config{
					MinVersion: tls.VersionTLS13,
					Certificates: []tls.Certificate{{
						Certificate: [][]byte{cert},
						PrivateKey:  key,
					}},
				}
				server.StartTLS()
				defer server.Close()
				request, err := fetchRecoveryRecipient(
					t.Context(),
					identity,
					server.URL,
					RecoveryPolicy{
						AttestationURL: "http://127.0.0.1:1",
						Native:         native,
						Images: []remote.ImagePin{{
							Name:       "recipient",
							Digest:     digest,
							LaunchFile: launch,
						}},
					},
				)
				if test.allowed {
					if err != nil || !bytes.Equal(
						request.Digest(),
						recipient.Request().Digest(),
					) || requests.Load() != 1 {
						t.Fatalf(
							"fixed recipient failed: %v",
							err,
						)
					}
				} else if err == nil || requests.Load() != 0 {
					t.Fatal("unproven or migratable peer received a recovery request")
				}
			},
		)
	}
}

func recoveryFixture(t *testing.T) (RecoveryIdentity, ed25519.PrivateKey, RecoveryMaterial) {
	t.Helper()
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return RecoveryIdentity{
		ClusterID: "cluster-one",
		StorageSHA256: strings.Repeat(
			"ab",
			32,
		),
		ConfigSHA256: strings.Repeat(
			"cd",
			32,
		),
	}, signer, RecoveryMaterial{Key: bytes.Repeat(
		[]byte{42},
		32,
	)}
}

func testRecoveryRecipient(
	t *testing.T,
	identity RecoveryIdentity,
) *Recipient {
	t.Helper()
	recipient, err := NewRecipient(identity)
	if err != nil {
		t.Fatal(err)
	}
	return recipient
}

func testRecoveryGrant(
	t *testing.T,
	recipient *Recipient,
	material RecoveryMaterial,
	signer ed25519.PrivateKey,
) RecoveryGrant {
	t.Helper()
	grant, err := sealRecovery(
		recipient.Request(),
		material,
		signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	return *grant
}

func TestRecoveryGrantBindsIncarnationIdentityAndAuthority(t *testing.T) {
	identity, signer, material := recoveryFixture(t)
	authority := signer.Public().(ed25519.PublicKey)
	recipient := testRecoveryRecipient(
		t,
		identity,
	)
	grant := testRecoveryGrant(
		t,
		recipient,
		material,
		signer,
	)
	for _, test := range []struct {
		name     string
		identity RecoveryIdentity
	}{
		{
			name:     "new incarnation",
			identity: identity,
		},
		{
			name: "different cluster",
			identity: RecoveryIdentity{
				ClusterID:     "cluster-two",
				StorageSHA256: identity.StorageSHA256,
				ConfigSHA256:  identity.ConfigSHA256,
			},
		},
		{
			name: "different storage",
			identity: RecoveryIdentity{
				ClusterID: identity.ClusterID,
				StorageSHA256: strings.Repeat(
					"ef",
					32,
				),
				ConfigSHA256: identity.ConfigSHA256,
			},
		},
		{
			name: "different launch",
			identity: RecoveryIdentity{
				ClusterID:     identity.ClusterID,
				StorageSHA256: identity.StorageSHA256,
				ConfigSHA256: strings.Repeat(
					"ef",
					32,
				),
			},
		},
	} {
		t.Run(
			test.name,
			func(t *testing.T) {
				other := testRecoveryRecipient(
					t,
					test.identity,
				)
				if _, err := other.Open(
					grant,
					authority,
				); err == nil {
					t.Fatal("released key across recipient boundary")
				}
				if test.identity != identity {
					request := recipient.Request()
					request.Identity = test.identity
					rebound, err := sealRecovery(
						request,
						material,
						signer,
					)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := recipient.Open(
						*rebound,
						authority,
					); err == nil {
						t.Fatal("accepted changed identity with the same recipient key and nonce")
					}
				}
			},
		)
	}
	otherAuthority, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recipient.Open(
		grant,
		otherAuthority,
	); err == nil {
		t.Fatal("accepted another authority")
	}
	requestCopy := recipient.Request()
	requestCopy.Nonce[0] ^= 1
	requestCopy.PublicKey[0] ^= 1
	requestCopy.Identity.ClusterID = "edited"
	opened, err := recipient.Open(
		grant,
		authority,
	)
	if err != nil || !bytes.Equal(
		opened.Key,
		material.Key,
	) {
		t.Fatalf(
			"valid recovery grant failed: %v",
			err,
		)
	}
	clear(opened.Key)
	if _, err := recipient.Open(
		grant,
		authority,
	); !errors.Is(
		err,
		ErrRecipientUsed,
	) {
		t.Fatalf(
			"reused recipient: %v",
			err,
		)
	}
}

func TestRecoveryGrantRejectsTamperingWithoutBurningRecipient(t *testing.T) {
	identity, signer, material := recoveryFixture(t)
	authority := signer.Public().(ed25519.PublicKey)
	for name, change := range map[string]func(*RecoveryGrant){
		"signature": func(grant *RecoveryGrant) { grant.Signature[0] ^= 1 },
		"request":   func(grant *RecoveryGrant) { grant.RequestHash[0] ^= 1 },
		"KEM":       func(grant *RecoveryGrant) { grant.KEM[0] ^= 1 },
		"ciphertext": func(grant *RecoveryGrant) {
			grant.Record.CT[0] ^= 1
			grant.Signature = ed25519.Sign(
				signer,
				recoverySignedBytes(*grant),
			)
		},
		"sequence": func(grant *RecoveryGrant) { grant.Record.Seq++ },
		"oversize": func(grant *RecoveryGrant) {
			grant.Record.CT = make(
				[]byte,
				257,
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
				bad := testRecoveryGrant(
					t,
					recipient,
					material,
					signer,
				)
				change(&bad)
				if _, err := recipient.Open(
					bad,
					authority,
				); err == nil {
					t.Fatal("accepted a modified grant")
				}
				good := testRecoveryGrant(
					t,
					recipient,
					material,
					signer,
				)
				opened, err := recipient.Open(
					good,
					authority,
				)
				if err != nil || !bytes.Equal(
					opened.Key,
					material.Key,
				) {
					t.Fatalf(
						"invalid grant burned the recipient: %v",
						err,
					)
				}
				clear(opened.Key)
			},
		)
	}
	first := testRecoveryRecipient(
		t,
		identity,
	)
	other := testRecoveryRecipient(
		t,
		identity,
	)
	transplant := testRecoveryGrant(
		t,
		first,
		material,
		signer,
	)
	transplant.RequestHash = other.Request().Digest()
	transplant.Signature = ed25519.Sign(
		signer,
		recoverySignedBytes(transplant),
	)
	if _, err := other.Open(
		transplant,
		authority,
	); err == nil {
		t.Fatal("accepted authority-signed ciphertext transplanted to another key")
	}
}

func TestRecoveryRecipientConcurrentOpenReturnsKeyOnce(t *testing.T) {
	identity, signer, material := recoveryFixture(t)
	recipient := testRecoveryRecipient(
		t,
		identity,
	)
	grant := testRecoveryGrant(
		t,
		recipient,
		material,
		signer,
	)
	var successes atomic.Int32
	var wait sync.WaitGroup
	start := make(chan struct{})
	for range 16 {
		wait.Go(func() {
			<-start
			opened, err := recipient.Open(
				grant,
				signer.Public().(ed25519.PublicKey),
			)
			if err == nil {
				if !bytes.Equal(
					opened.Key,
					material.Key,
				) {
					t.Error("recovered a different key")
				}
				clear(opened.Key)
				successes.Add(1)
			} else if !errors.Is(
				err,
				ErrRecipientUsed,
			) {
				t.Errorf(
					"concurrent open failed unexpectedly: %v",
					err,
				)
			}
		})
	}
	close(start)
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf(
			"returned key %d times",
			successes.Load(),
		)
	}
}

func TestRecoveryIdentityRejectsNoncanonicalBindings(t *testing.T) {
	identity, _, _ := recoveryFixture(t)
	for name, change := range map[string]func(*RecoveryIdentity){
		"empty cluster": func(i *RecoveryIdentity) { i.ClusterID = "" },
		"oversize cluster": func(i *RecoveryIdentity) {
			i.ClusterID = strings.Repeat(
				"a",
				257,
			)
		},
		"invalid UTF-8": func(i *RecoveryIdentity) { i.ClusterID = string([]byte{0xff}) },
		"empty storage": func(i *RecoveryIdentity) { i.StorageSHA256 = "" },
		"uppercase storage": func(i *RecoveryIdentity) {
			i.StorageSHA256 = strings.Repeat(
				"AB",
				32,
			)
		},
		"short launch": func(i *RecoveryIdentity) { i.ConfigSHA256 = "abcd" },
	} {
		t.Run(
			name,
			func(t *testing.T) {
				bad := identity
				change(&bad)
				if _, err := NewRecipient(bad); err == nil {
					t.Fatal("accepted malformed identity")
				}
			},
		)
	}
}

type recoveryPolicyFunc func(context.Context) (RecoveryPolicy, error)

func (f recoveryPolicyFunc) Current(ctx context.Context) (RecoveryPolicy, error) {
	return f(ctx)
}

func testRecoveryPolicy(identity *RecoveryIdentity) RecoveryPolicy {
	launch := []byte("measured object-state launch")
	hash := sha256.Sum256(launch)
	identity.ConfigSHA256 = hex.EncodeToString(hash[:])
	native, _ := armtls.NewNativeVerifier(teetypes.SnpTcb{Bootloader: 12, Snp: 28, Microcode: 28})
	return RecoveryPolicy{
		Native:   native,
		Revision: "policy-one",
		Images: []remote.ImagePin{
			{
				Digest: bytes.Repeat(
					[]byte{1},
					48,
				),
				LaunchFile: launch,
			},
		},
		AttestationURL: "http://127.0.0.1:9876",
	}
}

func TestRecoveryReleaseChecksPolicyAfterAttestation(t *testing.T) {
	for _, test := range []struct {
		name       string
		change     func(*RecoveryPolicy)
		finalError error
		cancel     bool
	}{
		{
			name: "stable policy",
		},
		{
			name:   "retirement during attestation",
			change: func(p *RecoveryPolicy) { p.Revision = "policy-two" },
		},
		{
			name: "changed pins even with reused revision",
			change: func(p *RecoveryPolicy) {
				p.Images = []remote.ImagePin{{
					Digest: bytes.Repeat(
						[]byte{2},
						48,
					),
					LaunchFile: p.Images[0].LaunchFile,
				}}
			},
		},
		{
			name:       "unavailable final read",
			finalError: errors.New("storage unavailable"),
		},
		{
			name:   "cancellation before seal",
			cancel: true,
		},
	} {
		t.Run(
			test.name,
			func(t *testing.T) {
				identity, signer, material := recoveryFixture(t)
				policy := testRecoveryPolicy(&identity)
				recipient := testRecoveryRecipient(
					t,
					identity,
				)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				reads := 0
				fetched := false
				source := recoveryPolicyFunc(func(context.Context) (RecoveryPolicy, error) {
					reads++
					if reads == 1 {
						return policy, nil
					}
					if !fetched {
						t.Fatal("final policy read preceded recipient attestation")
					}
					final := policy
					if test.change != nil {
						test.change(&final)
					}
					if test.cancel {
						cancel()
					}
					return final, test.finalError
				})
				grant, err := releaseRecovery(
					ctx,
					identity,
					"https://cds.example",
					source,
					material,
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
				if reads != 2 {
					t.Fatalf(
						"policy read %d times",
						reads,
					)
				}
				if test.change != nil || test.finalError != nil || test.cancel {
					if grant != nil || err == nil {
						t.Fatal("released after policy changed or freshness failed")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				opened, err := recipient.Open(
					*grant,
					signer.Public().(ed25519.PublicKey),
				)
				if err != nil || !bytes.Equal(
					opened.Key,
					material.Key,
				) {
					t.Fatalf(
						"stable policy recovery failed: %v",
						err,
					)
				}
				clear(opened.Key)
			},
		)
	}
}

func TestRecoveryReleaseRejectsUnattestedRecipientAndUnboundPolicy(t *testing.T) {
	identity, signer, material := recoveryFixture(t)
	policy := testRecoveryPolicy(&identity)
	var called atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(
		http.ResponseWriter,
		*http.Request,
	) {
		called.Store(true)
	}))
	defer server.Close()
	for name, change := range map[string]func(*RecoveryPolicy){
		"ordinary TLS":    func(*RecoveryPolicy) {},
		"no pins":         func(p *RecoveryPolicy) { p.Images = nil },
		"remote verifier": func(p *RecoveryPolicy) { p.AttestationURL = "https://operator.example" },
		"unbound launch": func(p *RecoveryPolicy) {
			p.Images = []remote.ImagePin{{Digest: bytes.Repeat(
				[]byte{1},
				48,
			)}}
		},
		"wrong launch": func(p *RecoveryPolicy) {
			p.Images = []remote.ImagePin{{
				Digest: bytes.Repeat(
					[]byte{1},
					48,
				),
				LaunchFile: []byte("other"),
			}}
		},
	} {
		t.Run(
			name,
			func(t *testing.T) {
				bad := policy
				change(&bad)
				grant, err := Release(
					t.Context(),
					identity,
					server.URL,
					recoveryPolicyFunc(func(context.Context) (RecoveryPolicy, error) { return bad, nil }),
					material,
					signer,
				)
				if grant != nil || err == nil {
					t.Fatal("released to unverified recipient or unbound policy")
				}
			},
		)
	}
	if called.Load() {
		t.Fatal("sent HTTP request before authenticating recipient")
	}
}

func TestRecoveryReleaseMissingStateDoesNotUseBootstrapPolicy(t *testing.T) {
	identity, signer, material := recoveryFixture(t)
	want := errors.New("current object is missing")
	grant, err := releaseRecovery(
		t.Context(),
		identity,
		"https://cds.example",
		recoveryPolicyFunc(func(context.Context) (RecoveryPolicy, error) {
			return RecoveryPolicy{}, want
		}),
		material,
		signer,
		func(
			context.Context,
			RecoveryIdentity,
			string,
			RecoveryPolicy,
		) (RecoveryRequest, error) {
			t.Fatal("attempted attestation with missing current state")
			return RecoveryRequest{}, nil
		},
	)
	if grant != nil || !errors.Is(
		err,
		want,
	) {
		t.Fatalf(
			"missing state did not fail closed: %v",
			err,
		)
	}
}
