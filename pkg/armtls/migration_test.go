package armtls

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
)

func migrationClaims(
	platform teetypes.PlatformType,
	migratable bool,
) map[string]any {
	if platform.IsSNP() {
		return map[string]any{"policy": map[string]any{"migrate_ma": migratable}}
	}
	attributes := "0000000000000000"
	if migratable {
		attributes = "0000002000000000"
	}
	return map[string]any{"td_attributes": attributes}
}

func TestRequireNonMigratableChecksVerifiedClaims(t *testing.T) {
	for _, platform := range []teetypes.PlatformType{
		teetypes.PlatformSNP,
		teetypes.PlatformTDX,
	} {
		t.Run(
			string(platform),
			func(t *testing.T) {
				cert, _ := embeddedEnvelopeCert(
					t,
					platform,
					json.RawMessage(`{"unverified_migration_claim":false}`),
				)
				api := mockapi.New(t)
				digest := imageDigest("approved")
				policy := &VerifyPolicy{
					Policy:               remote.Policy{Measurements: [][]byte{digest}},
					AttestationApiURL:    api.URL(),
					RequireNonMigratable: true,
				}
				for _, test := range []struct {
					name string
					data map[string]any
					want error
				}{
					{
						name: "non-migratable",
						data: migrationClaims(
							platform,
							false,
						),
					},
					{
						name: "migratable",
						data: migrationClaims(
							platform,
							true,
						),
						want: ErrPolicyViolation,
					},
					{
						name: "missing claims",
						want: ErrPolicyViolation,
					},
				} {
					t.Run(
						test.name,
						func(t *testing.T) {
							verdict := mockapi.PassingVerdict(hex.EncodeToString(digest))
							verdict.Claims.PlatformData = test.data
							api.SetVerdict(verdict)
							policy.RequireNonMigratable = true
							if _, err := VerifyCert(
								cert,
								policy,
								nil,
							); !errors.Is(
								err,
								test.want,
							) {
								t.Fatalf(
									"VerifyCert = %v, want %v",
									err,
									test.want,
								)
							}
							policy.RequireNonMigratable = false
							if _, err := VerifyCert(
								cert,
								policy,
								nil,
							); err != nil {
								t.Fatalf(
									"legacy policy changed: %v",
									err,
								)
							}
						},
					)
				}
				policy.RequireNonMigratable = true
				verdict := mockapi.PassingVerdict(hex.EncodeToString(digest))
				verdict.SignatureValid = false
				api.SetVerdict(verdict)
				if _, err := VerifyCert(
					cert,
					policy,
					nil,
				); !errors.Is(
					err,
					ErrSignatureInvalid,
				) {
					t.Fatalf(
						"unverified evidence reached migration policy: %v",
						err,
					)
				}
			},
		)
	}
}

func TestEnforceNonMigratableRejectsMalformedClaims(t *testing.T) {
	for _, platform := range []teetypes.PlatformType{
		teetypes.PlatformSNP,
		teetypes.PlatformTDX,
	} {
		for _, data := range []map[string]any{
			nil,
			{"policy": false},
			{"policy": map[string]any{}},
			{"policy": map[string]any{"migrate_ma": "false"}},
			{"policy": map[string]any{"migrate_ma": 0}},
			{"td_attributes": false},
			{"td_attributes": "00000000000000"},
			{"td_attributes": "000000000000000000"},
			{"td_attributes": "00000000000000zz"},
			{"td_attributes": "00000000000000AB"},
			{"td_attributes": " 0000000000000000"},
			{"td_attributes_parsed": map[string]any{"migratable": false}},
		} {
			result := &teetypes.VerificationResult{
				SignatureValid: true,
				Platform:       platform,
				Claims:         teetypes.Claims{PlatformData: data},
			}
			if err := EnforceNonMigratable(result); !errors.Is(
				err,
				ErrPolicyViolation,
			) {
				t.Fatalf(
					"%s malformed claims %v: %v",
					platform,
					data,
					err,
				)
			}
		}
	}
	for _, result := range []*teetypes.VerificationResult{
		nil,
		{Platform: teetypes.PlatformSNP},
		{SignatureValid: true},
		{
			SignatureValid: true,
			Platform:       "unknown",
		},
	} {
		if err := EnforceNonMigratable(result); !errors.Is(
			err,
			ErrPolicyViolation,
		) {
			t.Fatalf(
				"incomplete result was admitted: %v",
				err,
			)
		}
	}
	for _, platform := range []teetypes.PlatformType{
		teetypes.PlatformAzSNP,
		teetypes.PlatformGcpSNP,
		teetypes.PlatformAzTDX,
		teetypes.PlatformGcpTDX,
	} {
		result := &teetypes.VerificationResult{
			SignatureValid: true,
			Platform:       platform,
			Claims: teetypes.Claims{PlatformData: migrationClaims(
				platform,
				false,
			)},
		}
		if err := EnforceNonMigratable(result); !errors.Is(
			err,
			ErrPolicyViolation,
		) {
			t.Fatalf(
				"non-native platform %s was admitted: %v",
				platform,
				err,
			)
		}
	}
}

func TestEnforceNonMigratableTDXByteOrder(t *testing.T) {
	result := &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.PlatformTDX,
		Claims: teetypes.Claims{PlatformData: map[string]any{
			// Bit 28 is not the migration bit; interpreting bytes as big-endian
			// would also put the migration bit in the wrong place.
			"td_attributes": "0000001000000000",
		}},
	}
	if err := EnforceNonMigratable(result); err != nil {
		t.Fatal(err)
	}
	result.Claims.PlatformData["td_attributes"] = "0000003000000000"
	if err := EnforceNonMigratable(result); !errors.Is(
		err,
		ErrPolicyViolation,
	) {
		t.Fatalf(
			"TDX bit 29 was admitted: %v",
			err,
		)
	}
}

func TestFollowPinsNonMigrationReplacement(t *testing.T) {
	for side, follow := range map[string]func(
		*tls.Config,
		PinSource,
		string,
		...bool,
	){
		"server": FollowServerPins,
		"client": FollowClientPins,
	} {
		for _, platform := range []teetypes.PlatformType{
			teetypes.PlatformSNP,
			teetypes.PlatformTDX,
		} {
			for phase, current := range map[string]string{
				"initial":   "approved",
				"refreshed": "old",
			} {
				t.Run(
					side+"/"+string(platform)+"/"+phase,
					func(t *testing.T) {
						cert, _ := embeddedEnvelopeCert(
							t,
							platform,
							json.RawMessage(`{}`),
						)
						api := mockapi.New(t)
						verdict := mockapi.PassingVerdict(hex.EncodeToString(imageDigest("approved")))
						verdict.Claims.PlatformData = migrationClaims(
							platform,
							true,
						)
						api.SetVerdict(verdict)
						policy := Pins{Measurements: [][]byte{imageDigest("approved")}}.VerifyPolicy(api.URL())
						policy.RequireNonMigratable = true
						var tlsCfg *tls.Config
						var err error
						if side == "server" {
							tlsCfg, _, err = NewClientTLSConfig(&ClientConfig{Policy: policy})
						} else {
							tlsCfg, _, err = NewServerTLSConfig(&ServerConfig{
								Platform: "sev-snp",
								AttestFunc: func(
									context.Context,
									string,
								) (string, error) {
									return string(mockapi.FakeSNPReport(nil)), nil
								},
								ClientPolicy: policy,
							})
						}
						if err != nil {
							t.Fatal(err)
						}
						if err := tlsCfg.VerifyPeerCertificate(
							[][]byte{cert.Raw},
							nil,
						); !errors.Is(
							err,
							ErrPolicyViolation,
						) {
							t.Fatalf(
								"constructor admitted a migratable peer: %v",
								err,
							)
						}
						// Follow replaces the constructor policy; its omitted option
						// deliberately retains the legacy default, not the prior flag.
						follow(
							tlsCfg,
							&movingPins{current: "approved"},
							api.URL(),
						)
						if err := tlsCfg.VerifyPeerCertificate(
							[][]byte{cert.Raw},
							nil,
						); err != nil {
							t.Fatalf(
								"replacement retained a constructor option: %v",
								err,
							)
						}
						pins := &movingPins{current: current}
						wantAttempts := 1
						if phase == "refreshed" {
							pins.next = "approved"
							wantAttempts = 2
						}
						priorAttempts := len(api.VerifyRequests())
						follow(
							tlsCfg,
							pins,
							api.URL(),
							true,
						)
						if err := tlsCfg.VerifyPeerCertificate(
							[][]byte{cert.Raw},
							nil,
						); !errors.Is(
							err,
							ErrPolicyViolation,
						) {
							t.Fatalf(
								"migratable peer was admitted: %v",
								err,
							)
						}
						if len(api.VerifyRequests())-priorAttempts != wantAttempts || pins.looks() != 1 {
							t.Fatal("refusal did not exercise the expected pin-refresh attempts")
						}
						verdict.Claims.PlatformData = migrationClaims(
							platform,
							false,
						)
						api.SetVerdict(verdict)
						if err := tlsCfg.VerifyPeerCertificate(
							[][]byte{cert.Raw},
							nil,
						); err != nil {
							t.Fatalf(
								"non-migratable peer was refused: %v",
								err,
							)
						}
					},
				)
			}
		}
	}
}
