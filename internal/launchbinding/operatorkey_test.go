package launchbinding

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func tdxKeyWithPolicies(pub []byte, policies ...string) []byte {
	reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(pub), policies)
	return reg[:]
}

// A staged key passes when the register is its seed followed by a prefix of
// the journal, on TDX, and when HOSTDATA is its digest on SEV-SNP.
func TestLoadMeasuredOperatorKey(t *testing.T) {
	for _, tc := range []struct {
		name     string
		platform teetypes.PlatformType
		binding  []byte
		journal  string
	}{
		{"tdx: register at the key's seed, no journal", teetypes.PlatformTDX, tdxBinding(operatorPub), ""},
		{"tdx: register at journal prefix [P] of [P,Q]", teetypes.PlatformTDX, tdxKeyWithPolicies(operatorPub, policyP), policyP + "\n" + policyQ + "\n"},
		{"tdx: register at the seed, journal [P] not yet extended", teetypes.PlatformTDX, tdxBinding(operatorPub), policyP + "\n"},
		{"sev-snp: HOSTDATA is the key's digest", teetypes.PlatformSNP, snpBinding(operatorPub), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stageOperatorPubkey(t, operatorPub)
			pub, err := LoadMeasuredOperatorKey(context.Background(), attester(t, tc.platform, tc.binding), writeJournal(t, tc.journal))
			if err != nil {
				t.Fatalf("LoadMeasuredOperatorKey: %v", err)
			}
			if string(pub) != string(operatorPub) {
				t.Fatalf("LoadMeasuredOperatorKey = %q, want the staged key", pub)
			}
		})
	}
}

// Only a register compared and found different is ErrRegisterDoesNotReplay;
// a missing key, an unreachable attester and an over-cap journal are not.
func TestLoadMeasuredOperatorKeyFailsClosed(t *testing.T) {
	overCap := journalOfDistinctDigests(armtls.MaxRuntimeExtensions + 1)
	for _, tc := range []struct {
		name        string
		staged      []byte
		attestation func(t *testing.T) string
		journal     string
		want        string
		replay      bool
		noKey       bool
	}{
		{
			name:        "no staged key",
			attestation: func(t *testing.T) string { return attester(t, teetypes.PlatformTDX, tdxBinding(operatorPub)) },
			want:        "no operator pubkey staged",
			noKey:       true,
		},
		{
			name:        "unreachable attester",
			staged:      operatorPub,
			attestation: func(*testing.T) string { return "http://127.0.0.1:1" },
			want:        "not ready",
		},
		{
			name:        "report without a binding",
			staged:      operatorPub,
			attestation: func(t *testing.T) string { return attester(t, teetypes.PlatformTDX, nil) },
			want:        "this guest's self-report",
		},
		{
			name:        "tdx: register at another key's seed",
			staged:      operatorPub,
			attestation: func(t *testing.T) string { return attester(t, teetypes.PlatformTDX, tdxBinding([]byte("another key"))) },
			want:        "staged key's seed",
			replay:      true,
		},
		{
			name:   "tdx: register extended with Q, which journal [P] does not hold",
			staged: operatorPub,
			attestation: func(t *testing.T) string {
				return attester(t, teetypes.PlatformTDX, tdxKeyWithPolicies(operatorPub, policyQ))
			},
			journal: policyP + "\n",
			want:    "replays no prefix of the 1 measured policies",
			replay:  true,
		},
		{
			name:        "journal over the cap",
			staged:      operatorPub,
			attestation: func(t *testing.T) string { return attester(t, teetypes.PlatformTDX, tdxBinding(operatorPub)) },
			journal:     overCap,
			want:        "read measured policies",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stageOperatorPubkey(t, tc.staged)
			pub, err := LoadMeasuredOperatorKey(context.Background(), tc.attestation(t), writeJournal(t, tc.journal))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadMeasuredOperatorKey = %v, want %q", err, tc.want)
			}
			if pub != nil {
				t.Fatalf("LoadMeasuredOperatorKey returned key %q with an error", pub)
			}
			if errors.Is(err, ErrRegisterDoesNotReplay) != tc.replay {
				t.Fatalf("LoadMeasuredOperatorKey = %v, want ErrRegisterDoesNotReplay %v", err, tc.replay)
			}
			if errors.Is(err, ErrNoOperatorKey) != tc.noKey {
				t.Fatalf("LoadMeasuredOperatorKey = %v, want ErrNoOperatorKey %v", err, tc.noKey)
			}
		})
	}
}

func tdxIdentityAttester(t *testing.T, binding []byte) string {
	t.Helper()
	return stubAttester(t, selfReport{
		platform:     teetypes.PlatformTDX,
		binding:      binding,
		launchDigest: fill(0x11),
		rtmr1:        fill(0x22),
		rtmr2:        fill(0x33),
	}).URL()
}

// The image identity resolves whatever happened to the key; the key is
// returned only when its binding holds.
func TestLoadMeasuredIdentity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		staged  []byte
		binding []byte
		keyErr  error
	}{
		{"bound key", operatorPub, tdxBinding(operatorPub), nil},
		{"no staged key", nil, tdxBinding(operatorPub), ErrNoOperatorKey},
		{"key the launch did not bind", operatorPub, tdxBinding([]byte("another key")), ErrRegisterDoesNotReplay},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stageOperatorPubkey(t, tc.staged)
			got, err := LoadMeasuredIdentity(context.Background(), string(teetypes.FamilyTDX), tdxIdentityAttester(t, tc.binding), "")
			if err != nil {
				t.Fatalf("LoadMeasuredIdentity: %v", err)
			}
			if got.Image == nil || got.Image.Family() != teetypes.FamilyTDX {
				t.Fatalf("Image = %v, want a TDX identity", got.Image)
			}
			digests := got.Image.LaunchDigests()
			if len(digests) != 1 || string(digests[0].Digest[:]) != string(fill(0x11)) {
				t.Fatalf("launch digests = %v, want the reported MRTD", digests)
			}
			if tc.keyErr == nil {
				if got.OperatorKeyErr != nil || string(got.OperatorKey) != string(operatorPub) {
					t.Fatalf("OperatorKey = %q, %v, want the staged key", got.OperatorKey, got.OperatorKeyErr)
				}
				return
			}
			if !errors.Is(got.OperatorKeyErr, tc.keyErr) || got.OperatorKey != nil {
				t.Fatalf("OperatorKey = %q, %v, want no key and %v", got.OperatorKey, got.OperatorKeyErr, tc.keyErr)
			}
		})
	}
}

// A self-report, image or platform failure is the returned error, not a key
// error.
func TestLoadMeasuredIdentityFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name        string
		platform    string
		attestation func(t *testing.T) string
		want        string
	}{
		{"unreachable attester", string(teetypes.FamilyTDX), func(*testing.T) string { return "http://127.0.0.1:1" }, "not ready"},
		{"report from another platform", string(teetypes.FamilySNP), func(t *testing.T) string { return tdxIdentityAttester(t, tdxBinding(operatorPub)) }, "built for platform"},
		{"report without an image identity", string(teetypes.FamilyTDX), func(t *testing.T) string { return attester(t, teetypes.PlatformTDX, tdxBinding(operatorPub)) }, "launch digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stageOperatorPubkey(t, operatorPub)
			_, err := LoadMeasuredIdentity(context.Background(), tc.platform, tc.attestation(t), "")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadMeasuredIdentity = %v, want %q", err, tc.want)
			}
		})
	}
}
