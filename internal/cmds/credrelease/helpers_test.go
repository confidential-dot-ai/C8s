package credrelease

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
)

// stubMeasuredOperatorKey makes the launch-binding check return pub.
func stubMeasuredOperatorKey(t *testing.T, pub []byte) {
	t.Helper()
	stubMeasuredKeyLoader(t, func(context.Context, string, string) ([]byte, error) { return pub, nil })
}

// stubMeasuredOperatorKeyError makes the launch-binding check fail with err.
func stubMeasuredOperatorKeyError(t *testing.T, err error) {
	t.Helper()
	stubMeasuredKeyLoader(t, func(context.Context, string, string) ([]byte, error) { return nil, err })
}

func stubMeasuredKeyLoader(t *testing.T, loader measuredKeyLoader) {
	t.Helper()
	orig := loadMeasuredOperatorKey
	loadMeasuredOperatorKey = loader
	t.Cleanup(func() { loadMeasuredOperatorKey = orig })
}

// anyLaunchDigest leaves the verdict's launch digest unset.
const anyLaunchDigest = ""

// stubAttester serves a fake attestation-api on platform.
func stubAttester(t *testing.T, platform teetypes.PlatformType) *mockapi.Stub {
	t.Helper()
	stub := mockapi.New(t)
	stub.SetPlatform(platform)
	stub.SetVerdict(mockapi.PassingVerdict(anyLaunchDigest))
	return stub
}

// defaultRoles is the binary-default identity set (what the baked unit spells
// out), for handler tests.
func defaultRoles() Roles {
	return Config{
		CertOrg: defaultCertOrg, CertCN: defaultCertCN, CertTTL: defaultCertTTL,
		LogCertOrg: defaultLogCertOrg, LogCertCN: defaultLogCertCN, LogCertTTL: defaultLogCertTTL,
	}.roles()
}

// decodeOnePEM decodes a single PEM block and asserts its type.
func decodeOnePEM(t *testing.T, pemBytes []byte, wantType string) []byte {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("no PEM block")
	}
	if block.Type != wantType {
		t.Fatalf("PEM type = %q, want %q", block.Type, wantType)
	}
	return block.Bytes
}

// journalOfDistinctDigests is a journal of n distinct policy digests.
func journalOfDistinctDigests(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "sha256:%064x\n", i)
	}
	return b.String()
}

// writeJournal returns the path of a measured-policy journal holding journal.
func writeJournal(t *testing.T, journal string) string {
	t.Helper()
	path := missingJournalPath(t)
	if err := os.WriteFile(path, []byte(journal), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// missingJournalPath is the path of a journal file that was never written, as
// a node with no measured policies has.
func missingJournalPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "measured-policies")
}
