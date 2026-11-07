package launchbinding

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

var operatorPub = []byte("operator public key bytes")

// launchFile stands in for a whole configuration document a VM is launched
// with, the anchor shape a CDS VM binds.
var launchFile = []byte("schemaVersion: c8s-cds/v1\n")

// TestMain shortens the attestation-api readiness wait so the unreachable-URL
// cases fail in milliseconds rather than the 90s a real boot allows.
func TestMain(m *testing.M) {
	attestationReadyTimeout = 300 * time.Millisecond
	attestationReadyInterval = 20 * time.Millisecond
	os.Exit(m.Run())
}

// stageOperatorPubkey points the package's staging path at a temp file and
// writes pub to it. Pass nil to leave the file absent.
func stageOperatorPubkey(t *testing.T, pub []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "operator-pubkey")
	orig := operatorPubkeyPath
	operatorPubkeyPath = path
	t.Cleanup(func() { operatorPubkeyPath = orig })
	if pub == nil {
		return
	}
	if err := os.WriteFile(path, pub, 0o600); err != nil {
		t.Fatal(err)
	}
}

// selfReport is what a stub attestation-api's verified self-report carries:
// the operator-key binding in whichever claim the platform uses (RTMR[3] on
// TDX, HOSTDATA on SEV-SNP), the launch digest, and on TDX the RTMR[1]/[2]
// pins. Zero-valued fields are left off the claims.
type selfReport struct {
	platform     teetypes.PlatformType
	binding      []byte
	launchDigest []byte
	rtmr1, rtmr2 []byte
}

// stubAttester serves a fake attestation-api answering r as this guest's
// verified self-report.
func stubAttester(t *testing.T, r selfReport) *mockapi.Stub {
	t.Helper()
	stub := mockapi.New(t)
	stub.SetPlatform(r.platform)
	v := mockapi.PassingVerdict(hex.EncodeToString(r.launchDigest))
	if r.platform.IsTDX() {
		pd := map[string]any{}
		for k, b := range map[string][]byte{"rtmr_1": r.rtmr1, "rtmr_2": r.rtmr2, "rtmr_3": r.binding} {
			if b != nil {
				pd[k] = hex.EncodeToString(b)
			}
		}
		v.Claims.PlatformData = pd
	} else {
		v.Claims.InitData = r.binding
	}
	stub.SetVerdict(v)
	return stub
}

// attester serves a fake attestation-api whose verified self-report carries
// binding in whichever claim the platform uses. Both arms go through one code
// path now, so both are exercised by varying only the platform and the claim.
func attester(t *testing.T, platform teetypes.PlatformType, binding []byte) string {
	t.Helper()
	return stubAttester(t, selfReport{platform: platform, binding: binding}).URL()
}

func tdxBinding(pub []byte) []byte { v := runtimemeasure.Seed(pub); return v[:] }
func snpBinding(pub []byte) []byte { v := runtimemeasure.HostData(pub); return v[:] }

// fill returns a 48-byte register value, every byte equal to b.
func fill(b byte) []byte { return bytes.Repeat([]byte{b}, 48) }

// A missing pubkey is reported as ErrNoOperatorKey so a caller can tell a
// non-operator boot from every other refusal; an empty file is not. The image
// policy plugin reads this distinction (internal/cmds/nri-image-policy).
func TestReadOperatorPubkeyClassifiesAbsence(t *testing.T) {
	stageOperatorPubkey(t, nil)
	_, err := ReadOperatorPubkey()
	if !errors.Is(err, ErrNoOperatorKey) {
		t.Errorf("err = %v, want errors.Is(..., ErrNoOperatorKey)", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, must not leak fs.ErrNotExist (a missing sysfs node would be mistaken for it)", err)
	}

	stageOperatorPubkey(t, []byte{})
	if _, err := ReadOperatorPubkey(); err == nil || errors.Is(err, ErrNoOperatorKey) {
		t.Errorf("err = %v, want a refusal that is NOT ErrNoOperatorKey for an empty staged key", err)
	}

	stageOperatorPubkey(t, operatorPub)
	if pub, err := ReadOperatorPubkey(); err != nil || string(pub) != string(operatorPub) {
		t.Errorf("ReadOperatorPubkey = %q, %v, want the staged key", pub, err)
	}
}

// The self-report must be non-replayable: the code asks the verifier to bind a
// fresh nonce, and a stub reporting success without one would pass a replay.
func TestSelfReportBindsAFreshNonce(t *testing.T) {
	stub := mockapi.New(t)
	stub.SetPlatform(teetypes.PlatformType(teetypes.PlatformSNP))
	stub.SetVerdict(mockapi.PassingVerdict(""))

	if _, err := verifiedSelfReport(context.Background(), stub.URL()); err != nil {
		t.Fatalf("verifiedSelfReport: %v", err)
	}
	reqs := stub.VerifyRequests()
	if len(reqs) != 1 {
		t.Fatalf("verify requests = %d, want 1", len(reqs))
	}
	sent := reqs[0].Params.ExpectedReportData
	if len(sent) == 0 {
		t.Fatal("no expected report data sent; a self-report with no nonce is replayable")
	}
	var zero [64]byte
	if string(sent) == string(zero[:len(sent)]) {
		t.Fatal("expected report data is all zero, so it is not a fresh nonce")
	}
}

// The boot-order race: attestation-api is ordered before a guest's staging
// but binds its port only after fetching its certificate collateral, so the
// first /health calls fail. The self-report must wait for readiness and then
// attest exactly once.
func TestSelfReportWaitsForAttestationAPI(t *testing.T) {
	launchDigest := fill(0x5a)
	stub := stubAttester(t, selfReport{platform: teetypes.PlatformSNP, launchDigest: launchDigest})
	target, err := url.Parse(stub.URL())
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var healthRequests atomic.Int32
	delayed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" && healthRequests.Add(1) <= 3 {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer delayed.Close()

	report, err := verifiedSelfReport(context.Background(), delayed.URL)
	if err != nil {
		t.Fatalf("verifiedSelfReport: %v", err)
	}
	measurement, err := report.Claims.LaunchMeasurement()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(measurement, launchDigest) {
		t.Errorf("measurement = %x, want %x", measurement, launchDigest)
	}
	if n := healthRequests.Load(); n < 4 {
		t.Errorf("/health called %d times, want at least 4 (3 failures then success)", n)
	}
	if n := len(stub.AttestRequests()); n != 1 {
		t.Errorf("/attest called %d times, want exactly 1", n)
	}
}

func TestSelfReportFailsWhenAttestationAPINeverReady(t *testing.T) {
	_, err := verifiedSelfReport(context.Background(), "http://127.0.0.1:1")
	if err == nil {
		t.Fatal("want an error when the attestation-api never answers /health")
	}
	if !strings.Contains(err.Error(), "not ready after") {
		t.Errorf("error = %v, want the readiness wait to report the timeout", err)
	}
}

// A VM whose launch file is its whole configuration is bound to it on both
// platforms, and the platform it serves comes from the report rather than from
// something it was configured to believe.
func TestVerifyMeasuredLaunchFile(t *testing.T) {
	for _, tc := range []struct {
		platform teetypes.PlatformType
		binding  []byte
		want     teetypes.Family
	}{
		{teetypes.PlatformTDX, tdxBinding(launchFile), teetypes.FamilyTDX},
		{teetypes.PlatformSNP, snpBinding(launchFile), teetypes.FamilySNP},
		{teetypes.PlatformGcpSNP, snpBinding(launchFile), teetypes.FamilySNP},
	} {
		t.Run(string(tc.platform), func(t *testing.T) {
			got, err := VerifyMeasuredLaunchFile(context.Background(), attester(t, tc.platform, tc.binding), launchFile)
			if err != nil {
				t.Fatalf("VerifyMeasuredLaunchFile: %v", err)
			}
			if got != tc.want {
				t.Errorf("platform = %s, want %s", got, tc.want)
			}
		})
	}
}

// Serving a configuration the launch did not bind serves whatever the host
// wrote, so every binding other than the launch file's own fails closed —
// including a register extended past the seed, which no such VM does.
func TestVerifyMeasuredLaunchFileFailsClosed(t *testing.T) {
	extended := runtimemeasure.Extend(runtimemeasure.Seed(launchFile), runtimemeasure.Event("sha256:"+strings.Repeat("1", 64)))

	for _, tc := range []struct {
		name     string
		platform teetypes.PlatformType
		binding  []byte
	}{
		{"tdx: another document", teetypes.PlatformTDX, tdxBinding([]byte("another document"))},
		{"tdx: the seed extended at runtime", teetypes.PlatformTDX, extended[:]},
		{"tdx: fileless launch leaves the register zero", teetypes.PlatformTDX, make([]byte, runtimemeasure.Size)},
		{"snp: another document", teetypes.PlatformSNP, snpBinding([]byte("another document"))},
		{"az-snp: HOSTDATA is the paravisor's, not the launcher's", teetypes.PlatformAzSNP, snpBinding(launchFile)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyMeasuredLaunchFile(context.Background(), attester(t, tc.platform, tc.binding), launchFile); err == nil {
				t.Fatal("VerifyMeasuredLaunchFile = nil error, want a refusal")
			}
		})
	}
}

// tdxLaunchedWith is the RTMR[3] of a TDX guest launched with launchFile
// that has since extended policies, from launchFile's launch-file digest.
func tdxLaunchedWith(t *testing.T, launchFile []byte, policies ...string) []byte {
	t.Helper()
	digest, err := runtimemeasure.LaunchFileDigest(teetypes.FamilyTDX, launchFile)
	if err != nil {
		t.Fatal(err)
	}
	reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Extend(runtimemeasure.Zero, [runtimemeasure.Size]byte(digest)), policies)
	return reg[:]
}

var (
	policyP = "sha256:" + strings.Repeat("1", 64)
	policyQ = "sha256:" + strings.Repeat("2", 64)
)

// A launch bound to the file passes: on TDX its RTMR[3] seed followed by a
// prefix of the journal, on SEV-SNP HOSTDATA.
func TestVerifyLaunchBinding(t *testing.T) {
	for _, tc := range []struct {
		name     string
		platform teetypes.PlatformType
		binding  []byte
		journal  string
	}{
		{"tdx: register at the file's seed, no journal", teetypes.PlatformTDX, tdxLaunchedWith(t, launchFile), ""},
		{"tdx: register at journal prefix [P] of [P,Q]", teetypes.PlatformTDX, tdxLaunchedWith(t, launchFile, policyP), policyP + "\n" + policyQ + "\n"},
		{"sev-snp: HOSTDATA is the file's digest", teetypes.PlatformSNP, snpBinding(launchFile), ""},
		{"sev-snp: HOSTDATA is the file's digest, and SNP ignores the journal", teetypes.PlatformSNP, snpBinding(launchFile), policyP + "\n"},
		{"gcp-snp: HOSTDATA is the file's digest", teetypes.PlatformGcpSNP, snpBinding(launchFile), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyLaunchBinding(context.Background(), attester(t, tc.platform, tc.binding), writeJournal(t, tc.journal), launchFile); err != nil {
				t.Fatalf("VerifyLaunchBinding: %v", err)
			}
		})
	}
}

// Every refusal fails closed; only a binding compared and found different is
// ErrLaunchFileNotBound.
func TestVerifyLaunchBindingFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		platform teetypes.PlatformType
		binding  []byte
		journal  string
		file     []byte
		notBound bool
	}{
		{
			name:     "tdx: register at another document's seed",
			platform: teetypes.PlatformTDX,
			binding:  tdxLaunchedWith(t, []byte("another document")),
			file:     launchFile,
			notBound: true,
		},
		{
			name:     "tdx: register zero, launched with no disk",
			platform: teetypes.PlatformTDX,
			binding:  make([]byte, runtimemeasure.Size),
			file:     launchFile,
			notBound: true,
		},
		{
			name:     "tdx: register extended with Q, which journal [P] does not hold",
			platform: teetypes.PlatformTDX,
			binding:  tdxLaunchedWith(t, launchFile, policyQ),
			journal:  policyP + "\n",
			file:     launchFile,
			notBound: true,
		},
		{
			name:     "snp: another document",
			platform: teetypes.PlatformSNP,
			binding:  snpBinding([]byte("another document")),
			file:     launchFile,
			notBound: true,
		},
		{
			name:     "snp: fileless launch leaves HOSTDATA zero",
			platform: teetypes.PlatformSNP,
			binding:  make([]byte, runtimemeasure.HostDataSize),
			file:     launchFile,
			notBound: true,
		},
		{
			name:     "snp: an empty file",
			platform: teetypes.PlatformSNP,
			binding:  snpBinding(nil),
			file:     []byte{},
		},
		{
			name:     "az-snp: HOSTDATA is the paravisor's, not the launcher's",
			platform: teetypes.PlatformAzSNP,
			binding:  snpBinding(launchFile),
			file:     launchFile,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyLaunchBinding(context.Background(), attester(t, tc.platform, tc.binding), writeJournal(t, tc.journal), tc.file)
			if err == nil {
				t.Fatal("VerifyLaunchBinding = nil error, want a refusal")
			}
			if errors.Is(err, ErrLaunchFileNotBound) != tc.notBound {
				t.Fatalf("VerifyLaunchBinding = %v, want ErrLaunchFileNotBound %v", err, tc.notBound)
			}
		})
	}
}

// A journal over the per-boot cap is refused where it is read, naming the cap:
// a node that lists more policies than any verifier replays is not a node
// whose binding can be matched.
func TestVerifyLaunchBindingRefusesAJournalOverTheCap(t *testing.T) {
	journal := writeJournal(t, journalOfDistinctDigests(armtls.MaxRuntimeExtensions+1))
	attestationAPI := attester(t, teetypes.PlatformTDX, tdxLaunchedWith(t, launchFile))
	err := VerifyLaunchBinding(context.Background(), attestationAPI, journal, launchFile)
	if err == nil || !strings.Contains(err.Error(), "per-boot cap") {
		t.Fatalf("VerifyLaunchBinding = %v, want the per-boot cap named", err)
	}
	if errors.Is(err, ErrLaunchFileNotBound) {
		t.Fatalf("VerifyLaunchBinding = %v, want a read failure, not a binding mismatch", err)
	}
}

// An unreachable attestation API is a refusal, never a binding mismatch.
func TestVerifyLaunchBindingReportsAnUnreachableAttester(t *testing.T) {
	err := VerifyLaunchBinding(context.Background(), "http://127.0.0.1:1", "", launchFile)
	if err == nil || errors.Is(err, ErrLaunchFileNotBound) || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("VerifyLaunchBinding = %v, want the attestation API reported unreachable", err)
	}
}

// writeJournal returns the path of a journal holding journal, or of a missing
// file when journal is empty.
func writeJournal(t *testing.T, journal string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "measured-policies")
	if journal != "" {
		if err := os.WriteFile(path, []byte(journal), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// journalOfDistinctDigests is a journal of n distinct policy digests,
// "sha256:%064x" of i for i in [0,n): a list no binding replays, which is what
// a cap test needs.
func journalOfDistinctDigests(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "sha256:%064x\n", i)
	}
	return b.String()
}
