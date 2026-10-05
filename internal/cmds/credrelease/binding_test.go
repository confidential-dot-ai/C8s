package credrelease

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
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
)

var operatorPub = []byte("operator public key bytes")

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

// The happy path on both platforms: the staged pubkey is the one the launch
// bound, so the key is released. The caller no longer passes a platform — it
// comes from the verified report.
func TestLoadMeasuredOperatorKey(t *testing.T) {
	for _, tc := range []struct {
		platform teetypes.PlatformType
		binding  []byte
	}{
		{teetypes.PlatformTDX, tdxBinding(operatorPub)},
		{teetypes.PlatformAzTDX, tdxBinding(operatorPub)},
		{teetypes.PlatformSNP, snpBinding(operatorPub)},
		{teetypes.PlatformGcpSNP, snpBinding(operatorPub)},
	} {
		t.Run(string(tc.platform), func(t *testing.T) {
			stageOperatorPubkey(t, operatorPub)
			url := attester(t, tc.platform, tc.binding)

			got, err := LoadMeasuredOperatorKey(context.Background(), url)
			if err != nil {
				t.Fatalf("LoadMeasuredOperatorKey: %v", err)
			}
			if string(got) != string(operatorPub) {
				t.Errorf("returned key = %q, want %q", got, operatorPub)
			}
		})
	}
}

// Every way the anchor check can fail must refuse. Releasing a key the launch
// did not bind is the vulnerability this check exists to prevent.
func TestLoadMeasuredOperatorKeyFailsClosed(t *testing.T) {
	otherKey := []byte("a different operator key")
	zeroTDX := make([]byte, runtimemeasure.Size)
	zeroSNP := make([]byte, runtimemeasure.HostDataSize)

	for _, tc := range []struct {
		name     string
		staged   []byte
		platform teetypes.PlatformType
		binding  []byte
	}{
		{"no staged pubkey", nil, teetypes.PlatformTDX, tdxBinding(operatorPub)},
		{"empty staged pubkey", []byte{}, teetypes.PlatformTDX, tdxBinding(operatorPub)},
		{"tdx: register holds another key's seed", operatorPub, teetypes.PlatformTDX, tdxBinding(otherKey)},
		{"tdx: keyless launch leaves the register zero", operatorPub, teetypes.PlatformTDX, zeroTDX},
		{"snp: HOSTDATA holds another key", operatorPub, teetypes.PlatformSNP, snpBinding(otherKey)},
		{"snp: keyless launch leaves HOSTDATA zero", operatorPub, teetypes.PlatformSNP, zeroSNP},
		// A TDX-width value in the SNP claim is MRCONFIGID, not HOSTDATA. It
		// must be refused by width, never truncated into a match.
		{"snp claim carrying a 48-byte value", operatorPub, teetypes.PlatformSNP, tdxBinding(operatorPub)},
		{"tdx claim carrying a 32-byte value", operatorPub, teetypes.PlatformTDX, snpBinding(operatorPub)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stageOperatorPubkey(t, tc.staged)
			url := attester(t, tc.platform, tc.binding)
			if _, err := LoadMeasuredOperatorKey(context.Background(), url); err == nil {
				t.Fatal("LoadMeasuredOperatorKey = nil error, want a refusal")
			}
		})
	}
}

// A missing pubkey is reported as ErrNoOperatorKey so a caller can tell a
// non-operator boot from every other refusal; an empty file is not.
func TestLoadMeasuredOperatorKeyClassifiesAbsence(t *testing.T) {
	stageOperatorPubkey(t, nil)
	_, err := LoadMeasuredOperatorKey(context.Background(), "http://127.0.0.1:1")
	if !errors.Is(err, ErrNoOperatorKey) {
		t.Errorf("err = %v, want errors.Is(..., ErrNoOperatorKey)", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, must not leak fs.ErrNotExist (a missing sysfs node would be mistaken for it)", err)
	}

	stageOperatorPubkey(t, []byte{})
	_, err = LoadMeasuredOperatorKey(context.Background(), "http://127.0.0.1:1")
	if err == nil || errors.Is(err, ErrNoOperatorKey) {
		t.Errorf("err = %v, want a refusal that is NOT ErrNoOperatorKey for an empty staged key", err)
	}
}

// An unreachable attestation-api is a refusal, not a fallback to the local
// register: the binding must come from a report whose signature was checked.
func TestLoadMeasuredOperatorKeyRefusesUnreachableAttester(t *testing.T) {
	stageOperatorPubkey(t, operatorPub)
	if _, err := LoadMeasuredOperatorKey(context.Background(), "http://127.0.0.1:1"); err == nil {
		t.Fatal("LoadMeasuredOperatorKey = nil error, want a refusal")
	}
}

// A platform this build has no binding rules for gets no key.
func TestLoadMeasuredOperatorKeyRefusesUnknownPlatform(t *testing.T) {
	stageOperatorPubkey(t, operatorPub)
	url := attester(t, "nonsense", tdxBinding(operatorPub))
	if _, err := LoadMeasuredOperatorKey(context.Background(), url); err == nil {
		t.Fatal("LoadMeasuredOperatorKey = nil error, want a refusal")
	}
}

// The self-report must be non-replayable: the code asks the verifier to bind a
// fresh nonce, and a stub reporting success without one would pass a replay.
func TestSelfReportBindsAFreshNonce(t *testing.T) {
	stageOperatorPubkey(t, operatorPub)
	stub := mockapi.New(t)
	stub.SetPlatform(teetypes.PlatformType(teetypes.PlatformSNP))
	v := mockapi.PassingVerdict("")
	v.Claims.InitData = snpBinding(operatorPub)
	stub.SetVerdict(v)

	if _, err := LoadMeasuredOperatorKey(context.Background(), stub.URL()); err != nil {
		t.Fatalf("LoadMeasuredOperatorKey: %v", err)
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

// The boot-order race: attestation-api is ordered before launch-config staging
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

// operatorReport is a self-report from a guest launched with operatorPub,
// carrying launchDigest and, on TDX, fixed RTMR pins.
func operatorReport(platform teetypes.PlatformType, launchDigest []byte) selfReport {
	r := selfReport{platform: platform, launchDigest: launchDigest}
	if platform.IsTDX() {
		r.binding, r.rtmr1, r.rtmr2 = tdxBinding(operatorPub), fill(0xbb), fill(0xcc)
	} else {
		r.binding = snpBinding(operatorPub)
	}
	return r
}

var combinedPlatforms = []struct {
	name     string
	platform teetypes.PlatformType
}{{"tdx", teetypes.PlatformTDX}, {"sev-snp", teetypes.PlatformSNP}}

// The combined loader answers both questions off one self-report: the guest
// attests itself once per boot, not once per check.
func TestLoadMeasuredIdentityAttestsOnce(t *testing.T) {
	for _, p := range combinedPlatforms {
		t.Run(p.name, func(t *testing.T) {
			stageOperatorPubkey(t, operatorPub)
			launchDigest := fill(0xab)
			stub := stubAttester(t, operatorReport(p.platform, launchDigest))

			got, err := LoadMeasuredIdentity(context.Background(), p.name, stub.URL())
			if err != nil {
				t.Fatalf("LoadMeasuredIdentity: %v", err)
			}
			if got.OperatorKeyErr != nil {
				t.Fatalf("got.OperatorKeyErr: %v", got.OperatorKeyErr)
			}
			if string(got.OperatorKey) != string(operatorPub) {
				t.Errorf("got.OperatorKey = %q, want %q", got.OperatorKey, operatorPub)
			}
			gotMeasurement := got.Image.LaunchDigests()[0].Digest
			gotRTMRs := got.Image.RTMRs()
			if got.Image.Family() != p.platform.Family() {
				t.Errorf("image family = %s, want %s", got.Image.Family(), p.platform.Family())
			}
			if !bytes.Equal(gotMeasurement[:], launchDigest) {
				t.Errorf("measurement = %x, want %x", gotMeasurement, launchDigest)
			}
			if (gotRTMRs != nil) != p.platform.IsTDX() {
				t.Errorf("rtmrs = %v; want them on TDX only", gotRTMRs)
			}
			if n := len(stub.AttestRequests()); n != 1 {
				t.Errorf("attest-api /attest called %d times, want exactly 1 (one self-report shared by both checks)", n)
			}
			if n := len(stub.VerifyRequests()); n != 1 {
				t.Errorf("attest-api /verify called %d times, want exactly 1", n)
			}
		})
	}
}

// A launch with no opkeydata pubkey at all: the own measurement must still
// resolve, and OperatorKeyErr must wrap ErrNoOperatorKey rather than failing
// the whole call.
func TestLoadMeasuredIdentityNonOperatorBoot(t *testing.T) {
	for _, p := range combinedPlatforms {
		t.Run(p.name, func(t *testing.T) {
			stageOperatorPubkey(t, nil)
			launchDigest := fill(0xcd)
			r := operatorReport(p.platform, launchDigest)
			r.binding = make([]byte, len(r.binding)) // keyless launch: zero binding
			url := stubAttester(t, r).URL()

			got, err := LoadMeasuredIdentity(context.Background(), p.name, url)
			if err != nil {
				t.Fatalf("unexpected hard error: %v", err)
			}
			if !errors.Is(got.OperatorKeyErr, ErrNoOperatorKey) {
				t.Errorf("got.OperatorKeyErr = %v, want errors.Is(..., ErrNoOperatorKey)", got.OperatorKeyErr)
			}
			if got.OperatorKey != nil {
				t.Errorf("got.OperatorKey = %v, want nil", got.OperatorKey)
			}
			measurement := got.Image.LaunchDigests()[0].Digest
			if !bytes.Equal(measurement[:], launchDigest) {
				t.Errorf("measurement = %x, want %x — own measurement must resolve on a non-operator boot too", measurement, launchDigest)
			}
		})
	}
}

// A staged pubkey the launch did not bind: OperatorKeyErr carries the mismatch
// (not ErrNoOperatorKey), while the own measurement still resolves from the
// one self-report already made.
func TestLoadMeasuredIdentitySubstitutedKey(t *testing.T) {
	for _, p := range combinedPlatforms {
		t.Run(p.name, func(t *testing.T) {
			stageOperatorPubkey(t, []byte("a different key the host swapped in"))
			launchDigest := fill(0xef)
			url := stubAttester(t, operatorReport(p.platform, launchDigest)).URL()

			got, err := LoadMeasuredIdentity(context.Background(), p.name, url)
			if err != nil {
				t.Fatalf("unexpected hard error: %v", err)
			}
			if got.OperatorKeyErr == nil {
				t.Fatal("want got.OperatorKeyErr set for a binding mismatch")
			}
			if errors.Is(got.OperatorKeyErr, ErrNoOperatorKey) {
				t.Errorf("got.OperatorKeyErr = %v, must NOT be classified as absent (a substituted key must fail closed)", got.OperatorKeyErr)
			}
			if got.OperatorKey != nil {
				t.Errorf("got.OperatorKey = %v, want nil", got.OperatorKey)
			}
			measurement := got.Image.LaunchDigests()[0].Digest
			if !bytes.Equal(measurement[:], launchDigest) {
				t.Errorf("measurement = %x, want %x", measurement, launchDigest)
			}
		})
	}
}

// The hard-fail path: this guest's own measurement cannot be resolved, which
// must fail the whole call even though a valid operator key was staged.
func TestLoadMeasuredIdentityFailsClosedOnUnresolvableMeasurement(t *testing.T) {
	for _, platform := range []string{"sev-snp", "no-such-platform"} {
		t.Run("configured family "+platform, func(t *testing.T) {
			stageOperatorPubkey(t, operatorPub)
			url := stubAttester(t, operatorReport(teetypes.PlatformTDX, fill(0xaa))).URL()
			if _, err := LoadMeasuredIdentity(context.Background(), platform, url); err == nil || !strings.Contains(err.Error(), platform) {
				t.Fatalf("want configured-family refusal naming %q, got %v", platform, err)
			}
		})
	}
	t.Run("tdx report missing a register", func(t *testing.T) {
		stageOperatorPubkey(t, operatorPub)
		r := operatorReport(teetypes.PlatformTDX, fill(0xaa))
		r.rtmr2 = nil
		url := stubAttester(t, r).URL()
		if _, err := LoadMeasuredIdentity(context.Background(), "tdx", url); err == nil {
			t.Fatal("want an error when this guest's own launch measurement cannot be resolved")
		}
	})

	t.Run("attestation-api unreachable", func(t *testing.T) {
		stageOperatorPubkey(t, operatorPub)
		if _, err := LoadMeasuredIdentity(context.Background(), "sev-snp", "http://127.0.0.1:1"); err == nil {
			t.Fatal("want an error when the attestation-api is unreachable")
		}
	})
}

// The operator-key binding check replays the measured-policy journal, which
// may run ahead of the report.
func TestVerifyNodeBindingReplaysMeasuredPolicies(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "measured-policies")
	orig := measuredPoliciesPath
	measuredPoliciesPath = journal
	t.Cleanup(func() { measuredPoliciesPath = orig })
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	report := func(digests ...string) *teetypes.VerificationResult {
		reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(operatorPub), digests)
		return &teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformTDX, Claims: teetypes.Claims{
			PlatformData: map[string]any{"rtmr_3": hex.EncodeToString(reg[:])},
		}}
	}
	if err := verifyNodeBinding(report(), operatorPub); err != nil {
		t.Fatalf("bare seed without a journal = %v", err)
	}
	if err := os.WriteFile(journal, []byte(p+"\n"+q+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyNodeBinding(report(p), operatorPub); err != nil {
		t.Fatalf("a journal ahead of the report = %v", err)
	}
	if err := verifyNodeBinding(report(q), operatorPub); err == nil {
		t.Fatal("a register the journal does not replay was accepted")
	}

	rec := httptest.NewRecorder()
	(&Handler{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, MeasuredPoliciesPath, nil))
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `["`+p+`","`+q+`"]` {
		t.Fatalf("GET %s = %d %s, want the journal", MeasuredPoliciesPath, rec.Code, rec.Body)
	}
}
