package armtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/google/go-sev-guest/abi"
)

func nativeTestFloor() teetypes.SnpTcb {
	return teetypes.SnpTcb{Bootloader: 12, Snp: 28, Microcode: 28}
}

func nativeTestResult(platform teetypes.PlatformType) *teetypes.VerificationResult {
	result := &teetypes.VerificationResult{
		Platform: platform, SignatureValid: true, CollateralVerified: true,
		ReportDataMatch: teetypes.Ptr(true), InitDataMatch: teetypes.Ptr(true),
		Claims: teetypes.Claims{LaunchDigest: strings.Repeat("ab", 48), PlatformData: map[string]any{"policy": map[string]any{"migrate_ma": false}, "td_attributes": "0000000000000000"}},
	}
	if platform == teetypes.PlatformTDX {
		result.TCBStatus = &teetypes.DcapVerificationStatus{TCBStatus: teetypes.TdxUpToDate}
	}
	return result
}

func nativeTestSNP(signer abi.ReportSigner) teetypes.AttestationEvidence {
	report := make([]byte, abi.ReportSize)
	report[0] = 3
	report[0x188] = 0x19
	report[0x48] = byte(abi.ComposeSignerInfo(abi.SignerInfo{SigningKey: signer}))
	report[0x1f0], report[0x1f1], report[0x1f6], report[0x1f7] = 255, 255, 255, 255
	raw, _ := json.Marshal(map[string]string{"attestation_report": base64.StdEncoding.EncodeToString(report)})
	return teetypes.AttestationEvidence{Platform: teetypes.PlatformSNP, Evidence: raw}
}

func TestNativeVerifierRequiresCompleteVerdictAndStrictOptions(t *testing.T) {
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformSNP, teetypes.PlatformTDX} {
		for name, alter := range map[string]func(*teetypes.VerificationResult){
			"valid":          func(*teetypes.VerificationResult) {},
			"signature":      func(r *teetypes.VerificationResult) { r.SignatureValid = false },
			"collateral":     func(r *teetypes.VerificationResult) { r.CollateralVerified = false },
			"report binding": func(r *teetypes.VerificationResult) { r.ReportDataMatch = nil },
			"launch binding": func(r *teetypes.VerificationResult) { r.InitDataMatch = nil },
			"platform":       func(r *teetypes.VerificationResult) { r.Platform = teetypes.PlatformGcpSNP },
			"migration":      func(r *teetypes.VerificationResult) { r.Claims.PlatformData = nil },
			"measurement":    func(r *teetypes.VerificationResult) { r.Claims.LaunchDigest = strings.Repeat("cd", 48) },
		} {
			t.Run(string(platform)+"/"+name, func(t *testing.T) {
				result := nativeTestResult(platform)
				alter(result)
				native, err := NewNativeVerifierWithEngine(nativeTestFloor(), func(ctx context.Context, env teetypes.AttestationEvidence, p teetypes.VerifyParams, o teeverify.Options) (*teetypes.VerificationResult, error) {
					if _, ok := ctx.Deadline(); !ok || env.Platform != platform || p.AllowDebug || !o.SNP.CheckRevocations || !o.TDX.CheckRevocations || !o.TDX.GetCollateral || len(o.TDX.AcceptedTCBStatuses) != 1 || o.TDX.AcceptedTCBStatuses[0] != teetypes.TdxUpToDate {
						t.Fatal("native verification policy weakened")
					}
					if platform == teetypes.PlatformSNP && (p.MinTCB == nil || *p.MinTCB != nativeTestFloor()) {
						t.Fatal("mandatory SNP floor lost")
					}
					return result, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				env := nativeTestSNP(abi.VcekReportSigner)
				if platform == teetypes.PlatformTDX {
					env = teetypes.AttestationEvidence{Platform: platform, Evidence: json.RawMessage(`{"quote":"synthetic"}`)}
				}
				measurement, _ := hex.DecodeString(strings.Repeat("ab", 48))
				_, err = native.VerifyEvidence(t.Context(), env, remote.Policy{ExpectedReportData: make([]byte, 48), ExpectedInitDataHash: make([]byte, 32), Measurements: [][]byte{measurement}})
				if (err == nil) != (name == "valid") {
					t.Fatalf("verdict %q: %v", name, err)
				}
			})
		}
	}
}

func TestNativeSNPFloorCannotBeLoweredAndUnsupportedSignersFailBeforeEngine(t *testing.T) {
	var calls int
	want := nativeTestFloor()
	native, err := NewNativeVerifierWithEngine(nativeTestFloor(), func(_ context.Context, _ teetypes.AttestationEvidence, p teetypes.VerifyParams, _ teeverify.Options) (*teetypes.VerificationResult, error) {
		calls++
		if p.MinTCB == nil || *p.MinTCB != want {
			t.Fatalf("floor = %+v, want %+v", p.MinTCB, want)
		}
		return nativeTestResult(teetypes.PlatformSNP), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := remote.Policy{ExpectedReportData: make([]byte, 48)}
	for _, floor := range []*teetypes.SnpTcb{nil, {Snp: 1}, {Bootloader: 20, Snp: 29}} {
		policy.MinTcb = floor
		if floor != nil && floor.Bootloader == 20 {
			want.Bootloader = 20
			want.Snp = 29
		}
		if _, err := native.VerifyEvidence(t.Context(), nativeTestSNP(abi.VcekReportSigner), policy); err != nil {
			t.Fatal(err)
		}
	}
	before := calls
	if _, err := native.VerifyEvidence(t.Context(), nativeTestSNP(abi.VlekReportSigner), policy); err == nil {
		t.Fatal("accepted unqualified ASVK/VLEK revocation path")
	}
	policy.AllowDebug = true
	if _, err := native.VerifyEvidence(t.Context(), nativeTestSNP(abi.VcekReportSigner), policy); err == nil {
		t.Fatal("debug weakened native policy")
	}
	if calls != before {
		t.Fatal("unsupported profile reached crypto engine")
	}
	if _, err := NewNativeVerifier(teetypes.SnpTcb{}); err == nil {
		t.Fatal("invented default SNP floor")
	}
}

func TestNativeTDXRequiresFreshUpToDateStatus(t *testing.T) {
	for _, status := range []*teetypes.DcapVerificationStatus{nil, {TCBStatus: teetypes.TdxOutOfDate}, {TCBStatus: teetypes.TdxUpToDate, CollateralExpired: true}} {
		native, _ := NewNativeVerifierWithEngine(nativeTestFloor(), func(context.Context, teetypes.AttestationEvidence, teetypes.VerifyParams, teeverify.Options) (*teetypes.VerificationResult, error) {
			r := nativeTestResult(teetypes.PlatformTDX)
			r.TCBStatus = status
			return r, nil
		})
		if _, err := native.VerifyEvidence(t.Context(), teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{}`)}, remote.Policy{ExpectedReportData: make([]byte, 48)}); err == nil {
			t.Fatal("accepted missing, stale or outdated TDX collateral")
		}
	}
}

func TestNativeCertNeverFallsBackToRemoteSuccess(t *testing.T) {
	var calls int
	cert, _ := embeddedEnvelopeCert(t, teetypes.PlatformTDX, json.RawMessage(`{"quote":"invalid"}`))
	want := errors.New("invalid local quote")
	native, _ := NewNativeVerifierWithEngine(nativeTestFloor(), func(context.Context, teetypes.AttestationEvidence, teetypes.VerifyParams, teeverify.Options) (*teetypes.VerificationResult, error) {
		calls++
		return nil, want
	})
	_, err := VerifyCert(cert, &VerifyPolicy{Native: native, AttestationApiURL: "http://127.0.0.1:1", Policy: remote.Policy{Measurements: [][]byte{bytes.Repeat([]byte{0xab}, 48)}}}, nil)
	if !errors.Is(err, want) || calls != 1 {
		t.Fatalf("local rejection fell back: err=%v native=%d", err, calls)
	}
}

func TestNativeCollateralWindowsAndSignedEnvelope(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, window := range [][2]time.Time{{{}, now.Add(time.Hour)}, {now.Add(time.Hour), now.Add(2 * time.Hour)}, {now.Add(-time.Hour), now}, {now, now.Add(-time.Hour)}} {
		if err := checkNativeWindow(window[0], window[1], now); err == nil {
			t.Fatal("accepted missing, future, expired or reversed window")
		}
	}
	qe := `{"issueDate":"` + now.Add(-time.Hour).Format(time.RFC3339) + `","nextUpdate":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}`
	valid := `{"enclaveIdentity":` + qe + `,"signature":"00"}`
	if err := checkNativeSignedWindow([]byte(valid), "enclaveIdentity", now); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"enclaveIdentity":` + qe + `,"ENCLAVEIDENTITY":` + qe + `,"signature":"00"}`,
		`{"enclaveIdentity":` + qe + `,"enclaveIdentity":` + qe + `,"signature":"00"}`,
		`{"ENCLAVEIDENTITY":` + qe + `,"signature":"00"}`,
	} {
		if err := checkNativeSignedWindow([]byte(bad), "enclaveIdentity", now); err == nil {
			t.Fatal("accepted ambiguous signed payload")
		}
	}
}

func TestNativeCRLRejectsExpiredFutureAndDeltaLists(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CRL signer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1}}
	der, err := x509.CreateCertificate(rand.Reader, issuer, issuer, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://kdsintf.amd.com/vcek/v1/Genoa/crl")
	for _, name := range []string{"fresh", "expired", "future", "delta"} {
		t.Run(name, func(t *testing.T) {
			list := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Minute)}
			switch name {
			case "expired":
				list.NextUpdate = now.Add(-time.Second)
			case "future":
				list.ThisUpdate = now.Add(time.Second)
			case "delta":
				list.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Value: []byte{2, 1, 1}}}
			}
			body, err := x509.CreateRevocationList(rand.Reader, list, issuer, key)
			if err != nil {
				t.Fatal(err)
			}
			err = checkNativeCollateral(u, body, now)
			if (err == nil) != (name == "fresh") {
				t.Fatalf("%s: %v", name, err)
			}
		})
	}
}

// These fixtures qualify wrapper policy and admission, not hardware signatures.
func TestNativeVerificationBackpressureCancellationAndIsolation(t *testing.T) {
	entered := make(chan struct{}, nativeVerificationCapacity+1)
	release := make(chan struct{})
	var calls atomic.Int64
	native, err := NewNativeVerifierWithEngine(nativeTestFloor(), func(ctx context.Context, _ teetypes.AttestationEvidence, _ teetypes.VerifyParams, _ teeverify.Options) (*teetypes.VerificationResult, error) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return nativeTestResult(teetypes.PlatformTDX), nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence := teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{}`)}
	policy := remote.Policy{ExpectedReportData: make([]byte, 48)}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	results := make(chan error, nativeVerificationCapacity+1)
	start := func(ctx context.Context) {
		go func() {
			_, err := native.VerifyEvidence(ctx, evidence, policy)
			results <- err
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("verification did not enter")
		}
	}
	for range nativeVerificationCapacity {
		start(ctx)
	}
	if _, err := native.VerifyEvidence(t.Context(), evidence, policy); !errors.Is(err, ErrNativeVerifierBusy) || calls.Load() != nativeVerificationCapacity {
		t.Fatalf("saturated verifier started work: calls=%d err=%v", calls.Load(), err)
	}
	other, err := NewNativeVerifierWithEngine(nativeTestFloor(), func(context.Context, teetypes.AttestationEvidence, teetypes.VerifyParams, teeverify.Options) (*teetypes.VerificationResult, error) {
		return nativeTestResult(teetypes.PlatformTDX), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.VerifyEvidence(t.Context(), evidence, policy); err != nil {
		t.Fatalf("one cluster blocked an independent verifier: %v", err)
	}
	cancel()
	for range nativeVerificationCapacity {
		if err := <-results; !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled verification = %v", err)
		}
	}
	before := calls.Load()
	if _, err := native.VerifyEvidence(ctx, evidence, policy); !errors.Is(err, context.Canceled) || calls.Load() != before {
		t.Fatalf("already canceled request started verification: %v", err)
	}
	start(t.Context())
	close(release)
	if err := <-results; err != nil {
		t.Fatalf("capacity was not recovered: %v", err)
	}
}

func TestNativeSNPLaunchFloorAndTurinRejection(t *testing.T) {
	var calls int
	native, _ := NewNativeVerifierWithEngine(nativeTestFloor(), func(context.Context, teetypes.AttestationEvidence, teetypes.VerifyParams, teeverify.Options) (*teetypes.VerificationResult, error) {
		calls++
		return nativeTestResult(teetypes.PlatformSNP), nil
	})
	for name, change := range map[string]func([]byte){
		"old launch": func(raw []byte) { raw[0x1f6] = 27 },
		"Turin":      func(raw []byte) { raw[0x188] = 0x1a },
	} {
		evidence := nativeTestSNP(abi.VcekReportSigner)
		var envelope map[string]string
		if err := json.Unmarshal(evidence.Evidence, &envelope); err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(envelope["attestation_report"])
		if err != nil {
			t.Fatal(err)
		}
		change(raw)
		envelope["attestation_report"] = base64.StdEncoding.EncodeToString(raw)
		evidence.Evidence, _ = json.Marshal(envelope)
		before := calls
		if _, err := native.VerifyEvidence(t.Context(), evidence, remote.Policy{ExpectedReportData: make([]byte, 48)}); !errors.Is(err, ErrPolicyViolation) {
			t.Fatalf("accepted %s: %v", name, err)
		}
		if name == "Turin" && calls != before {
			t.Fatal("unqualified FMC profile reached the verifier")
		}
	}
}

func TestNativeCollateralRoutesAndTDXProfile(t *testing.T) {
	for _, raw := range []string{
		"https://kdsintf.amd.com/vcek/v1/Genoa/crl",
		"https://kdsintf.amd.com/vcek/v1/Milan/" + strings.Repeat("aa", 64) + "?blSPL=12",
		"https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=00906ed50000",
		"https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity",
		"https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor&encoding=der",
		"https://certificates.trustedservices.intel.com/IntelSGXRootCA.der",
	} {
		u, _ := url.Parse(raw)
		if _, err := nativeCollateralKind(u); err != nil {
			t.Fatalf("current SDK collateral route refused: %s: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"https://kdsintf.amd.com/vlek/v1/Genoa/crl",
		"https://kdsintf.amd.com/vcek/v1/Turin/crl",
		"https://api.trustedservices.intel.com/unknown",
		"https://certificates.trustedservices.intel.com/other.der",
		"https://certificates.trustedservices.intel.com/IntelSGXRootCA.der?scope=other",
	} {
		u, _ := url.Parse(raw)
		if _, err := nativeCollateralKind(u); err == nil {
			t.Fatalf("unknown collateral route accepted: %s", raw)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	module := map[string]any{"mrsigner": strings.Repeat("ab", 48), "attributes": strings.Repeat("00", 8), "attributesMask": strings.Repeat("ff", 8)}
	for _, test := range []string{"valid", "missing type", "unsupported type", "divergent module", "unsigned alias"} {
		info := map[string]any{"issueDate": now.Add(-time.Hour), "nextUpdate": now.Add(time.Hour), "tcbType": 0, "tdxModule": module}
		switch test {
		case "missing type":
			delete(info, "tcbType")
		case "unsupported type":
			info["tcbType"] = 1
		case "divergent module":
			info["tdxModuleIdentities"] = []any{map[string]any{"id": "TDX_01", "mrsigner": module["mrsigner"], "attributes": module["attributes"], "attributesMask": strings.Repeat("00", 8)}}
		}
		wrapper := map[string]any{"tcbInfo": info, "signature": "00"}
		if test == "unsigned alias" {
			wrapper["TCBINFO"] = info
		}
		body, _ := json.Marshal(wrapper)
		if err := checkNativeSignedWindow(body, "tcbInfo", now); (err == nil) != (test == "valid") {
			t.Fatalf("%s: %v", test, err)
		}
	}
}

func TestNativePinRefreshRetainsCryptoFloorAndMigrationPolicy(t *testing.T) {
	for name, follow := range map[string]func(*tls.Config, PinSource, *NativeVerifier){"server": FollowNativeServerPins, "client": FollowNativeClientPins} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			migrate := false
			native, _ := NewNativeVerifierWithEngine(nativeTestFloor(), func(_ context.Context, _ teetypes.AttestationEvidence, params teetypes.VerifyParams, opts teeverify.Options) (*teetypes.VerificationResult, error) {
				calls++
				if params.MinTCB == nil || *params.MinTCB != nativeTestFloor() || !opts.SNP.CheckRevocations {
					t.Fatal("refreshed policy lost native floor or revocation")
				}
				result := nativeTestResult(teetypes.PlatformSNP)
				result.Claims.LaunchDigest = hex.EncodeToString(imageDigest("approved"))
				result.Claims.PlatformData["policy"] = map[string]any{"migrate_ma": migrate}
				return result, nil
			})
			cert, _ := embeddedEnvelopeCert(t, teetypes.PlatformSNP, nativeTestSNP(abi.VcekReportSigner).Evidence)
			pins := &movingPins{current: "old", next: "approved"}
			cfg := &tls.Config{MinVersion: tls.VersionTLS13}
			follow(cfg, pins, native)
			if err := cfg.VerifyPeerCertificate([][]byte{cert.Raw}, nil); err != nil || calls != 2 || pins.looks() != 1 {
				t.Fatalf("native refreshed handshake: calls=%d err=%v", calls, err)
			}
			migrate = true
			if err := cfg.VerifyPeerCertificate([][]byte{cert.Raw}, nil); err == nil {
				t.Fatal("refreshed pins admitted a migratable peer")
			}
		})
	}
}

type nativeTestTransport func(*http.Request) (*http.Response, error)

func (f nativeTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestNativeCollateralOutageRemainsAvailabilityAfterSDKFormatting(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusBadRequest, http.StatusOK} {
		native, _ := NewNativeVerifierWithEngine(nativeTestFloor(), func(_ context.Context, _ teetypes.AttestationEvidence, _ teetypes.VerifyParams, options teeverify.Options) (*teetypes.VerificationResult, error) {
			fetch := options.TDX.Getter.(nativeTDXFetch)
			fetch.client.Transport = nativeTestTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("malformed collateral"))}, nil
			})
			_, _, err := fetch.Get("https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity")
			return nil, fmt.Errorf("SDK layer using %%v: %v", err)
		})
		_, err := native.VerifyEvidence(t.Context(), teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{}`)}, remote.Policy{ExpectedReportData: make([]byte, 48)})
		wantUnavailable := status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests
		if errors.Is(err, ErrNativeCollateralUnavailable) != wantUnavailable || err == nil {
			t.Fatalf("status %d: %v", status, err)
		}
	}
}
