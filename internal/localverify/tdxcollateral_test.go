package localverify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// The signed fixture rates this platform OutOfDate at the capture time.
var recordedPCSTime = time.Date(2026, time.November, 17, 22, 30, 0, 0, time.UTC)

type recordedPCS struct {
	responses map[string]struct {
		Header map[string][]string `json:"header"`
		Body   []byte              `json:"body"`
	}
	tamper func(url string, body []byte) []byte

	mu       sync.Mutex
	requests int
}

func (r *recordedPCS) Get(url string) (map[string][]string, []byte, error) {
	r.mu.Lock()
	r.requests++
	r.mu.Unlock()
	resp, ok := r.responses[url]
	if !ok {
		return nil, nil, errors.New("no recorded response for " + url)
	}
	body := bytes.Clone(resp.Body)
	if r.tamper != nil {
		body = r.tamper(url, body)
	}
	return resp.Header, body, nil
}

func useRecordedPCS(t *testing.T, getter tdxtrust.HTTPSGetter) {
	t.Helper()
	prevGetter, prevTime := pcsGetter, tdxCollateralTime
	pcsGetter = func() tdxtrust.HTTPSGetter { return getter }
	tdxCollateralTime = recordedPCSTime
	t.Cleanup(func() { pcsGetter, tdxCollateralTime = prevGetter, prevTime })
}

func loadRecordedPCS(t *testing.T) *recordedPCS {
	t.Helper()
	data, err := os.ReadFile("testdata/tdx-pcs-collateral.json")
	if err != nil {
		t.Fatal(err)
	}
	r := &recordedPCS{}
	if err := json.Unmarshal(data, &r.responses); err != nil {
		t.Fatal(err)
	}
	return r
}

type failingPCS struct{ err error }

func (f failingPCS) Get(string) (map[string][]string, []byte, error) { return nil, nil, f.err }

func TestVerifyTDXTCBStatus(t *testing.T) {
	platform, evidence := envelopeFixture(t, "tdx-evidence.json")
	upToDate := []teetypes.TdxTcbStatus{teetypes.TdxUpToDate}

	t.Run("OutOfDate platform is rejected when only UpToDate is accepted", func(t *testing.T) {
		useRecordedPCS(t, loadRecordedPCS(t))
		_, _, err := VerifyWithCollateralExpiry(context.Background(), platform, evidence, Params{TDXTCBStatuses: upToDate})
		if err == nil || !strings.Contains(err.Error(), "OutOfDate is not accepted") {
			t.Fatalf("want an OutOfDate rejection, got %v", err)
		}
		if _, ok := errors.AsType[*CollateralError](err); ok {
			t.Fatalf("a rejected TCB status is a verdict, not unavailable collateral: %v", err)
		}
	})

	t.Run("accepted status is reported with the collateral expiry", func(t *testing.T) {
		pcs := loadRecordedPCS(t)
		useRecordedPCS(t, pcs)
		res, collateral, err := VerifyWithCollateralExpiry(context.Background(), platform, evidence, Params{
			TDXTCBStatuses: []teetypes.TdxTcbStatus{teetypes.TdxUpToDate, teetypes.TdxOutOfDate},
		})
		if err != nil {
			t.Fatalf("an accepted status must verify: %v", err)
		}
		if res.TCBStatus == nil || res.TCBStatus.TCBStatus != teetypes.TdxOutOfDate {
			t.Fatalf("TCB status = %+v, want OutOfDate", res.TCBStatus)
		}
		if want := time.Date(2026, time.December, 17, 21, 30, 1, 0, time.UTC); collateral == nil || !collateral.Equal(want) {
			t.Fatalf("collateral = %+v, want NextUpdate %s", collateral, want)
		}
		if pcs.requests != 4 {
			t.Fatalf("PCS requests = %d, want 4 (TCB info, QE identity, PCK CRL, root CRL)", pcs.requests)
		}
	})

	t.Run("collateral rewritten to UpToDate fails its Intel signature", func(t *testing.T) {
		pcs := loadRecordedPCS(t)
		pcs.tamper = func(url string, body []byte) []byte {
			if strings.Contains(url, "/tcb?") {
				return bytes.ReplaceAll(body, []byte(`"OutOfDate"`), []byte(`"UpToDate"`))
			}
			return body
		}
		useRecordedPCS(t, pcs)
		_, _, err := VerifyWithCollateralExpiry(context.Background(), platform, evidence, Params{TDXTCBStatuses: upToDate})
		if err == nil {
			t.Fatal("collateral whose signature does not verify must be refused")
		}
		if _, ok := errors.AsType[*CollateralError](err); ok {
			t.Fatalf("forged collateral is a verdict, not unavailable collateral: %v", err)
		}
	})

	t.Run("expired collateral is refused", func(t *testing.T) {
		useRecordedPCS(t, loadRecordedPCS(t))
		tdxCollateralTime = recordedPCSTime.AddDate(0, 2, 0)
		if _, _, err := VerifyWithCollateralExpiry(context.Background(), platform, evidence, Params{
			TDXTCBStatuses: []teetypes.TdxTcbStatus{teetypes.TdxOutOfDate},
		}); err == nil {
			t.Fatal("collateral past its nextUpdate must be refused")
		}
	})

	t.Run("unreachable PCS is a CollateralError", func(t *testing.T) {
		useRecordedPCS(t, failingPCS{err: errors.New("connection refused")})
		_, _, err := VerifyWithCollateralExpiry(context.Background(), platform, evidence, Params{TDXTCBStatuses: upToDate})
		if _, ok := errors.AsType[*CollateralError](err); !ok {
			t.Fatalf("want CollateralError, got %v", err)
		}
	})

	t.Run("the fetch is bounded by ctx", func(t *testing.T) {
		prev := pcsGetter
		t.Cleanup(func() { pcsGetter = prev })
		pcsGetter = func() tdxtrust.HTTPSGetter {
			return &tdxtrust.RetryHTTPSGetter{Timeout: time.Minute, MaxRetryDelay: 10 * time.Millisecond, Getter: failingPCS{err: errors.New("unreachable")}}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, _, err := VerifyWithCollateralExpiry(ctx, platform, evidence, Params{TDXTCBStatuses: upToDate})
		if _, ok := errors.AsType[*CollateralError](err); !ok {
			t.Fatalf("want CollateralError, got %v", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("fetch took %s, want it ended by the 200ms context", elapsed)
		}
	})

	t.Run("without accepted statuses TDX verifies offline", func(t *testing.T) {
		pcs := loadRecordedPCS(t)
		useRecordedPCS(t, pcs)
		res, collateral, err := VerifyWithCollateralExpiry(context.Background(), platform, evidence, Params{})
		if err != nil {
			t.Fatalf("offline TDX verification: %v", err)
		}
		if pcs.requests != 0 || res.TCBStatus != nil || collateral != nil {
			t.Fatalf("offline verification fetched %d PCS responses, status %+v, collateral %+v", pcs.requests, res.TCBStatus, collateral)
		}
	})
}

func TestParseTDXTCBStatus(t *testing.T) {
	if got, err := ParseTDXTCBStatus("SWHardeningNeeded"); err != nil || got != teetypes.TdxSWHardeningNeeded {
		t.Fatalf("ParseTDXTCBStatus(SWHardeningNeeded) = %q, %v", got, err)
	}
	for _, s := range []string{"Revoked", "uptodate", ""} {
		if _, err := ParseTDXTCBStatus(s); err == nil {
			t.Errorf("ParseTDXTCBStatus(%q) must fail", s)
		}
	}
}

func TestTDXCollateralExpiryIncludesCRLs(t *testing.T) {
	responses := loadRecordedPCS(t).responses
	bodies := make(map[string][]byte, len(responses))
	for url, response := range responses {
		bodies[url] = response.Body
	}
	tcbURL := pcs.TcbInfoURL("b0c06f000000")
	bodies[tcbURL] = []byte(`{"tcbInfo":{"nextUpdate":"2028-01-01T00:00:00Z"}}`)
	bodies[pcs.QeIdentityURL()] = []byte(`{"enclaveIdentity":{"nextUpdate":"2028-01-01T00:00:00Z"}}`)
	fetch := &collateralFetch{bodies: bodies}
	got, err := fetch.earliestNextUpdate("b0c06f000000")
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, time.December, 17, 21, 31, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("collateral expiry = %s, want PCK CRL expiry %s", got, want)
	}
	rootURL := "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
	bodies[rootURL] = bytes.Replace(bodies[rootURL], []byte("270226130400Z"), []byte("261217212900Z"), 1)
	got, err = fetch.earliestNextUpdate("b0c06f000000")
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, time.December, 17, 21, 29, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("collateral expiry = %s, want root CRL expiry %s", got, want)
	}
}

func TestPCSFetchRecovery(t *testing.T) {
	fetch := collateralFetch{ctx: t.Context(), inner: loadRecordedPCS(t), bodies: make(map[string][]byte)}
	if _, _, err := fetch.Get("unavailable"); err == nil || fetch.failure() == nil {
		t.Fatal("missing response must record a fetch failure")
	}
	if _, _, err := fetch.Get(pcs.QeIdentityURL()); err != nil || fetch.failure() != nil {
		t.Fatalf("successful response must clear the earlier fetch failure: %v", err)
	}
}
