//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
)

type refusingKDS struct{ urls []string }

func (k *refusingKDS) Get(url string) ([]byte, error) {
	k.urls = append(k.urls, url)
	return nil, errors.New("offline test refuses certificate fetch")
}

func TestV2VerifierUsesExplicitRemoteProductAndFailsClosed(t *testing.T) {
	for _, invalid := range []string{"", "Unknown", "genoa", "Genoa-B1"} {
		if err := request([]string{"-product-line", invalid}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "expected AMD product") {
			t.Fatalf("missing/invalid product reached request: %q: %v", invalid, err)
		}
	}
	d, _, _ := deviceFixture()
	for _, product := range []string{"Milan", "Genoa", "Turin"} {
		opts, err := verificationOptions(product)
		if err != nil || !opts.CheckRevocations || opts.DisableCertFetching || len(opts.TrustedRoots) != 0 {
			t.Fatalf("weakened verification for %s: %v", product, err)
		}
		getter := &refusingKDS{}
		opts.Getter = getter
		if err := verify.SnpReport(d.report, opts); err == nil {
			t.Fatal("unverified report accepted")
		}
		want := "https://kdsintf.amd.com/vcek/v1/" + product + "/cert_chain"
		if len(getter.urls) != 1 || getter.urls[0] != want {
			t.Fatalf("remote product %s selected endpoints %v", product, getter.urls)
		}
	}
}

func TestSignedCPUIDCannotOverrideExpectedProduct(t *testing.T) {
	for _, product := range []string{"Milan", "Genoa", "Turin"} {
		opts, _ := verificationOptions(product)
		r := &spb.Report{Version: 3, Cpuid1EaxFms: abi.MaskedCpuid1EaxFromSevProduct(opts.Product)}
		if err := checkReportProduct(r, product); err != nil {
			t.Fatal(err)
		}
		for _, different := range []string{"Milan", "Genoa", "Turin"} {
			if different != product && checkReportProduct(r, different) == nil {
				t.Fatalf("%s report accepted for %s", product, different)
			}
		}
	}
	if checkReportProduct(&spb.Report{Version: 3, Cpuid1EaxFms: 1}, "Genoa") == nil {
		t.Fatal("unknown signed CPUID accepted")
	}
}

func TestZen4cUsesExistingVerifierWithoutChangingSignedBytes(t *testing.T) {
	d, _, _ := deviceFixture()
	d.report.Version, d.report.Cpuid1EaxFms = 5, 0xaa0f02
	d.report.ChipId = bytes.Repeat([]byte{9}, 64)
	d.report.ReportData = make([]byte, 64)
	raw, err := abi.ReportToAbiBytes(d.report)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(raw)
	opts, _ := verificationOptions("Genoa")
	getter := &refusingKDS{}
	opts.Getter = getter
	if err := verifyHardwareReport(context.Background(), raw, opts); err == nil {
		t.Fatal("missing AMD collateral accepted")
	}
	want := kds.VCEKCertURL("Genoa", d.report.ChipId, kds.TCBVersion(d.report.ReportedTcb))
	if len(getter.urls) != 1 || getter.urls[0] != want || !bytes.Equal(raw, original) {
		t.Fatalf("wrong Zen4c endpoint or modified report: %v", getter.urls)
	}
	opts, _ = verificationOptions("Milan")
	getter.urls = nil
	opts.Getter = getter
	if err := verifyHardwareReport(context.Background(), raw, opts); err == nil || len(getter.urls) != 0 {
		t.Fatal("wrong expected product reached certificate fetch")
	}
}

func TestExchangeBindsFreshRequestResultAndChip(t *testing.T) {
	d, measurement, launch := deviceFixture()
	d.report.ChipId = bytes.Repeat([]byte{9}, 64)
	d.report.ReportId = bytes.Repeat([]byte{7}, 32)
	req := probeRequest{Operation: "seal", Measurement: hex.EncodeToString(measurement), Nonce: bytes.Repeat([]byte{1}, 32)}
	r, err := exchange(d, launch, req)
	if err != nil || checkReply(req, r, launch) != nil {
		t.Fatalf("exchange: %v", err)
	}
	// The software fixture satisfies shape/binding checks but MUST NOT pass
	// the mandatory independent AMD signature verification in the client.
	opts := verify.DefaultOptions()
	opts.DisableCertFetching = true
	if err := verify.RawSnpReport(r.Report, opts); err == nil {
		t.Fatal("software fixture accepted as AMD evidence")
	}
	for _, field := range []string{"nonce", "measurement", "launch", "result", "capsule", "acceptance"} {
		t.Run(field, func(t *testing.T) {
			b, _ := json.Marshal(r)
			var changed probeReply
			_ = json.Unmarshal(b, &changed)
			request := req
			config := bytes.Clone(launch)
			switch field {
			case "nonce":
				request.Nonce = bytes.Repeat([]byte{2}, 32)
			case "measurement":
				request.Measurement = hex.EncodeToString(bytes.Repeat([]byte{3}, 48))
			case "launch":
				config[0] ^= 1
			case "result":
				changed.Result.Outcome = "rejected"
			case "capsule":
				changed.Result.Capsule.Ciphertext[0] ^= 1
			case "acceptance":
				changed.Result.FullAcceptancePassed = true
			}
			if checkReply(request, changed, config) == nil {
				t.Fatal("accepted substituted exchange")
			}
		})
	}
	open := req
	open.Operation, open.Capsule = "open", r.Result.Capsule
	opened, err := exchange(d, launch, open)
	if err != nil || opened.Result.Outcome != "opened" || checkReply(open, opened, launch) != nil {
		t.Fatalf("open: %v", err)
	}
	d.root++
	d.report.ChipId[0]++
	rejected, err := exchange(d, launch, open)
	if err != nil || rejected.Result.Outcome != "rejected" || checkReply(open, rejected, launch) != nil {
		t.Fatalf("different simulated chip: %v", err)
	}
	// A lost network response is not a verified hardware refusal.
	if checkReply(open, probeReply{Result: probeResult{Outcome: "rejected"}}, launch) == nil {
		t.Fatal("missing report accepted as rejection")
	}
}

func TestExchangeDoesNotCountKeyFailuresAsRejection(t *testing.T) {
	d, measurement, launch := deviceFixture()
	req := probeRequest{Operation: "seal", Measurement: hex.EncodeToString(measurement), Nonce: bytes.Repeat([]byte{1}, 32)}
	sealed, err := exchange(d, launch, req)
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"device", "firmware", "foreign launch"} {
		t.Run(failure, func(t *testing.T) {
			next, _, _ := deviceFixture()
			capsule := *sealed.Result.Capsule
			open := req
			open.Operation, open.Capsule = "open", &capsule
			switch failure {
			case "device":
				next.keyError = errors.New("device unavailable")
			case "firmware":
				next.keyStatus = 1
			case "foreign launch":
				capsule.LaunchSHA256 = hex.EncodeToString(bytes.Repeat([]byte{9}, 32))
			}
			reply, err := exchange(next, launch, open)
			if err == nil || reply.Result.Outcome == "rejected" || len(reply.Report) != 0 {
				t.Fatal("operational failure counted as cryptographic rejection")
			}
		})
	}
}

func TestExchangeBackpressureAndSingleDeviceOwner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}, 128), make(chan struct{})
	var active atomic.Int32
	h, _ := probeHandler(ctx, func(probeRequest) (probeReply, error) {
		if active.Add(1) != 1 {
			t.Error("concurrent firmware access")
		}
		defer active.Add(-1)
		entered <- struct{}{}
		<-release
		return probeReply{}, nil
	})
	defer close(release)
	req := probeRequest{Operation: "seal", Measurement: hex.EncodeToString(bytes.Repeat([]byte{1}, 48)), Nonce: bytes.Repeat([]byte{2}, 32)}
	body, _ := json.Marshal(req)
	var wg sync.WaitGroup
	statuses := make(chan int, 128)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodPost, "/v1/probe", bytes.NewReader(body)).WithContext(ctx)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			statuses <- w.Code
		}()
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("actor did not start")
	}
	select {
	case status := <-statuses:
		if status != http.StatusTooManyRequests {
			t.Fatalf("queue overflow returned %d", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("unbounded queue accepted all work")
	}
	cancel()
	wg.Wait()
	if len(entered) != 0 {
		t.Fatal("actor processed queued work while device was busy")
	}
}

func TestExchangeRejectsInputWithoutTouchingHardware(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h, _ := probeHandler(ctx, func(probeRequest) (probeReply, error) {
		t.Error("invalid input reached device")
		return probeReply{}, nil
	})
	for _, body := range []string{`null`, `{"operation":"seal","operation":"open"}`, `{} {}`, `{"unknown":1}`, string(bytes.Repeat([]byte("x"), exchangeLimit+1))} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/probe", bytes.NewBufferString(body)))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid input returned %d", w.Code)
		}
	}
}
