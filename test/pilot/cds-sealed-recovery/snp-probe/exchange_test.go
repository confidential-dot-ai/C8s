//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-sev-guest/verify"
)

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
