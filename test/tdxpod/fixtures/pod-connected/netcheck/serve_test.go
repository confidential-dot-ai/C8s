package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// roundTrip answers each request from a function; no network is used.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResponse(status int, body any) *http.Response {
	data, _ := json.Marshal(body)
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(data))), Header: http.Header{}}
}

func testApp(cfg config) *app {
	return &app{cfg: cfg, instance: strings.Repeat("f", 32), now: func() float64 { return 0 }, sleep: func(time.Duration) {}, out: io.Discard, checks: map[string]checkResult{}}
}

func sixChecks(ok bool) map[string]checkResult {
	checks := map[string]checkResult{}
	for _, name := range checkNames {
		checks[name] = checkResult{OK: ok}
	}
	return checks
}

func TestResponderRequiresFreshExactPeerReceipt(t *testing.T) {
	a := testApp(config{Role: "responder", InitiatorPodUID: "run-b"})
	a.now = func() float64 { return 10 }
	if _, err := a.peerMesh(); err == nil {
		t.Fatal("responder passed without a receipt")
	}
	if a.recordInbound(strings.Repeat("a", 32), "other-run") {
		t.Fatal("accepted a receipt from another pod")
	}
	if !a.recordInbound(strings.Repeat("a", 32), "run-b") {
		t.Fatal("refused the initiator's receipt")
	}
	if a.recordInbound(strings.Repeat("b", 32), "run-b") {
		t.Fatal("accepted a second distinct instance")
	}
	if a.recordInbound(strings.Repeat("A", 32), "run-b") || a.recordInbound(a.instance, "run-b") {
		t.Fatal("accepted an instance that is not 32 lowercase hex or is this one")
	}
	detail, err := a.peerMesh()
	if err != nil {
		t.Fatal(err)
	}
	if detail.(map[string]any)["inboundReceipt"].(*receipt).PodUID != "run-b" {
		t.Fatal("receipt does not name the initiator")
	}
	a.now = func() float64 { return 101 }
	if _, err := a.peerMesh(); err == nil {
		t.Fatal("a receipt older than the freshness window passed")
	}
}

func TestInitiatorUsesAllocatedPortAndVerifiesResponder(t *testing.T) {
	a := testApp(config{Role: "initiator", PodUID: "run-b", Peer: &peerConfig{Host: "203.0.113.5", Port: 41080, PodUID: "run-a"}})
	answer := map[string]any{"instance": strings.Repeat("a", 32), "podUID": "run-a"}
	a.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "203.0.113.5:41080" || r.URL.Path != "/id" || r.Header.Get("X-Acceptance-Instance") != a.instance || r.Header.Get("X-Acceptance-Pod") != "run-b" {
			return nil, errors.New("dialled the wrong tuple or omitted the acceptance headers")
		}
		if deadline, ok := r.Context().Deadline(); !ok || time.Until(deadline) > 4*time.Second {
			return nil, errors.New("no 4s timeout")
		}
		return jsonResponse(http.StatusOK, answer), nil
	})
	detail, err := a.peerMesh()
	if err != nil {
		t.Fatal(err)
	}
	if detail.(map[string]any)["endpoint"] != "203.0.113.5:41080" {
		t.Fatal("initiator did not report the allocated tuple")
	}
	answer["podUID"] = "foreign"
	if _, err := a.peerMesh(); err == nil {
		t.Fatal("accepted a responder answering for another pod")
	}
	answer["podUID"], answer["instance"] = "run-a", a.instance
	if _, err := a.peerMesh(); err == nil {
		t.Fatal("accepted its own instance as the responder")
	}
}

func TestReadinessDependsOnNetworkAndHasObservableTransitions(t *testing.T) {
	a := testApp(config{PodUID: "test"})
	first := 0.0
	a.firstPass = &first
	a.checks = sixChecks(true)
	for _, tc := range []struct {
		now  float64
		want bool
	}{{119, false}, {120, true}, {299, true}, {300, false}, {479, false}, {480, true}} {
		now := tc.now
		a.now = func() float64 { return now }
		a.checkedAt = &now
		if got := a.report()["ready"].(bool); got != tc.want {
			t.Fatalf("at %v ready=%v, want %v", tc.now, got, tc.want)
		}
	}
	a.now = func() float64 { return 600 }
	if a.report()["ready"].(bool) {
		t.Fatal("a stale round kept the pod ready")
	}
	checked := 600.0
	a.checkedAt = &checked
	a.checks[checkNames[0]] = checkResult{OK: false}
	if a.report()["ready"].(bool) {
		t.Fatal("a failed check kept the pod ready")
	}
	a.checks = map[string]checkResult{}
	if a.report()["ready"].(bool) {
		t.Fatal("no checks at all counted as ready")
	}
}

func TestHandlerRoutesAndResponderReceipt(t *testing.T) {
	a := testApp(config{Role: "responder", PodUID: "run-a", InitiatorPodUID: "run-b"})
	get := func(path string, headers map[string]string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, req)
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("%s: not a JSON answer", path)
		}
		return rec.Code, body
	}
	if code, body := get("/ready", nil); code != http.StatusServiceUnavailable || body["ready"] != false {
		t.Fatal("an application without a round is ready")
	}
	if code, body := get("/live", nil); code != http.StatusOK || body["instance"] != a.instance || body["podUID"] != "run-a" {
		t.Fatal("/live does not identify the instance")
	}
	if code, body := get("/id", map[string]string{"X-Acceptance-Instance": strings.Repeat("c", 32), "X-Acceptance-Pod": "other"}); code != http.StatusForbidden || body["instance"] != a.instance {
		t.Fatal("a foreign caller was not refused with the identity body")
	}
	if code, _ := get("/id", map[string]string{"X-Acceptance-Instance": strings.Repeat("c", 32), "X-Acceptance-Pod": "run-b"}); code != http.StatusOK {
		t.Fatal("the initiator was refused")
	}
	if code, body := get("/report", nil); code != http.StatusOK || body["inboundReceipt"] == nil {
		t.Fatal("/report does not carry the receipt")
	}
	if code, body := get("/nothing", nil); code != http.StatusNotFound || len(body) != 0 {
		t.Fatal("an unknown path is not 404 with an empty object")
	}
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/id", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatal("a POST was served")
	}
}

func TestHelloAnswersOnlyTheProbes(t *testing.T) {
	for path, want := range map[string]int{"/live": http.StatusOK, "/ready": http.StatusOK, "/id": http.StatusNotFound, "/report": http.StatusNotFound} {
		rec := httptest.NewRecorder()
		hello(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Fatalf("%s: %d, want %d", path, rec.Code, want)
		}
	}
}

func TestConfigRoundTripsThroughArgv(t *testing.T) {
	raw := `{"peers":["10.0.0.1","10.0.0.2"],"dnsIPv4":"1.1.1.1","podUID":"run","collectorURL":"http://collector/","role":"initiator","peer":{"host":"10.0.0.1","port":41080,"podUID":"run-a"},"initiatorPodUID":"run-b"}`
	cfg, err := parseConfig(raw)
	if err != nil || cfg.PodUID != "run" || len(cfg.Peers) != 2 || cfg.Peer == nil || cfg.Peer.Port != 41080 || cfg.DNSIPv4 != "1.1.1.1" || cfg.CollectorURL != "http://collector/" || cfg.InitiatorPodUID != "run-b" {
		t.Fatalf("config lost a field: %+v %v", cfg, err)
	}
	if _, err := parseConfig("not json"); err == nil {
		t.Fatal("accepted a config that is not JSON")
	}
	if code := run([]string{"serve", "not json"}); code != 2 {
		t.Fatal("serve started on a config that is not JSON")
	}
	if code := run(nil); code != 2 {
		t.Fatal("no mode did not fail usage")
	}
}
