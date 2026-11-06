package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifierNeverAttestsOrAcceptsUnsupportedPolicy(t *testing.T) {
	for _, v := range []struct{ path, body string }{{"/attest", `{}`}, {"/verify", `{"platform":"sev-snp","params":{}}`}, {"/verify", `{"platform":"tdx"}`}, {"/verify", `{"platform":"tdx","params":{"allow_debug":true}}`}} {
		w := httptest.NewRecorder()
		verifyTDX(w, httptest.NewRequest("POST", v.path, strings.NewReader(v.body)))
		if w.Code < 400 {
			t.Fatalf("unsupported operation accepted: %s", v.path)
		}
	}
}

func TestPhaseWaitsForDelayedHeadersWithinBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(40 * time.Millisecond)
		_, _ = w.Write([]byte("completed phase"))
	}))
	defer server.Close()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	transport := &http.Transport{TLSClientConfig: tlsConfig, ResponseHeaderTimeout: time.Millisecond}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	if err := phaseTimeout(client, time.Second); err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "completed phase" {
		t.Fatalf("phase response: %q, %v", body, err)
	}
	if client.Transport != transport || transport.TLSClientConfig != tlsConfig {
		t.Fatal("phase timeout replaced the verified TLS transport")
	}
}
