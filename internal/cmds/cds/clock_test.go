package cds

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func TestClockQuarantineHTTPOnExistingConnection(t *testing.T) {
	var fault atomic.Bool
	reason := errors.New("this replica's clock lags another member")
	clock := func() error {
		if fault.Load() {
			return reason
		}
		return nil
	}
	serving := func() cdsha.Serving { return cdsha.Serving{OK: !fault.Load(), Reason: reason.Error()} }
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(haGate(serving, clock, next))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	client := server.Client()
	for _, latched := range []bool{false, true} {
		fault.Store(latched)
		for _, tt := range []struct {
			method, path string
			quarantined  int
		}{
			{"GET", "/allowlist", 503}, {"GET", "/readyz", 503}, {"POST", "/ha/decrees", 503},
			{"GET", "/ha/decrees", 204}, {"GET", "/ha/status", 204}, {"GET", "/healthz", 204}, {"GET", "/metrics", 204},
		} {
			req, err := http.NewRequest(tt.method, server.URL+tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			want := http.StatusNoContent
			if latched {
				want = tt.quarantined
			}
			if resp.StatusCode != want || (want == 503 && !strings.Contains(string(body), reason.Error())) {
				t.Fatalf("%s %s latched=%v: %d %s", tt.method, tt.path, latched, resp.StatusCode, body)
			}
		}
	}
	if connections.Load() != 1 {
		t.Fatalf("used %d connections, want the original socket", connections.Load())
	}
}

func TestClockBeforeObservationFutureTokenStillGetsUnauthorized(t *testing.T) {
	key, _ := operatorKeyPair(t)
	body := []byte(anySeed(map[string]string{"cds": digestA}))
	sum := sha256.Sum256(body)
	issued := time.Now().Add(time.Minute)
	token, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat": issued.Unix(), "exp": issued.Add(30 * time.Second).Unix(),
		"htm": http.MethodPut, "htu": "/allowlist", "pbh": base64.RawURLEncoding.EncodeToString(sum[:]),
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	handler := allowlist.Handler{Allowlist: inMemoryStore(t), WriteAuthorizer: operatorauth.Verifier{Keys: []*ecdsa.PublicKey{&key.PublicKey}, ClockSkew: 30 * time.Second}.Authorize}
	gated := haGate(func() cdsha.Serving { return cdsha.Serving{OK: true} }, func() error { return nil }, http.HandlerFunc(handler.HandleReplaceAll))
	request := httptest.NewRequest(http.MethodPut, "/allowlist", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	gated.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("future token before observation = %d: %s", response.Code, response.Body.String())
	}
}

func TestClockGateDiagnosticsDoNotConsultServing(t *testing.T) {
	gated := haGate(func() cdsha.Serving { t.Error("exempt route consulted Serving"); return cdsha.Serving{} },
		func() error { return nil }, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, path := range []string{"/healthz", "/metrics", "/ha/status", "/ha/pins", "/ha/decrees"} {
		response := httptest.NewRecorder()
		gated.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNoContent {
			t.Errorf("GET %s = %d", path, response.Code)
		}
	}
}
