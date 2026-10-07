package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// TestClassifyVerifyError mirrors internal/cmds/cds.TestClassifyVerifyError: a
// rejected verdict is the caller's 401/422, only a transport or 5xx/408/429
// outage is a 502. The api-422 row is the shape mock-attestation returns for a
// report-data mismatch or garbage evidence. The non-json rows are the second
// arm: a body-rejection status with a body is a rejection, anything else on
// that type is an outage.
func TestClassifyVerifyError(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "signature invalid",
			err:        fmt.Errorf("wrap: %w", remote.ErrSignatureInvalid),
			wantStatus: http.StatusUnauthorized,
			wantCode:   types.ErrorCodeVerificationFailed,
		},
		{
			name:       "report data mismatch",
			err:        fmt.Errorf("wrap: %w", remote.ErrReportDataMismatch),
			wantStatus: http.StatusUnauthorized,
			wantCode:   types.ErrorCodeVerificationFailed,
		},
		{
			name:       "api 400 is client fault",
			err:        &remote.APIError{Status: http.StatusBadRequest},
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   types.ErrorCodeVerificationFailed,
		},
		{
			name:       "api 403 is client fault",
			err:        &remote.APIError{Status: http.StatusForbidden},
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   types.ErrorCodeVerificationFailed,
		},
		{
			name:       "api 422 is a mismatch or garbage refusal",
			err:        &remote.APIError{Status: http.StatusUnprocessableEntity},
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   types.ErrorCodeVerificationFailed,
		},
		{
			name:       "api 500 is upstream outage",
			err:        &remote.APIError{Status: http.StatusInternalServerError},
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
		},
		{
			name:       "api 408 is retryable unavailability",
			err:        &remote.APIError{Status: http.StatusRequestTimeout},
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
		},
		{
			name:       "api 429 is retryable unavailability",
			err:        &remote.APIError{Status: http.StatusTooManyRequests},
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
		},
		{
			name:       "non-json 400 is a request rejection",
			err:        fmt.Errorf("wrap: %w", &remote.UnexpectedError{Status: http.StatusBadRequest, Text: "Failed to parse the request body as JSON"}),
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   types.ErrorCodeVerificationFailed,
		},
		{
			name:       "non-json 415 is a request rejection",
			err:        fmt.Errorf("wrap: %w", &remote.UnexpectedError{Status: http.StatusUnsupportedMediaType, Text: "Expected request with `Content-Type: application/json`"}),
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   types.ErrorCodeVerificationFailed,
		},
		{
			name:       "non-json 400 with no body is an outage",
			err:        fmt.Errorf("wrap: %w", &remote.UnexpectedError{Status: http.StatusBadRequest}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
		},
		{
			name:       "non-json 403 is an outage",
			err:        fmt.Errorf("wrap: %w", &remote.UnexpectedError{Status: http.StatusForbidden, Text: "<html>403 Forbidden</html>"}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
		},
		{
			name:       "non-json 500 is upstream outage",
			err:        fmt.Errorf("wrap: %w", &remote.UnexpectedError{Status: http.StatusInternalServerError, Text: "<html>500 Internal Server Error</html>"}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
		},
		{
			name:       "transport failure is unreachable",
			err:        fmt.Errorf("wrap: %w", &remote.RequestError{Err: errors.New("dial tcp: connection refused")}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, code, msg := classifyVerifyError(tc.err)
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q", code, tc.wantCode)
			}
			if msg == "" {
				t.Error("message empty")
			}
		})
	}
}

// TestVerifySandboxToken covers what the mock promises an integration run: a
// leaf only ever names a sandbox an inventory signed for this requester key and
// this challenge.
func TestVerifySandboxToken(t *testing.T) {
	const sandboxID = "3c8f1d0b7a46e95281cf0a3d6b7e5419f2a8c04d1e6b93758af2c05d9e314b67"
	host := routableIPv4(t)
	signer, err := workloadclaims.NewSandboxTokenSigner(host)
	if err != nil {
		t.Fatal(err)
	}
	// The identity endpoint has to answer on the address and port the
	// verification path dials, which is the only place it looks.
	serveIdentity(t, host, signer.PublicKeyDER())

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest, err := workloadclaims.RequesterKeyDigest(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("the challenge being consumed")
	token, err := signer.Sign(sandboxID, keyDigest, nonce)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(token)
	if err != nil {
		t.Fatal(err)
	}

	got, err := verifySandboxToken(context.Background(), raw, &key.PublicKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if got != sandboxID {
		t.Errorf("sandbox ID = %q, want %q", got, sandboxID)
	}

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		raw       []byte
		requester *ecdsa.PublicKey
		nonce     []byte
	}{
		{name: "no token", raw: nil, requester: &key.PublicKey, nonce: nonce},
		{name: "another requester key", raw: raw, requester: &other.PublicKey, nonce: nonce},
		{name: "another challenge", raw: raw, requester: &key.PublicKey, nonce: []byte("a later challenge")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifySandboxToken(context.Background(), tc.raw, tc.requester, tc.nonce); err == nil {
				t.Fatal("token accepted")
			}
		})
	}
}

// serveIdentity answers IdentityPath on the host and port the verifier dials,
// like the mock inventory.
func serveIdentity(t *testing.T, host string, pubDER []byte) {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(host, inventoryIdentityPort))
	if err != nil {
		t.Skipf("cannot serve the inventory identity on %s:%s: %v", host, inventoryIdentityPort, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+workloadclaims.IdentityPath, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(workloadclaims.InventoryIdentity{PublicKey: pubDER})
	})
	srv := httptest.NewUnstartedServer(mux)
	_ = srv.Listener.Close()
	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)
}

// routableIPv4 is an address a sandbox token may name: the inventory host is a
// global unicast IP, so loopback cannot stand in for it.
func routableIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ip := ipnet.IP.To4(); ip != nil && ip.IsGlobalUnicast() {
			return ip.String()
		}
	}
	t.Skip("no global unicast IPv4 address to host the inventory on")
	return ""
}
