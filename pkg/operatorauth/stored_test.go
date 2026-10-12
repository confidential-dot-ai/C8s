package operatorauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifyStoredToken(t *testing.T) {
	keyPEM, pub := genKey(t, elliptic.P256())
	_, otherPub := genKey(t, elliptic.P256())
	body := []byte(`{"schema":"c8s.routes/v1"}`)
	keys := []*ecdsa.PublicKey{pub}
	issued := time.Now().Add(-48 * time.Hour)
	stored := func(edit func(jwt.MapClaims)) string {
		c := jwt.MapClaims{
			"iat":                issued.Unix(),
			"exp":                issued.Add(time.Minute).Unix(),
			claimHTTPMethod:      http.MethodPut,
			claimHTTPPath:        "/routes",
			claimPayloadBodyHash: sha256Base64URL(body),
		}
		if edit != nil {
			edit(c)
		}
		return strings.TrimPrefix(mintCustom(t, keyPEM, c), "Bearer ")
	}
	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		claimHTTPMethod: http.MethodPut, claimHTTPPath: "/routes", claimPayloadBodyHash: sha256Base64URL(body),
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		keys    []*ecdsa.PublicKey
		token   string
		body    []byte
		wantErr string // empty: must verify
	}{
		{name: "expired token verifies (W3)", keys: keys, token: stored(nil), body: body},
		{name: "no time claims verifies (W3)", keys: keys, token: stored(func(c jwt.MapClaims) {
			delete(c, "iat")
			delete(c, "exp")
		}), body: body},
		{name: "validity beyond MaxTokenValidity verifies (W3)", keys: keys, token: stored(func(c jwt.MapClaims) {
			c["exp"] = issued.Add(time.Hour).Unix()
		}), body: body},
		{name: "not yet valid verifies (W3)", keys: keys, token: stored(func(c jwt.MapClaims) {
			c["nbf"] = time.Now().Add(time.Hour).Unix()
		}), body: body},
		{name: "no keys", token: stored(nil), body: body, wantErr: "no operator keys"},
		{name: "empty token", keys: keys, body: body, wantErr: "missing operator bearer token"},
		{name: "unpinned key (W2 step 1)", keys: []*ecdsa.PublicKey{otherPub}, token: stored(nil), body: body, wantErr: "operator token invalid"},
		{name: "alg none (W2 step 1)", keys: keys, token: none, body: body, wantErr: "operator token invalid"},
		{name: "wrong htm (W2 step 2)", keys: keys, token: stored(func(c jwt.MapClaims) { c[claimHTTPMethod] = http.MethodPost }), body: body, wantErr: "htm"},
		{name: "wrong htu (W2 step 2)", keys: keys, token: stored(func(c jwt.MapClaims) { c[claimHTTPPath] = "/allowlist" }), body: body, wantErr: "htu"},
		{name: "wrong body (W2 step 3)", keys: keys, token: stored(nil), body: []byte(`{}`), wantErr: "pbh"},
		{name: "missing pbh (W2 step 3)", keys: keys, token: stored(func(c jwt.MapClaims) { delete(c, claimPayloadBodyHash) }), body: body, wantErr: "pbh"},
		{name: "signature checked before bindings", keys: []*ecdsa.PublicKey{otherPub}, token: stored(func(c jwt.MapClaims) { c[claimHTTPMethod] = "GET" }), body: []byte(`{}`), wantErr: "operator token invalid"},
		{name: "htm checked before htu", keys: keys, token: stored(func(c jwt.MapClaims) {
			c[claimHTTPMethod] = "GET"
			c[claimHTTPPath] = "/x"
		}), body: body, wantErr: "htm"},
		{name: "htu checked before pbh", keys: keys, token: stored(func(c jwt.MapClaims) { c[claimHTTPPath] = "/x" }), body: []byte(`{}`), wantErr: "htu"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyStoredToken(tt.keys, tt.token, http.MethodPut, "/routes", tt.body)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("VerifyStoredToken() = %v, want nil", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("VerifyStoredToken() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}
