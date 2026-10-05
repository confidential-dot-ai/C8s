package operatorauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// --- test key helpers ---

func genKey(t *testing.T, curve elliptic.Curve) (keyPEM []byte, pub *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), &key.PublicKey
}

func pubPEM(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// mintCustom crafts a token with arbitrary claims signed by keyPEM — used to
// exercise malformed/expired tokens the well-behaved Signer would never produce.
func mintCustom(t *testing.T, keyPEM []byte, claims jwt.MapClaims) string {
	t.Helper()
	key, err := certutil.ParseECPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return "Bearer " + s
}

func reqWith(auth string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/allowlist", nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	return r
}

func sha256Base64URL(b []byte) string {
	h := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// baseClaims returns a fully valid claim set for a POST /allowlist request
// bound to body; tests override or delete one field to isolate one failure.
func baseClaims(body []byte) jwt.MapClaims {
	return jwt.MapClaims{
		"iat":                time.Now().Unix(),
		"exp":                time.Now().Add(time.Minute).Unix(),
		claimHTTPMethod:      http.MethodPost,
		claimHTTPPath:        "/allowlist",
		claimPayloadBodyHash: sha256Base64URL(body),
	}
}

// --- tests ---

func TestSignerVerifierRoundTrip(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		keyPEM, pub := genKey(t, curve)
		signer, err := NewSignerFromKeyPEM(keyPEM)
		if err != nil {
			t.Fatalf("new signer (%s): %v", curve.Params().Name, err)
		}
		body := []byte(`{"digests":{"sha256:aa":"img"}}`)
		auth, err := signer.Authorization(http.MethodPost, "/allowlist", body)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		v := Verifier{Keys: []*ecdsa.PublicKey{pub}, ClockSkew: 30 * time.Second}
		if err := v.Authorize(reqWith(auth), body); err != nil {
			t.Fatalf("verify (%s): %v", curve.Params().Name, err)
		}
	}
}

// TestVerifyAcceptsAnyPinnedKey proves a token signed by the second of several
// pinned keys is accepted (the verifier tries each pinned key).
func TestVerifyAcceptsAnyPinnedKey(t *testing.T) {
	_, pub1 := genKey(t, elliptic.P256())
	keyPEM2, pub2 := genKey(t, elliptic.P256())
	signer, _ := NewSignerFromKeyPEM(keyPEM2)

	body := []byte("body")
	auth, _ := signer.Authorization(http.MethodPost, "/allowlist", body)
	v := Verifier{Keys: []*ecdsa.PublicKey{pub1, pub2}}
	if err := v.Authorize(reqWith(auth), body); err != nil {
		t.Fatalf("expected token signed by a pinned key to verify: %v", err)
	}
}

func TestVerifyRejectsUnpinnedKey(t *testing.T) {
	keyPEM, _ := genKey(t, elliptic.P256())
	_, otherPub := genKey(t, elliptic.P256()) // not the signer's key
	signer, _ := NewSignerFromKeyPEM(keyPEM)

	body := []byte("body")
	auth, _ := signer.Authorization(http.MethodPost, "/allowlist", body)
	v := Verifier{Keys: []*ecdsa.PublicKey{otherPub}}
	if err := v.Authorize(reqWith(auth), body); err == nil {
		t.Fatal("expected a token signed by an unpinned key to be rejected")
	}
}

func TestVerifyRejectsBodyMismatch(t *testing.T) {
	keyPEM, pub := genKey(t, elliptic.P256())
	signer, _ := NewSignerFromKeyPEM(keyPEM)

	auth, err := signer.Authorization(http.MethodPost, "/allowlist", []byte("original-body"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	v := Verifier{Keys: []*ecdsa.PublicKey{pub}}
	if err := v.Authorize(reqWith(auth), []byte("tampered-body")); err == nil {
		t.Fatal("expected pbh mismatch to be rejected")
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	keyPEM, pub := genKey(t, elliptic.P256())
	body := []byte("body")
	claims := baseClaims(body)
	claims["iat"] = time.Now().Add(-10 * time.Minute).Unix()
	claims["exp"] = time.Now().Add(-5 * time.Minute).Unix()
	auth := mintCustom(t, keyPEM, claims)
	v := Verifier{Keys: []*ecdsa.PublicKey{pub}, ClockSkew: 30 * time.Second}
	if err := v.Authorize(reqWith(auth), body); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestVerifyRejectsMissingExpiration(t *testing.T) {
	keyPEM, pub := genKey(t, elliptic.P256())
	body := []byte("body")
	claims := baseClaims(body)
	delete(claims, "exp")
	auth := mintCustom(t, keyPEM, claims)
	v := Verifier{Keys: []*ecdsa.PublicKey{pub}}
	if err := v.Authorize(reqWith(auth), body); err == nil {
		t.Fatal("expected token without exp to be rejected")
	}
}

// TestVerifyRejectsMissingIssuedAt pins the server-side validity bound: iat is
// required, since without it exp−iat cannot be checked and a foreign-tooling
// token could carry any exp.
func TestVerifyRejectsMissingIssuedAt(t *testing.T) {
	keyPEM, pub := genKey(t, elliptic.P256())
	body := []byte("body")
	claims := baseClaims(body)
	delete(claims, "iat")
	auth := mintCustom(t, keyPEM, claims)
	v := Verifier{Keys: []*ecdsa.PublicKey{pub}}
	if err := v.Authorize(reqWith(auth), body); err == nil {
		t.Fatal("expected token without iat to be rejected")
	}
}

// TestVerifyRejectsExcessiveValidity proves the Signer's short TTL is enforced
// server-side: a well-signed token minted with a 10-year exp must not verify.
func TestVerifyRejectsExcessiveValidity(t *testing.T) {
	keyPEM, pub := genKey(t, elliptic.P256())
	body := []byte("body")
	claims := baseClaims(body)
	claims["exp"] = time.Now().Add(10 * 365 * 24 * time.Hour).Unix()
	auth := mintCustom(t, keyPEM, claims)
	v := Verifier{Keys: []*ecdsa.PublicKey{pub}}
	if err := v.Authorize(reqWith(auth), body); err == nil {
		t.Fatal("expected token with exp-iat beyond MaxTokenValidity to be rejected")
	}
}

func TestVerifyRejectsMethodMismatch(t *testing.T) {
	keyPEM, pub := genKey(t, elliptic.P256())
	signer, _ := NewSignerFromKeyPEM(keyPEM)
	body := []byte("body")
	auth, _ := signer.Authorization(http.MethodDelete, "/allowlist", body)
	v := Verifier{Keys: []*ecdsa.PublicKey{pub}}
	// reqWith builds a POST; a token minted for DELETE must not authorize it.
	if err := v.Authorize(reqWith(auth), body); err == nil {
		t.Fatal("expected token bound to another method to be rejected")
	}
}

func TestVerifyRejectsPathMismatch(t *testing.T) {
	keyPEM, pub := genKey(t, elliptic.P256())
	signer, _ := NewSignerFromKeyPEM(keyPEM)
	body := []byte("body")
	auth, _ := signer.Authorization(http.MethodPost, "/other", body)
	v := Verifier{Keys: []*ecdsa.PublicKey{pub}}
	if err := v.Authorize(reqWith(auth), body); err == nil {
		t.Fatal("expected token bound to another path to be rejected")
	}
}

func TestVerifyRejectsMissingPBH(t *testing.T) {
	keyPEM, pub := genKey(t, elliptic.P256())
	body := []byte("body")
	claims := baseClaims(body)
	delete(claims, claimPayloadBodyHash)
	auth := mintCustom(t, keyPEM, claims)
	v := Verifier{Keys: []*ecdsa.PublicKey{pub}}
	if err := v.Authorize(reqWith(auth), body); err == nil {
		t.Fatal("expected token without pbh to be rejected")
	}
}

// TestVerifyRejectsAlgNone pins the WithValidMethods allowlist: an unsigned
// alg:none token carrying otherwise valid claims must be rejected.
func TestVerifyRejectsAlgNone(t *testing.T) {
	_, pub := genKey(t, elliptic.P256())
	body := []byte("body")
	s, err := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims(body)).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("mint alg:none token: %v", err)
	}
	v := Verifier{Keys: []*ecdsa.PublicKey{pub}}
	if err := v.Authorize(reqWith("Bearer "+s), body); err == nil {
		t.Fatal("expected alg:none token to be rejected")
	}
}

// TestVerifyRejectsHMACWithPinnedKeyBytes pins the ECDSA method check against
// key confusion: an HS256 token keyed with the pinned public key's PEM bytes
// must be rejected.
func TestVerifyRejectsHMACWithPinnedKeyBytes(t *testing.T) {
	_, pub := genKey(t, elliptic.P256())
	body := []byte("body")
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims(body)).
		SignedString(pubPEM(t, pub))
	if err != nil {
		t.Fatalf("mint HS256 token: %v", err)
	}
	v := Verifier{Keys: []*ecdsa.PublicKey{pub}}
	if err := v.Authorize(reqWith("Bearer "+s), body); err == nil {
		t.Fatal("expected HS256 token keyed with the public key to be rejected")
	}
}

func TestVerifyRejectsMissingToken(t *testing.T) {
	_, pub := genKey(t, elliptic.P256())
	v := Verifier{Keys: []*ecdsa.PublicKey{pub}}
	if err := v.Authorize(reqWith(""), []byte("body")); err == nil {
		t.Fatal("expected request without Authorization to be rejected")
	}
}

func TestVerifyRejectsNoPinnedKeys(t *testing.T) {
	var v Verifier
	if err := v.Authorize(reqWith("Bearer x"), []byte("body")); err == nil {
		t.Fatal("expected an empty pinned-key set to reject every request")
	}
}

func TestParsePublicKeysPEM(t *testing.T) {
	_, pub1 := genKey(t, elliptic.P256())
	_, pub2 := genKey(t, elliptic.P384())
	bundle := append(pubPEM(t, pub1), pubPEM(t, pub2)...)

	keys, err := ParsePublicKeysPEM(bundle)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	if _, err := ParsePublicKeysPEM([]byte("not pem")); err == nil {
		t.Fatal("expected error on input with no PUBLIC KEY block")
	}
	// A private key PEM must not be accepted as a pinned public key.
	privPEM, _ := genKey(t, elliptic.P256())
	if _, err := ParsePublicKeysPEM(privPEM); err == nil {
		t.Fatal("expected a private-key PEM to be rejected (no PUBLIC KEY block)")
	}
}

func TestKeySetHashIsCanonical(t *testing.T) {
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ab, err := KeySetHash([]*ecdsa.PublicKey{&keyA.PublicKey, &keyB.PublicKey})
	if err != nil {
		t.Fatalf("KeySetHash: %v", err)
	}
	ba, err := KeySetHash([]*ecdsa.PublicKey{&keyB.PublicKey, &keyA.PublicKey})
	if err != nil {
		t.Fatalf("KeySetHash reversed: %v", err)
	}
	if ab != ba {
		t.Fatalf("key order changed hash: %q != %q", ab, ba)
	}
	withDuplicate, err := KeySetHash([]*ecdsa.PublicKey{&keyA.PublicKey, &keyB.PublicKey, &keyA.PublicKey})
	if err != nil {
		t.Fatalf("KeySetHash duplicate: %v", err)
	}
	if withDuplicate != ab {
		t.Fatalf("duplicate key changed set hash: %q != %q", withDuplicate, ab)
	}

	onlyA, err := KeySetHash([]*ecdsa.PublicKey{&keyA.PublicKey})
	if err != nil {
		t.Fatalf("KeySetHash one key: %v", err)
	}
	if onlyA == ab {
		t.Fatal("adding a key did not change the key-set hash")
	}
}

func TestKeySetHashRejectsInvalidInputs(t *testing.T) {
	if _, err := KeySetHash(nil); err == nil {
		t.Fatal("expected empty key set to fail")
	}
	if _, err := KeySetHash([]*ecdsa.PublicKey{nil}); err == nil {
		t.Fatal("expected nil key to fail")
	}
}

// TestSignerMintsSixtySecondTokens pins the minted lifetime: one round trip
// plus skew, nothing more.
func TestSignerMintsSixtySecondTokens(t *testing.T) {
	keyPEM, pub := genKey(t, elliptic.P256())
	signer, err := NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	auth, err := signer.Authorization(http.MethodPost, "/allowlist", []byte("body"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(strings.TrimPrefix(auth, "Bearer "), claims,
		func(*jwt.Token) (any, error) { return pub, nil }); err != nil {
		t.Fatalf("parse minted token: %v", err)
	}
	iat, err := claims.GetIssuedAt()
	if err != nil || iat == nil {
		t.Fatalf("iat: %v", err)
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		t.Fatalf("exp: %v", err)
	}
	if got := exp.Sub(iat.Time); got != 60*time.Second {
		t.Fatalf("token lifetime = %v, want 60s", got)
	}
}

// TestVerifyAcceptsMaxValidityToken pins the bound as inclusive: exp-iat equal
// to MaxTokenValidity must still authorize.
func TestVerifyAcceptsMaxValidityToken(t *testing.T) {
	keyPEM, pub := genKey(t, elliptic.P256())
	body := []byte("body")
	claims := baseClaims(body)
	iat := time.Now().Add(-time.Minute)
	claims["iat"] = iat.Unix()
	claims["exp"] = iat.Add(MaxTokenValidity).Unix()
	auth := mintCustom(t, keyPEM, claims)
	v := Verifier{Keys: []*ecdsa.PublicKey{pub}, ClockSkew: 30 * time.Second}
	if err := v.Authorize(reqWith(auth), body); err != nil {
		t.Fatalf("token with exp-iat == MaxTokenValidity rejected: %v", err)
	}
}

// TestVerifyRejectsZeroValidityToken: exp == iat means no usable window; such
// a token is malformed and must not authorize even inside clock-skew leeway.
func TestVerifyRejectsZeroValidityToken(t *testing.T) {
	keyPEM, pub := genKey(t, elliptic.P256())
	body := []byte("body")
	claims := baseClaims(body)
	now := time.Now().Unix()
	claims["iat"] = now
	claims["exp"] = now
	auth := mintCustom(t, keyPEM, claims)
	v := Verifier{Keys: []*ecdsa.PublicKey{pub}, ClockSkew: time.Minute}
	if err := v.Authorize(reqWith(auth), body); err == nil {
		t.Fatal("expected token with exp == iat to be rejected")
	}
}

// TestVerifyUnpinnedKeyErrorKeepsCause: the returned error must wrap the last
// per-key verification failure, not replace it with a generic fallback.
func TestVerifyUnpinnedKeyErrorKeepsCause(t *testing.T) {
	keyPEM, _ := genKey(t, elliptic.P256())
	_, otherPub := genKey(t, elliptic.P256())
	signer, _ := NewSignerFromKeyPEM(keyPEM)
	body := []byte("body")
	auth, _ := signer.Authorization(http.MethodPost, "/allowlist", body)
	v := Verifier{Keys: []*ecdsa.PublicKey{otherPub}}
	err := v.Authorize(reqWith(auth), body)
	if err == nil {
		t.Fatal("expected rejection")
	}
	if !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		t.Fatalf("err = %v, want it to wrap the signature failure", err)
	}
}

func TestVerifyStored(t *testing.T) {
	keyPEM, pub := genKey(t, elliptic.P256())
	_, other := genKey(t, elliptic.P256())
	body := []byte(`{"schema":"x"}`)
	stale := baseClaims(body)
	stale["iat"] = time.Now().Add(-time.Hour).Unix()
	stale["exp"] = time.Now().Add(-59 * time.Minute).Unix()
	token := strings.TrimPrefix(mintCustom(t, keyPEM, stale), "Bearer ")
	wide := baseClaims(body)
	wide["exp"] = time.Now().Add(time.Hour).Unix()
	wideToken := strings.TrimPrefix(mintCustom(t, keyPEM, wide), "Bearer ")
	for _, tc := range []struct {
		name         string
		keys         []*ecdsa.PublicKey
		token        string
		method, path string
		body         []byte
		ok           bool
	}{
		{"expired token, matching request", []*ecdsa.PublicKey{pub}, token, http.MethodPost, "/allowlist", body, true},
		{"other key", []*ecdsa.PublicKey{other}, token, http.MethodPost, "/allowlist", body, false},
		{"other body", []*ecdsa.PublicKey{pub}, token, http.MethodPost, "/allowlist", []byte("{}"), false},
		{"other method", []*ecdsa.PublicKey{pub}, token, http.MethodPut, "/allowlist", body, false},
		{"other path", []*ecdsa.PublicKey{pub}, token, http.MethodPost, "/allowlist/workloads/a", body, false},
		{"validity over the maximum", []*ecdsa.PublicKey{pub}, wideToken, http.MethodPost, "/allowlist", body, false},
	} {
		if err := VerifyStored(tc.keys, tc.token, tc.method, tc.path, tc.body); (err == nil) != tc.ok {
			t.Errorf("%s: VerifyStored = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
	r := reqWith("Bearer " + token)
	if err := (Verifier{Keys: []*ecdsa.PublicKey{pub}}).Authorize(r, body); err == nil {
		t.Error("Authorize accepted an expired token")
	}
}

// TestOperatorSignatureVector pins the stored-token check and the key-set hash
// to testdata/operator_signature_vector.json, which TEErminator and
// c8s-verify-js reproduce.
func TestOperatorSignatureVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/operator_signature_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		OperatorKeysPEM  string `json:"operator_keys_pem"`
		OperatorKeysHash string `json:"operator_keys_hash"`
		PolicyB64        string `json:"policy_b64"`
		Token            string `json:"token"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	keys, err := ParsePublicKeysPEM([]byte(v.OperatorKeysPEM))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := KeySetHash(keys); err != nil || got != v.OperatorKeysHash {
		t.Fatalf("KeySetHash = %s, %v; want %s", got, err, v.OperatorKeysHash)
	}
	policy, err := base64.StdEncoding.DecodeString(v.PolicyB64)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStored(keys, v.Token, http.MethodPut, "/allowlist", policy); err != nil {
		t.Fatalf("VerifyStored(vector) = %v", err)
	}
}
