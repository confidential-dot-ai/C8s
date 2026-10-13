package cds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func TestSingleUse(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"exp": time.Now().Add(time.Minute).Unix()}).SignedString([]byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	denied := errors.New("denied")
	var verdict error
	authorize := singleUse(func(*http.Request, []byte) error { return verdict }, &store, time.Second)
	r := httptest.NewRequest(http.MethodPut, "/allowlist", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	for _, step := range []struct {
		name    string
		verdict error
		want    error
	}{
		{"rejected token is not consumed", denied, denied},
		{"first use", nil, nil},
		{"replay", nil, allowlist.ErrTokenReused},
	} {
		verdict = step.verdict
		if err := authorize(r, nil); !errors.Is(err, step.want) {
			t.Fatalf("%s: authorize = %v, want %v", step.name, err, step.want)
		}
	}
}

// Every token verifying as the same signed header.payload is one token: the
// (r, n-s) twin of an ECDSA signature verifies too.
func TestSingleUseRejectsSignatureTwin(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(nil)
	token, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute).Unix(),
		"htm": http.MethodPut,
		"htu": "/allowlist",
		"pbh": base64.RawURLEncoding.EncodeToString(sum[:]),
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	dot := strings.LastIndexByte(token, '.')
	sig, err := base64.RawURLEncoding.DecodeString(token[dot+1:])
	if err != nil {
		t.Fatal(err)
	}
	s := new(big.Int).SetBytes(sig[32:])
	s.Sub(elliptic.P256().Params().N, s).FillBytes(sig[32:])
	twin := token[:dot+1] + base64.RawURLEncoding.EncodeToString(sig)

	verifier := operatorauth.Verifier{Keys: []*ecdsa.PublicKey{&key.PublicKey}}
	authorize := singleUse(verifier.Authorize, &store, time.Second)
	request := func(token string) *http.Request {
		r := httptest.NewRequest(http.MethodPut, "/allowlist", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}
	if err := verifier.Authorize(request(twin), nil); err != nil {
		t.Fatalf("Authorize(twin) = %v; the twin must verify for this test to mean anything", err)
	}
	if err := authorize(request(token), nil); err != nil {
		t.Fatalf("first use = %v", err)
	}
	if err := authorize(request(twin), nil); !errors.Is(err, allowlist.ErrTokenReused) {
		t.Fatalf("twin after first use = %v, want ErrTokenReused", err)
	}
}
