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
	authorize := singleUse(func(*http.Request, []byte) error { return verdict }, &store, time.Time{}, 0)
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
	authorize := singleUse(verifier.Authorize, &store, time.Time{}, 0)
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

// A store that forgets spent tokens at restart refuses every token that could
// have been spent before CDS started: Authorize accepts an iat up to the clock
// skew ahead.
func TestSingleUseRefusesTokensBeforeStart(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	start := time.Unix(1_700_000_000, 0)
	const skew = 30 * time.Second
	authorize := singleUse(func(*http.Request, []byte) error { return nil }, &store, start, skew)
	for _, tc := range []struct {
		name   string
		claims jwt.MapClaims
		ok     bool
	}{
		{"issued before start", jwt.MapClaims{"iat": start.Add(-time.Second).Unix()}, false},
		{"issued at start", jwt.MapClaims{"iat": start.Unix()}, false},
		{"issued inside the skew", jwt.MapClaims{"iat": start.Add(skew - time.Second).Unix()}, false},
		{"issued at start plus skew", jwt.MapClaims{"iat": start.Add(skew).Unix()}, true},
		{"no iat", jwt.MapClaims{}, false},
	} {
		r := bearerRequest(t, tc.claims)
		if err := authorize(r, nil); (err == nil) != tc.ok {
			t.Errorf("%s: authorize = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// A token minted by an operator whose clock runs ahead is spent, CDS restarts
// on a fresh in-memory store, and the replay is refused although the record of
// the spend is gone.
func TestSingleUseRefusesReplayAfterRestart(t *testing.T) {
	const skew = 30 * time.Second
	start := time.Unix(1_700_000_000, 0)
	r := bearerRequest(t, jwt.MapClaims{"iat": start.Add(5 * time.Second).Unix()})
	allow := func(*http.Request, []byte) error { return nil }

	first, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := singleUse(allow, &first, start.Add(-time.Hour), skew)(r, nil); err != nil {
		t.Fatalf("first use = %v", err)
	}

	restarted, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := singleUse(allow, &restarted, start.Add(time.Second), skew)(r, nil); !errors.Is(err, allowlist.ErrTokenBeforeStart) {
		t.Fatalf("replay after restart = %v, want ErrTokenBeforeStart", err)
	}
}

func bearerRequest(t *testing.T, claims jwt.MapClaims) *http.Request {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPut, "/allowlist", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}
