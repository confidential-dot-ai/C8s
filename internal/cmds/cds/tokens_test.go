package cds

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
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
