package routes

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func genKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// mint signs a write token for body. edit changes its claims before signing.
func mint(t testing.TB, key *ecdsa.PrivateKey, body []byte, edit func(jwt.MapClaims)) string {
	t.Helper()
	sum := sha256.Sum256(body)
	now := time.Now()
	c := jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"htm": "PUT",
		"htu": Path,
		"pbh": base64.RawURLEncoding.EncodeToString(sum[:]),
	}
	if edit != nil {
		edit(c)
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodES256, c).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEnvelopeJSON(t *testing.T) {
	manifest := []byte{0xfb, 0xff, '{', '}'}
	env := Envelope{Manifest: manifest, Token: "a.b.c"}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	// C1: standard alphabet ("+/"), padded.
	if got, want := string(b), `{"manifest":"+/97fQ==","token":"a.b.c"}`; got != want {
		t.Errorf("json.Marshal(%+v) = %s, want %s", env, got, want)
	}
	var back Envelope
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("json.Unmarshal(%s) = %v, want nil", b, err)
	}
	if !bytes.Equal(back.Manifest, manifest) || back.Token != env.Token {
		t.Errorf("json.Unmarshal(%s) = %+v, want %+v", b, back, env)
	}
}

func TestEnvelopeUnmarshalRejects(t *testing.T) {
	tests := []struct{ name, input string }{
		{"C1 unpadded", `{"manifest":"+/97fQ","token":"t"}`},
		{"C1 URL-safe alphabet", `{"manifest":"-_97fQ==","token":"t"}`},
		{"C1 embedded newline", `{"manifest":"+/97\nfQ==","token":"t"}`},
		{"C1 non-canonical padding bits", `{"manifest":"+/97fR==","token":"t"}`},
		{"C1 manifest as JSON", `{"manifest":{},"token":"t"}`},
		{"C1 manifest null", `{"manifest":null,"token":"t"}`},
		{"C1 token not a string", `{"manifest":"","token":1}`},
		{"C1 missing token", `{"manifest":""}`},
		{"C1 missing manifest", `{"token":"t"}`},
		{"C1 unknown member", `{"manifest":"","token":"t","digest":""}`},
		{"C1 duplicate member", `{"manifest":"","manifest":"","token":"t"}`},
		{"C1 not an object", `[]`},
		{"C1 null", `null`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var env Envelope
			if err := json.Unmarshal([]byte(tt.input), &env); err == nil {
				t.Errorf("json.Unmarshal(%s) = %+v, nil; want error", tt.input, env)
			}
		})
	}
}

func TestVerifySigned(t *testing.T) {
	key, other := genKey(t), genKey(t)
	keys := []*ecdsa.PublicKey{&key.PublicKey}
	body := readExample(t)
	invalid := []byte(`{"schema":"c8s.routes/v1"}`)
	tests := []struct {
		name    string
		env     Envelope
		keys    []*ecdsa.PublicKey
		wantErr string // empty: must verify
	}{
		{name: "valid", env: Envelope{body, mint(t, key, body, nil)}, keys: keys},
		{name: "W3 expired token", env: Envelope{body, mint(t, key, body, func(c jwt.MapClaims) {
			c["iat"] = time.Now().Add(-90 * 24 * time.Hour).Unix()
			c["exp"] = time.Now().Add(-89 * 24 * time.Hour).Unix()
		})}, keys: keys},
		{name: "W2.1 no trusted keys", env: Envelope{body, mint(t, key, body, nil)}, wantErr: "no operator keys"},
		{name: "W2.1 untrusted key", env: Envelope{body, mint(t, other, body, nil)}, keys: keys, wantErr: "operator token invalid"},
		{name: "W2.1 HS256", env: Envelope{body, func() string {
			s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"htm": "PUT", "htu": Path}).SignedString([]byte("k"))
			if err != nil {
				t.Fatal(err)
			}
			return s
		}()}, keys: keys, wantErr: "operator token invalid"},
		{name: "W2.1 Bearer prefix is not a token", env: Envelope{body, "Bearer " + mint(t, key, body, nil)}, keys: keys, wantErr: "operator token invalid"},
		{name: "W2.2 wrong htm", env: Envelope{body, mint(t, key, body, func(c jwt.MapClaims) { c["htm"] = "POST" })}, keys: keys, wantErr: "htm"},
		{name: "W2.2 wrong htu", env: Envelope{body, mint(t, key, body, func(c jwt.MapClaims) { c["htu"] = "/allowlist" })}, keys: keys, wantErr: "htu"},
		{name: "W2.3 other body", env: Envelope{append([]byte(" "), body...), mint(t, key, body, nil)}, keys: keys, wantErr: "pbh"},
		{name: "W2.4 invalid manifest", env: Envelope{invalid, mint(t, key, invalid, nil)}, keys: keys, wantErr: "route manifest"},
		{name: "W2 signature before bindings", env: Envelope{invalid, mint(t, other, body, func(c jwt.MapClaims) { c["htm"] = "GET" })}, keys: keys, wantErr: "operator token invalid"},
		{name: "W2 htm before pbh", env: Envelope{invalid, mint(t, key, body, func(c jwt.MapClaims) { c["htm"] = "GET" })}, keys: keys, wantErr: "htm"},
		{name: "W2 pbh before manifest", env: Envelope{invalid, mint(t, key, body, nil)}, keys: keys, wantErr: "pbh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := VerifySigned(tt.env, tt.keys, nil)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("VerifySigned() = %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifySigned() = %v, want nil", err)
			}
			if s.Digest() != Digest(tt.env.Manifest) || !bytes.Equal(s.Bytes(), tt.env.Manifest) || s.Token() != tt.env.Token || s.Manifest().Revision != 12 {
				t.Errorf("VerifySigned() = %+v, want the envelope's bytes, token, digest and revision 12", s)
			}
		})
	}
}

func TestVerifySignedRejectsMeshCA(t *testing.T) {
	key := genKey(t)
	body := readExample(t)
	m, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	mesh := m.Hosts["app.example"].Routes[1].Backend.Anchors()
	_, other, _ := newCA(t, nil)
	env := Envelope{body, mint(t, key, body, nil)}
	keys := []*ecdsa.PublicKey{&key.PublicKey}
	if _, err := VerifySigned(env, keys, []*x509.Certificate{other}); err != nil {
		t.Errorf("VerifySigned(other mesh CA) = %v, want nil", err)
	}
	if _, err := VerifySigned(env, keys, append(mesh, other)); err == nil || !strings.Contains(err.Error(), "excluded CA") {
		t.Errorf("VerifySigned(ca holds the mesh CA) = %v, want an excluded-CA error", err)
	}
}

func TestVerifySignedOwnsBytes(t *testing.T) {
	key := genKey(t)
	body := readExample(t)
	env := Envelope{bytes.Clone(body), mint(t, key, body, nil)}
	s, err := VerifySigned(env, []*ecdsa.PublicKey{&key.PublicKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	env.Manifest[0] = 'x'
	if !bytes.Equal(s.Bytes(), body) {
		t.Errorf("Signed.Bytes() after the caller changed its envelope = %.20q, want %.20q", s.Bytes(), body)
	}
	if got := s.Envelope(); !bytes.Equal(got.Manifest, body) || got.Token != env.Token {
		t.Errorf("Signed.Envelope() = %+v, want the verified bytes and token", got)
	}
}

func TestSignedImmutable(t *testing.T) {
	key := genKey(t)
	body := readExample(t)
	s, err := VerifySigned(Envelope{body, mint(t, key, body, nil)}, []*ecdsa.PublicKey{&key.PublicKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Bytes()[0] = 'x'
	s.Envelope().Manifest[0] = 'x'
	m := s.Manifest()
	m.Revision++
	m.NotBefore = m.NotBefore.Add(time.Hour)
	m.Hosts["app.example"].Routes[0].Backend.Address = "evil.example:443"
	delete(m.Hosts, "app.example")
	want, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.Bytes(), body) || s.Digest() != Digest(body) || !reflect.DeepEqual(s.Manifest(), want) {
		t.Error("changing the values Signed returned changed the Signed")
	}
}

func TestSupersedes(t *testing.T) {
	d := func(b byte) [32]byte { return [32]byte{b} }
	s := &Signed{manifest: &Manifest{Revision: 5}, digest: d(1)}
	tests := []struct {
		name     string
		revision uint64
		digest   [32]byte
		want     error
	}{
		{"W4 nothing accepted yet", 0, [32]byte{}, nil},
		{"W4 higher revision", 4, d(9), nil},
		{"W4 equal revision, equal digest", 5, d(1), nil},
		{"W4 equal revision, other digest", 5, d(2), ErrRevisionConflict},
		{"W4 lower revision", 6, d(9), ErrRollback},
		{"W4 lower revision, equal digest", 6, d(1), ErrRollback},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.Supersedes(tt.revision, tt.digest); !errors.Is(err, tt.want) || (tt.want == nil) != (err == nil) {
				t.Errorf("Supersedes(%d, %x) = %v, want %v", tt.revision, tt.digest[:1], err, tt.want)
			}
		})
	}
}
