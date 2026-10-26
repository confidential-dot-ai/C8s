package nodetoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testConfig() Config {
	return Config{
		URL:       "https://cds.cl-1.example.test",
		Audiences: []string{"cl-1.k8s.example.test"},
		Cluster:   "cl-1",
		TTL:       MaxTTL,
	}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestNew_RefusesBadConfig(t *testing.T) {
	cases := map[string]func(*Config){
		"plain http":     func(c *Config) { c.URL = "http://cds.example.test" },
		"no host":        func(c *Config) { c.URL = "https://" },
		"query":          func(c *Config) { c.URL = "https://cds.example.test?a=b" },
		"user":           func(c *Config) { c.URL = "https://u@cds.example.test" },
		"path":           func(c *Config) { c.URL = "https://cds.example.test/issuer" },
		"root path":      func(c *Config) { c.URL = "https://cds.example.test/" },
		"ipv4 host":      func(c *Config) { c.URL = "https://192.0.2.1" },
		"ipv6 host":      func(c *Config) { c.URL = "https://[2001:db8::1]" },
		"no audience":    func(c *Config) { c.Audiences = nil },
		"empty audience": func(c *Config) { c.Audiences = []string{""} },
		"no cluster":     func(c *Config) { c.Cluster = "" },
		"zero ttl":       func(c *Config) { c.TTL = 0 },
		"ttl over max":   func(c *Config) { c.TTL = MaxTTL + time.Second },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("New accepted a bad config")
			}
		})
	}
}

func TestSubject_DerivedFromKey(t *testing.T) {
	a, b := newKey(t), newKey(t)
	sa, err := Subject(&a.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !subjectPattern.MatchString(sa) {
		t.Fatalf("subject %q does not match %s", sa, subjectPattern)
	}
	again, _ := Subject(&a.PublicKey)
	if again != sa {
		t.Fatalf("subject not stable: %q then %q", sa, again)
	}
	if sb, _ := Subject(&b.PublicKey); sb == sa {
		t.Fatalf("two keys share subject %q", sa)
	}
}

// jwksKey reads the issuer's one published key the way a relying party does.
func jwksKey(t *testing.T, i *Issuer) (string, *ecdsa.PublicKey) {
	t.Helper()
	raw, err := i.Keys()
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("JWKS has %d keys, want 1", len(set.Keys))
	}
	k := set.Keys[0]
	coord := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(b) != 32 {
			t.Fatalf("bad coordinate %q", s)
		}
		return b
	}
	point := append(append([]byte{4}, coord(k["x"])...), coord(k["y"])...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		t.Fatalf("JWKS key is not a P-256 point: %v", err)
	}
	return k["kid"], pub
}

func TestMint_VerifiesAgainstPublishedKeys(t *testing.T) {
	i, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	i.now = func() time.Time { return now }
	node := newKey(t)

	signed, expires, err := i.Mint("cl-1.k8s.example.test", Attested{NodeKey: &node.PublicKey, TEE: "snp", LaunchDigest: "deadbeef"})
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(MaxTTL); !expires.Equal(want) {
		t.Fatalf("expires %s, want %s", expires, want)
	}

	kid, pub := jwksKey(t, i)
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(signed, claims, func(tok *jwt.Token) (any, error) {
		if tok.Header["kid"] != kid {
			t.Fatalf("token kid %v, JWKS kid %q", tok.Header["kid"], kid)
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithTimeFunc(func() time.Time { return now }),
		jwt.WithIssuer("https://cds.cl-1.example.test"), jwt.WithAudience("cl-1.k8s.example.test"))
	if err != nil || !tok.Valid {
		t.Fatalf("token does not verify: %v", err)
	}
	sub, _ := Subject(&node.PublicKey)
	for claim, want := range map[string]any{
		"sub": sub, "cluster": "cl-1", "tee": "snp", "launch_digest": "deadbeef",
		"iat": float64(now.Unix()), "exp": float64(now.Add(MaxTTL).Unix()),
	} {
		if claims[claim] != want {
			t.Errorf("claim %s = %v, want %v", claim, claims[claim], want)
		}
	}
	if jti, _ := claims["jti"].(string); len(jti) != 32 {
		t.Errorf("jti %q, want 16 random bytes in hex", jti)
	}
}

func TestMint_RefusesOtherAudienceAndUnattestedNode(t *testing.T) {
	i, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	node := newKey(t)
	if _, _, err := i.Mint("other.k8s.example.test", Attested{NodeKey: &node.PublicKey, TEE: "snp", LaunchDigest: "d"}); err == nil {
		t.Fatal("minted for an audience the issuer does not serve")
	}
	if _, _, err := i.Mint("cl-1.k8s.example.test", Attested{NodeKey: &node.PublicKey}); err == nil {
		t.Fatal("minted without the attested TEE and launch digest")
	}
}

func TestHandler_ServesOnlyDiscoveryAndKeys(t *testing.T) {
	i, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	h, err := i.Handler()
	if err != nil {
		t.Fatal(err)
	}
	get := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}

	w := get(http.MethodGet, DiscoveryPath)
	if w.Code != http.StatusOK {
		t.Fatalf("discovery: %d", w.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != "https://cds.cl-1.example.test" || doc["jwks_uri"] != "https://cds.cl-1.example.test"+KeysPath {
		t.Fatalf("discovery document %v", doc)
	}
	if w := get(http.MethodGet, KeysPath); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"kty":"EC"`) {
		t.Fatalf("keys: %d %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"/", "/node-token", "/.well-known/jwks.json"} {
		if w := get(http.MethodGet, path); w.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", path, w.Code)
		}
	}
	if w := get(http.MethodPost, KeysPath); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST keys: %d, want 405", w.Code)
	}
}

func TestServing_LeafIsServerOnlyAndConstrainedToHost(t *testing.T) {
	s, err := NewServing("cds.cl-1.example.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := s.certificate()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(s.CAPEM()) {
		t.Fatal("CA PEM does not parse")
	}
	verify := func(name string, usage x509.ExtKeyUsage) error {
		_, err := cert.Leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, KeyUsages: []x509.ExtKeyUsage{usage}})
		return err
	}
	if err := verify("cds.cl-1.example.test", x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("leaf does not verify for its host: %v", err)
	}
	if err := verify("cds.cl-1.example.test", x509.ExtKeyUsageClientAuth); err == nil {
		t.Fatal("leaf verifies as a client certificate")
	}
	if err := verify("other.example.test", x509.ExtKeyUsageServerAuth); err == nil {
		t.Fatal("leaf verifies for another host")
	}
	if len(s.Fingerprint()) != 64 {
		t.Fatalf("fingerprint %q", s.Fingerprint())
	}
}

func TestServing_RenewsLeafUnderSameCA(t *testing.T) {
	s, err := NewServing("cds.cl-1.example.test")
	if err != nil {
		t.Fatal(err)
	}
	first, _ := s.certificate()
	if again, _ := s.certificate(); again != first {
		t.Fatal("leaf renewed before it was due")
	}
	start := time.Now()
	s.now = func() time.Time { return start.Add(servingLeafValidity * 2 / 3) }
	renewed, err := s.certificate()
	if err != nil {
		t.Fatal(err)
	}
	if renewed == first {
		t.Fatal("leaf not renewed two thirds into its life")
	}
	if err := renewed.Leaf.CheckSignatureFrom(s.ca); err != nil {
		t.Fatalf("renewed leaf not signed by the pinned CA: %v", err)
	}
}

func TestServing_CAConstraints(t *testing.T) {
	s, err := NewServing("cds.cl-1.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.ca.ExcludedIPRanges) != 2 {
		t.Fatalf("CA excludes %v, want every IPv4 and IPv6 address", s.ca.ExcludedIPRanges)
	}
	if len(s.ca.ExtKeyUsage) != 1 || s.ca.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("CA EKU %v, want serverAuth only", s.ca.ExtKeyUsage)
	}
}
