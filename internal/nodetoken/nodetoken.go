// Package nodetoken issues the short-lived JWTs a hosted Kubernetes API server
// accepts as a node's join credential, after CDS has checked the node's
// attestation (docs/node-tokens.md).
//
// The API server checks them with its own structured JWT authenticator, the
// way it checks any OIDC issuer: it reads this issuer's discovery document and
// keys, checks the signature, audience and claims, and maps the subject to
// system:node:<sub>. So the token is all a node needs to get its own kubelet
// certificate through the stock self-node approval, and there is no bootstrap
// token anywhere.
//
// The signing key is generated in memory and never leaves the process. A
// restart publishes a new key, which costs nothing: a token lives for minutes
// and the API server refetches the keys when it meets an unknown key id.
package nodetoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MaxTTL bounds a token's lifetime. A token is a bearer credential, so it is
// only ever good for the join it was minted for.
const MaxTTL = 5 * time.Minute

// DiscoveryPath and KeysPath are where the issuer's documents are served, the
// paths a Kubernetes API server's own service-account issuer uses.
const (
	DiscoveryPath = "/.well-known/openid-configuration"
	KeysPath      = "/openid/v1/jwks"
)

// subjectPattern is the shape of every subject this issuer mints, which the
// API server's claim rules can pin exactly.
var subjectPattern = regexp.MustCompile(`^n-[0-9a-f]{16}$`)

// Config names what every token of this issuer carries.
type Config struct {
	// URL is the issuer: an https URL with no query or fragment, served at
	// DiscoveryPath and KeysPath below it.
	URL string
	// Audiences are the API servers this issuer mints for, by the hostname
	// each is reached at. A request names one of them.
	Audiences []string
	// Cluster is the id of the cluster the API servers serve, carried in
	// every token so a rule can refuse one meant for another cluster.
	Cluster string
	// TTL is each token's lifetime, at most MaxTTL.
	TTL time.Duration
}

// Issuer mints node tokens with a key of its own.
type Issuer struct {
	cfg Config
	key *ecdsa.PrivateKey
	kid string
	now func() time.Time
}

// New validates cfg and generates the issuer's signing key.
func New(cfg Config) (*Issuer, error) {
	u, err := url.Parse(cfg.URL)
	// The discovery document and keys are served at the root, and the serving
	// certificate carries only a DNS name, so a path (even "/", which would
	// double the slash in jwks_uri) or an IP-literal host leaves the API server
	// unable to check the tokens.
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || net.ParseIP(u.Hostname()) != nil {
		return nil, fmt.Errorf("node token issuer %q must be an https URL with a DNS host and no path, query, fragment or user", cfg.URL)
	}
	if len(cfg.Audiences) == 0 {
		return nil, errors.New("node token issuer needs at least one audience")
	}
	for _, a := range cfg.Audiences {
		if a == "" {
			return nil, errors.New("node token audience must not be empty")
		}
	}
	if cfg.Cluster == "" {
		return nil, errors.New("node token issuer needs a cluster id")
	}
	if cfg.TTL <= 0 || cfg.TTL > MaxTTL {
		return nil, fmt.Errorf("node token TTL %s must be positive and at most %s", cfg.TTL, MaxTTL)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate node token key: %w", err)
	}
	kid, err := thumbprint(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Issuer{cfg: cfg, key: key, kid: kid, now: time.Now}, nil
}

// Subject is the node name a node key gets: derived from the key, never chosen
// by the node, so a host cannot claim another node's name first.
func Subject(nodeKey crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(nodeKey)
	if err != nil {
		return "", fmt.Errorf("node key: %w", err)
	}
	sum := sha256.Sum256(der)
	return "n-" + hex.EncodeToString(sum[:8]), nil
}

// Attested is what CDS checked about the node a token is minted for.
type Attested struct {
	// NodeKey is the key the node's evidence was bound to.
	NodeKey crypto.PublicKey
	// TEE is the platform family of the evidence, "tdx" or "sev-snp".
	TEE string
	// LaunchDigest is the node's verified launch measurement.
	LaunchDigest string
}

// Mint signs a token for a node CDS has attested, for one of the issuer's
// audiences, and returns it with its expiry.
func (i *Issuer) Mint(audience string, node Attested) (string, time.Time, error) {
	if !slices.Contains(i.cfg.Audiences, audience) {
		return "", time.Time{}, fmt.Errorf("%w: %q", ErrAudience, audience)
	}
	if node.TEE == "" || node.LaunchDigest == "" {
		return "", time.Time{}, errors.New("node token needs the attested TEE and launch digest")
	}
	sub, err := Subject(node.NodeKey)
	if err != nil {
		return "", time.Time{}, err
	}
	if !subjectPattern.MatchString(sub) {
		return "", time.Time{}, fmt.Errorf("node token subject %q has the wrong shape", sub)
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", time.Time{}, err
	}
	now := i.now().Truncate(time.Second)
	expires := now.Add(i.cfg.TTL)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":           i.cfg.URL,
		"aud":           audience,
		"sub":           sub,
		"cluster":       i.cfg.Cluster,
		"tee":           node.TEE,
		"launch_digest": node.LaunchDigest,
		"iat":           now.Unix(),
		"nbf":           now.Unix(),
		"exp":           expires.Unix(),
		"jti":           hex.EncodeToString(jti),
	})
	token.Header["kid"] = i.kid
	signed, err := token.SignedString(i.key)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expires, nil
}

// ErrAudience is returned for a request naming an audience this issuer does
// not mint for.
var ErrAudience = errors.New("not an audience of this issuer")

// Discovery is the issuer's OpenID discovery document, the fields a
// Kubernetes JWT authenticator reads.
func (i *Issuer) Discovery() ([]byte, error) {
	return json.Marshal(map[string]any{
		"issuer":                                i.cfg.URL,
		"jwks_uri":                              i.cfg.URL + KeysPath,
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
	})
}

// Keys is the issuer's JSON Web Key Set: its one current public key.
func (i *Issuer) Keys() ([]byte, error) {
	x, y, err := coordinates(&i.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC",
		"crv": "P-256",
		"x":   x,
		"y":   y,
		"alg": "ES256",
		"use": "sig",
		"kid": i.kid,
	}}})
}

// coordinates are a P-256 key's x and y as JWK encodes them: 32 bytes each,
// base64url, read from the key's uncompressed encoding.
func coordinates(pub *ecdsa.PublicKey) (string, string, error) {
	point, err := pub.Bytes()
	if err != nil {
		return "", "", err
	}
	if len(point) != 65 || point[0] != 4 {
		return "", "", errors.New("node token key is not an uncompressed P-256 point")
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc(point[1:33]), enc(point[33:]), nil
}

// thumbprint is the RFC 7638 thumbprint of an EC key, its key id.
func thumbprint(pub *ecdsa.PublicKey) (string, error) {
	x, y, err := coordinates(pub)
	if err != nil {
		return "", err
	}
	canonical, err := json.Marshal(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{"P-256", "EC", x, y})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// Handler serves the issuer's discovery document and keys, and nothing else.
// Both are public by design: they let anyone check a token, not mint one.
func (i *Issuer) Handler() (http.Handler, error) {
	discovery, err := i.Discovery()
	if err != nil {
		return nil, err
	}
	keys, err := i.Keys()
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	serve := func(body []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "public, max-age=300")
			w.Write(body)
		}
	}
	mux.Handle("GET "+DiscoveryPath, serve(discovery))
	mux.Handle("GET "+KeysPath, serve(keys))
	return mux, nil
}

// MintsFor reports whether audience is one this issuer mints for.
func (i *Issuer) MintsFor(audience string) bool {
	return slices.Contains(i.cfg.Audiences, audience)
}
