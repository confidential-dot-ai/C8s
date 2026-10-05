// Package operatorauth implements the operator-credential scheme that
// authorizes C8s allowlist mutations (POST/PUT/DELETE /allowlist).
//
// STOP-GAP DESIGN — pinned public keys. CDS is configured with a set of trusted
// operator EC public keys. For each write the client mints a short-lived
// ES256/384/512 JWT signed with an operator EC private key, carrying a `pbh`
// claim equal to the SHA-256 of the exact request body plus `htm`/`htu` claims
// naming the method and path. CDS verifies the signature against its pinned
// keys, re-hashes the body against pbh, matches htm/htu against the request,
// and rejects any token whose exp−iat exceeds MaxTokenValidity — so a captured
// token cannot be replayed against a different payload, verb, or path, and
// cannot be minted long-lived regardless of client tooling.
//
// FUTURE IMPROVEMENT — a CA + operator certificates (chain carried in the JWT
// x5c header), giving delegated issuance and CA-based revocation instead of
// editing a pinned-key list, plus single-file (cert+key) operator credentials.
//
// Either way this is the sole authorization path for allowlist writes.
package operatorauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// claimPayloadBodyHash binds a token to a specific request body using
// base64url(SHA-256(body)).
const claimPayloadBodyHash = "pbh"

// claimHTTPMethod and claimHTTPPath bind a token to the request's method and
// path (names per RFC 9449 DPoP).
// DEVIATION: htu carries only the URL path, not the full URI RFC 9449 specifies
// — the client-visible host may differ from CDS's behind a proxy or LB.
const (
	claimHTTPMethod = "htm"
	claimHTTPPath   = "htu"
)

// DefaultTokenTTL is the lifetime the Signer stamps on minted tokens. A write is
// a single request, so the token only needs to outlive the round trip plus
// clock skew; keeping it short bounds the replay window.
const DefaultTokenTTL = 60 * time.Second

// MaxTokenValidity is the widest exp−iat window the Verifier accepts. The
// Signer's TTL is client-side only, so without this bound a token minted by
// other tooling could be replayable (against the same body) indefinitely.
const MaxTokenValidity = 5 * time.Minute

// validMethods is the ECDSA signing-method allowlist for both minting and
// verification. RSA/HMAC/none are rejected so a token cannot downgrade the
// algorithm (e.g. HMAC-with-the-public-key confusion).
var validMethods = []string{
	jwt.SigningMethodES256.Alg(),
	jwt.SigningMethodES384.Alg(),
	jwt.SigningMethodES512.Alg(),
}

// KeySetHash returns the lowercase-hex form of KeySetDigest for a non-empty
// operator public-key set. Empty sets are rejected here (KeySetDigest is used
// directly where the empty set is a defined value).
func KeySetHash(keys []*ecdsa.PublicKey) (string, error) {
	if len(keys) == 0 {
		return "", fmt.Errorf("operator key set is empty")
	}
	digest, err := KeySetDigest(keys)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest), nil
}

// Signer mints operator authorization tokens from an EC private key. Construct
// with NewSignerFromKeyPEM; the zero value is unusable.
type Signer struct {
	key    *ecdsa.PrivateKey
	method jwt.SigningMethod
	ttl    time.Duration
}

// NewSignerFromKeyPEM builds a Signer from a PEM EC private key (PKCS#8 or SEC1).
func NewSignerFromKeyPEM(keyPEM []byte) (*Signer, error) {
	key, err := certutil.ParseECPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse operator key: %w", err)
	}
	method, err := esMethodFor(key.Curve)
	if err != nil {
		return nil, err
	}
	return &Signer{key: key, method: method, ttl: DefaultTokenTTL}, nil
}

// Authorization returns the HTTP Authorization header value ("Bearer <jwt>")
// for a token freshly bound to the request. It satisfies
// allowlistclient.Authorizer; the caller must pass the exact method, URL path,
// and body bytes it will send so the htm/htu/pbh claims match server-side.
func (s *Signer) Authorization(method, path string, body []byte) (string, error) {
	now := time.Now()
	sum := sha256.Sum256(body)
	claims := jwt.MapClaims{
		"iat":                now.Unix(),
		"exp":                now.Add(s.ttl).Unix(),
		claimHTTPMethod:      method,
		claimHTTPPath:        path,
		claimPayloadBodyHash: base64.RawURLEncoding.EncodeToString(sum[:]),
	}
	signed, err := jwt.NewWithClaims(s.method, claims).SignedString(s.key)
	if err != nil {
		return "", fmt.Errorf("sign operator token: %w", err)
	}
	return "Bearer " + signed, nil
}

// Verifier authorizes an allowlist mutation by validating the operator token on
// the request against a set of pinned operator public keys: signature, exp−iat
// within MaxTokenValidity, htm/htu against the request's method and path, and
// pbh against the body. It satisfies allowlist.WriteAuthorizer via Authorize.
type Verifier struct {
	// Keys are the pinned operator public keys; a token is authorized if it
	// verifies under any one of them. An empty set rejects every request.
	Keys []*ecdsa.PublicKey
	// ClockSkew is the leeway applied to exp/nbf/iat validation.
	ClockSkew time.Duration
}

// Authorize returns nil when the request carries a valid, body-bound operator
// token signed by one of the pinned keys. Any failure returns a non-nil error
// and the caller must reject the mutation.
func (v Verifier) Authorize(r *http.Request, body []byte) error {
	tokenStr, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tokenStr == "" {
		return fmt.Errorf("missing operator bearer token")
	}
	return verifyToken(v.Keys, tokenStr, r.Method, r.URL.Path, body,
		jwt.WithLeeway(v.ClockSkew), jwt.WithIssuedAt(), jwt.WithExpirationRequired())
}

// VerifyStored checks a token that authorized a past request: its signature
// under one of keys, and its method, path and body binding. It skips the
// time checks, since a stored token is always expired by the time it is
// read; the server that accepted the request enforced them. It still
// requires exp−iat within MaxTokenValidity.
func VerifyStored(keys []*ecdsa.PublicKey, token, method, path string, body []byte) error {
	return verifyToken(keys, token, method, path, body, jwt.WithoutClaimsValidation())
}

func verifyToken(keys []*ecdsa.PublicKey, tokenStr, method, path string, body []byte, opts ...jwt.ParserOption) error {
	if len(keys) == 0 {
		return fmt.Errorf("no operator keys configured")
	}

	// Try each pinned key. A signature made by key N fails verification under
	// the others, so at most one key yields a valid token; once one does, its
	// result (including the body-binding check) is authoritative.
	var lastErr error
	for _, pub := range keys {
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method %s", t.Method.Alg())
			}
			return pub, nil
		}, append([]jwt.ParserOption{jwt.WithValidMethods(validMethods)}, opts...)...)
		if err != nil {
			lastErr = err
			continue
		}
		if !token.Valid {
			lastErr = fmt.Errorf("token not valid")
			continue
		}

		// Signature verified under this key; claim failures are authoritative.
		// The Signer's TTL is client-side only, so the replay bound is enforced
		// here: iat is required and exp−iat must fit MaxTokenValidity, whatever
		// tooling minted the token.
		iat, err := claims.GetIssuedAt()
		if err != nil || iat == nil {
			return fmt.Errorf("operator token missing iat claim")
		}
		exp, err := claims.GetExpirationTime()
		if err != nil || exp == nil {
			return fmt.Errorf("operator token missing exp claim")
		}
		if validity := exp.Sub(iat.Time); validity <= 0 || validity > MaxTokenValidity {
			return fmt.Errorf("operator token validity %s outside (0, %s]", validity, MaxTokenValidity)
		}
		if htm, _ := claims[claimHTTPMethod].(string); htm != method {
			return fmt.Errorf("operator token %s %q does not match request method %q", claimHTTPMethod, htm, method)
		}
		if htu, _ := claims[claimHTTPPath].(string); htu != path {
			return fmt.Errorf("operator token %s %q does not match request path %q", claimHTTPPath, htu, path)
		}

		// Body binding: the token's pbh must equal SHA-256 of the body the
		// server received. Constant-time to avoid leaking the comparison via
		// timing.
		pbh, _ := claims[claimPayloadBodyHash].(string)
		if pbh == "" {
			return fmt.Errorf("operator token missing %s claim", claimPayloadBodyHash)
		}
		sum := sha256.Sum256(body)
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(pbh), []byte(want)) != 1 {
			return fmt.Errorf("operator token %s does not match request body", claimPayloadBodyHash)
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("token not signed by any pinned operator key")
	}
	return fmt.Errorf("operator token invalid: %w", lastErr)
}

// ParsePublicKeysPEM parses one or more PEM "PUBLIC KEY" (PKIX/SubjectPublicKeyInfo)
// blocks into EC public keys. It is the single parser shared by CDS's
// --operator-keys load path and the install-time validation, and it fails when
// no EC public key is present so a wrong file cannot silently disable writes.
func ParsePublicKeysPEM(pemBytes []byte) ([]*ecdsa.PublicKey, error) {
	var keys []*ecdsa.PublicKey
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse operator public key: %w", err)
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("operator public key is not ECDSA")
		}
		keys = append(keys, ec)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no PEM PUBLIC KEY block found")
	}
	return keys, nil
}

func esMethodFor(curve elliptic.Curve) (jwt.SigningMethod, error) {
	switch curve {
	case elliptic.P256():
		return jwt.SigningMethodES256, nil
	case elliptic.P384():
		return jwt.SigningMethodES384, nil
	case elliptic.P521():
		return jwt.SigningMethodES512, nil
	default:
		return nil, fmt.Errorf("unsupported operator key curve %s (use P-256, P-384, or P-521)", curve.Params().Name)
	}
}
