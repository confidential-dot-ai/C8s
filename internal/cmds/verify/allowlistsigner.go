package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// parseSignerPins reads --allowlist-signer: PEM files of operator public
// keys.
func parseSignerPins(cfg config) ([]*ecdsa.PublicKey, error) {
	if len(cfg.allowlistSigner) == 0 {
		return nil, nil
	}
	if cfg.url == "" {
		return nil, errors.New("--allowlist-signer needs a live target to fetch the leaf's allowlist from")
	}
	var keys []*ecdsa.PublicKey
	for _, path := range cfg.allowlistSigner {
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read --allowlist-signer: %w", err)
		}
		k, err := operatorauth.ParsePublicKeysPEM(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("--allowlist-signer %s: %w", path, err)
		}
		keys = append(keys, k...)
	}
	return keys, nil
}

// keyFingerprint is the hex SHA-256 of pub's PKIX/SPKI DER.
func keyFingerprint(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// checkAllowlistSigner enforces --allowlist-signer: the allowlist the leaf is
// stamped with must carry a stored write token that verifies under a pinned
// key. Like checkPolicyHistory it fetches over any connection: the document
// authenticates itself against the stamped digest, the token against the
// pinned keys. It reports whether the verdict failed because the target could not be reached.
func checkAllowlistSigner(ctx context.Context, oc *Outcome, cfg config, ev *evidence, keys []*ecdsa.PublicKey) (unreachable bool) {
	if keys == nil || (!oc.Verified && !oc.Partial) {
		return false
	}
	fail := func(format string, args ...any) {
		oc.Verified, oc.Partial = false, false
		oc.Error = fmt.Sprintf(format, args...)
	}
	digest, err := leafPolicy(ev)
	switch {
	case errors.Is(err, errLeafUnstamped):
		demoteNaming(oc, "the operator that signed the leaf's allowlist: the leaf carries no matched-workload stamp, so --allowlist-signer checked nothing")
		return false
	case err != nil:
		fail("allowlist_unstamped: %v", err)
		return false
	case digest == "":
		fail("allowlist_unstamped: --allowlist-signer needs evidence carrying the target's mesh leaf")
		return false
	}
	_, baseURL, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		fail("allowlist_fetch_failed: %v", err)
		return false
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	object := baseURL + "/allowlist/objects/sha256/" + hexDigest
	body, err := fetchPolicy(ctx, object, cfg.server, cfg.timeout)
	if err != nil {
		fail("allowlist_fetch_failed: fetch %s: %v", digest, err)
		return isConnectError(err)
	}
	if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != hexDigest {
		fail("allowlist_digest_mismatch: the target served bytes for %s that hash to sha256:%x", digest, sum)
		return false
	}
	token, err := fetchPolicy(ctx, object+"/signature", cfg.server, cfg.timeout)
	if errors.Is(err, errNotFound) {
		fail("allowlist_unsigned: the leaf's allowlist %s carries no operator signature; upload the whole document to sign it (c8s allowlist upload)", digest)
		return false
	}
	if err != nil {
		fail("allowlist_fetch_failed: fetch the signature of %s: %v", digest, err)
		return isConnectError(err)
	}
	var invalid error
	for _, k := range keys {
		err := operatorauth.VerifyStored([]*ecdsa.PublicKey{k}, strings.TrimSpace(string(token)), http.MethodPut, "/allowlist", body)
		if err == nil {
			fp, err := keyFingerprint(k)
			if err != nil {
				fail("allowlist_signature_invalid: %v", err)
				return false
			}
			oc.AllowlistSigner = fp
			demoteUnvouchedStamp(oc, cfg, "operator-signed")
			return false
		}
		// A signature made by another key fails as invalid or unverifiable
		// under this one; anything else is a token that is broken or binds
		// another write.
		if invalid == nil && !errors.Is(err, jwt.ErrTokenSignatureInvalid) && !errors.Is(err, jwt.ErrTokenUnverifiable) {
			invalid = err
		}
	}
	if invalid != nil {
		fail("allowlist_signature_invalid: the leaf's allowlist %s: %v", digest, invalid)
		return false
	}
	fail("allowlist_signer_not_pinned: the leaf's allowlist %s is signed by no --allowlist-signer key", digest)
	return false
}
