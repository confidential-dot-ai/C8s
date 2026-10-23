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
	"regexp"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// keyFingerprintRE is an operator key fingerprint: the hex SHA-256 of the
// key's PKIX/SPKI DER, as verify reports operator keys.
var keyFingerprintRE = regexp.MustCompile(`^(sha256:)?[0-9a-f]{64}$`)

// signerPins is the parsed --operator-key set: public keys read from PEM
// files, and fingerprints the target's /operator-keys must supply keys for.
type signerPins struct {
	keys         []*ecdsa.PublicKey
	fingerprints []string
}

// parseSignerPins reads --operator-key. Each value is a fingerprint or a PEM
// file of one or more operator public keys.
func parseSignerPins(cfg config) (*signerPins, error) {
	if len(cfg.operatorKey) == 0 {
		return nil, nil
	}
	if cfg.url == "" {
		return nil, errors.New("--operator-key needs a live target to fetch the leaf's allowlist from")
	}
	pins := &signerPins{}
	for _, v := range cfg.operatorKey {
		if keyFingerprintRE.MatchString(v) {
			pins.fingerprints = append(pins.fingerprints, strings.TrimPrefix(v, "sha256:"))
			continue
		}
		pemBytes, err := os.ReadFile(v)
		if err != nil {
			return nil, fmt.Errorf("--operator-key %q is neither a sha256 key fingerprint nor a readable PEM file: %w", v, err)
		}
		keys, err := operatorauth.ParsePublicKeysPEM(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("--operator-key %s: %w", v, err)
		}
		pins.keys = append(pins.keys, keys...)
	}
	return pins, nil
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

// checkAllowlistSigner enforces --operator-key: the allowlist the leaf is
// stamped with must carry a stored write token that verifies under a pinned
// key. Like checkPolicyHistory it fetches over any connection: the document
// authenticates itself against the stamped digest, the token against the
// pinned keys, and a fingerprint-pinned key against its fingerprint. It
// reports whether the verdict failed because the target could not be reached.
func checkAllowlistSigner(ctx context.Context, oc *Outcome, cfg config, ev *evidence, pins *signerPins) (unreachable bool) {
	if pins == nil || (!oc.Verified && !oc.Partial) {
		return false
	}
	fail := func(format string, args ...any) {
		oc.Verified, oc.Partial = false, false
		oc.Error = fmt.Sprintf(format, args...)
	}
	digest, err := leafPolicy(ev)
	switch {
	case errors.Is(err, errLeafUnstamped):
		demoteNaming(oc, "the operator that signed the leaf's allowlist: the leaf carries no matched-workload stamp, so --operator-key checked nothing")
		return false
	case err != nil:
		fail("allowlist_unstamped: %v", err)
		return false
	case digest == "":
		fail("allowlist_unstamped: --operator-key needs evidence carrying the target's mesh leaf")
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
	keys := pins.keys
	if len(pins.fingerprints) > 0 {
		served, err := fetchPolicy(ctx, baseURL+operatorauth.PublishedKeysPath, cfg.server, cfg.timeout)
		switch {
		case errors.Is(err, errNotFound):
			// A router does not proxy /operator-keys.
		case err != nil:
			fail("allowlist_fetch_failed: fetch %s to resolve --operator-key fingerprints: %v", operatorauth.PublishedKeysPath, err)
			return isConnectError(err)
		default:
			servedKeys, err := operatorauth.ParsePublicKeysPEM(served)
			if err != nil {
				fail("allowlist_fetch_failed: %s: %v", operatorauth.PublishedKeysPath, err)
				return false
			}
			for _, k := range servedKeys {
				if fp, err := keyFingerprint(k); err == nil && slices.Contains(pins.fingerprints, fp) {
					keys = append(keys, k)
				}
			}
		}
	}
	if len(keys) == 0 {
		fail("allowlist_signer_not_pinned: the target serves no key at %s matching the --operator-key fingerprints; pass the operator public key PEM instead", operatorauth.PublishedKeysPath)
		return false
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
	fail("allowlist_signer_not_pinned: the leaf's allowlist %s is signed by no --operator-key", digest)
	return false
}
