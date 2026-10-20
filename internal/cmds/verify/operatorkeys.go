package verify

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// fetchOperatorKeyFingerprints GETs <base>/operator-keys and returns a hex
// SHA-256 fingerprint of each pinned operator public key (of its PKIX/SPKI DER,
// so `openssl pkey -pubin -outform DER < operator.pub | sha256sum` reproduces
// it), plus the served set's KeySetDigest for comparison against the attested
// --operator-keys bundle (applySandboxPolicy).
//
// A 404 sets note and returns the empty-set digest: the endpoint reports
// allowlist writes disabled, which --operator-keys can still be checked against.
func fetchOperatorKeyFingerprints(ctx context.Context, base, serverName, wantCertSHA256 string, timeout time.Duration) (fingerprints []string, digest []byte, note string, err error) {
	resp, err := fetchAttested(ctx, base+operatorauth.PublishedKeysPath, serverName, wantCertSHA256, timeout)
	if err != nil {
		return nil, nil, "", fmt.Errorf("fetch %s: %w", operatorauth.PublishedKeysPath, err)
	}
	defer resp.Body.Close()

	keys, err := operatorauth.ReadPublishedKeys(resp)
	if errors.Is(err, operatorauth.ErrNoPublishedKeys) {
		// Writes disabled — the empty set. Returning its digest lets
		// --operator-keys distinguish "no keys" from "not fetched".
		emptyDigest, err := operatorauth.KeySetDigest(nil)
		if err != nil {
			return nil, nil, "", err
		}
		return nil, emptyDigest, "endpoint reports no pinned operator keys (allowlist writes disabled)", nil
	}
	if err != nil {
		return nil, nil, "", err
	}
	for _, pub := range keys {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, nil, "", fmt.Errorf("fingerprint operator key: %w", err)
		}
		sum := sha256.Sum256(der)
		fingerprints = append(fingerprints, hex.EncodeToString(sum[:]))
	}
	if digest, err = operatorauth.KeySetDigest(keys); err != nil {
		return nil, nil, "", err
	}
	return fingerprints, digest, "", nil
}
