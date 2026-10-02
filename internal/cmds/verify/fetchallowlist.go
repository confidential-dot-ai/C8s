package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// maxPolicyBytes bounds one fetched policy object.
const maxPolicyBytes = 16 << 20

// fetchAllowlists downloads every policy in the attested bound from the
// router and keeps it only when its SHA-256 matches the digest the attested
// state names: the operator-trusting alternative to pinning digests.
func fetchAllowlists(ctx context.Context, cfg config, oc *Outcome) {
	// A partial verdict still verified the attestation that commits the
	// state; it is the usual outcome without a --mesh-ca pin.
	if cfg.fetchAllowlists == "" || (!oc.Verified && !oc.Partial) {
		return
	}
	fail := func(format string, args ...any) {
		oc.Verified, oc.Partial = false, false
		oc.Error = fmt.Sprintf(format, args...)
	}
	if len(oc.AllowlistBound) == 0 {
		fail("allowlist_fetch_failed: the target attested no CDS rollout state (router.attest.pinnedAllowlist)")
		return
	}
	if cfg.url == "" {
		fail("allowlist_fetch_failed: --fetch-allowlists needs a live target, not --from-file")
		return
	}
	_, baseURL, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		fail("allowlist_fetch_failed: %v", err)
		return
	}
	if err := os.MkdirAll(cfg.fetchAllowlists, 0o755); err != nil {
		fail("allowlist_fetch_failed: %v", err)
		return
	}
	client := insecureClient(cfg.server, cfg.timeout)
	for _, digest := range oc.AllowlistBound {
		if !policyDigestRE.MatchString(digest) {
			fail("allowlist_fetch_failed: malformed digest %q in the rollout state", digest)
			return
		}
		hexDigest := strings.TrimPrefix(digest, "sha256:")
		body, err := fetchPolicy(ctx, client, baseURL+"/.well-known/c8s/objects/sha256/"+hexDigest)
		if err != nil {
			fail("allowlist_fetch_failed: %s: %v", digest, err)
			return
		}
		if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != hexDigest {
			fail("allowlist_digest_mismatch: the router served bytes for %s that hash to sha256:%x", digest, sum)
			return
		}
		path := filepath.Join(cfg.fetchAllowlists, hexDigest+".json")
		if err := os.WriteFile(path, body, 0o644); err != nil {
			fail("allowlist_fetch_failed: %v", err)
			return
		}
		oc.AllowlistFiles = append(oc.AllowlistFiles, path)
	}
}

func fetchPolicy(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxPolicyBytes))
}
