package verify

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
)

// checkAllowlistDigestFlags validates --allowlist-digest. Only attested
// transcripts bind an allowlist digest, so the flag applies to the attested
// modes and to saved attestation responses.
func checkAllowlistDigestFlags(cfg config) error {
	if len(cfg.allowlistDigests) == 0 {
		return nil
	}
	for _, d := range cfg.allowlistDigests {
		if !policyDigestRE.MatchString(d) {
			return fmt.Errorf("--allowlist-digest %q is not sha256:<64 lowercase hex>", d)
		}
	}
	switch {
	case cfg.expectedRDHex != "":
		return errors.New("--allowlist-digest does not apply with --expected-report-data: the override replaces the transcript that binds the allowlist digest")
	case !attestedMode(cfg) && cfg.fromFile == "":
		return errors.New("--allowlist-digest applies only to --mode attest-pq, --mode attest-lb and saved attestation responses")
	}
	return nil
}

// servedAllowlistDigest decodes a bundle's allowlist_digest. The transcript
// is recomputed with it, so a forged value fails verification; the pin check
// then runs on the verified value (applyAllowlistDigestPolicy).
func servedAllowlistDigest(served string) ([]byte, error) {
	d, err := hex.DecodeString(served)
	if err != nil || len(d) != overenc.AllowlistDigestBytes || hex.EncodeToString(d) != served {
		return nil, fmt.Errorf("the responder's allowlist_digest %q is not %d lower-case hex characters", served, 2*overenc.AllowlistDigestBytes)
	}
	return d, nil
}

// applyAllowlistDigestPolicy reports the allowlist digest the verified
// transcript binds and enforces --allowlist-digest on it. It fails a partial
// verdict too, like --pin-policy.
func applyAllowlistDigestPolicy(oc *Outcome, cfg config, ev *evidence) {
	if ev.allowlistDigest == nil || (!oc.Verified && !oc.Partial) {
		return
	}
	digest := "sha256:" + hex.EncodeToString(ev.allowlistDigest)
	switch {
	case len(cfg.allowlistDigests) == 0:
		oc.AllowlistDigest = digest
		oc.AllowlistNote = "reported: the router's last fetch of the CDS allowlist; pass --allowlist-digest to require one"
	case slices.Contains(cfg.allowlistDigests, digest):
		oc.AllowlistDigest = digest
		oc.AllowlistNote = "pinned: matches --allowlist-digest"
	default:
		oc.Verified, oc.Partial = false, false
		if oc.Error == "" {
			oc.Error = fmt.Sprintf("allowlist_digest_not_pinned: the router binds allowlist %s, which no --allowlist-digest value names", digest)
		}
	}
}
