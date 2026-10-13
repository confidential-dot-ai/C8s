package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// policyDigestRE is the form of an allowlist policy digest.
var policyDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// checkHistoryFlags validates --pin-policy, --trust-operator and
// --fetch-allowlists, and returns the parsed --trust-operator-keys.
func checkHistoryFlags(cfg config) ([]*ecdsa.PublicKey, error) {
	for _, d := range cfg.pinPolicies {
		if !policyDigestRE.MatchString(d) {
			return nil, fmt.Errorf("--pin-policy %q is not sha256:<64 lowercase hex>", d)
		}
	}
	if cfg.trustOperator && len(cfg.pinPolicies) > 0 {
		return nil, fmt.Errorf("--trust-operator and --pin-policy are exclusive: accept what the operator signed, or only what you pinned")
	}
	if cfg.trustOperatorKeys != "" && !cfg.trustOperator {
		return nil, fmt.Errorf("--trust-operator-keys requires --trust-operator")
	}
	var flag string
	switch {
	case len(cfg.pinPolicies) > 0:
		flag = "--pin-policy"
	case cfg.trustOperator:
		flag = "--trust-operator"
	case cfg.fetchAllowlists != "":
		flag = "--fetch-allowlists"
	default:
		return nil, nil
	}
	if cfg.operatorPubkey == "" {
		return nil, fmt.Errorf("%s requires --operator-pkey: the node's policy history counts only as far as it replays against RTMR[3] after the operator-key seed", flag)
	}
	if !cfg.trustOperator {
		return nil, nil
	}
	if cfg.trustOperatorKeys == "" {
		return nil, fmt.Errorf("--trust-operator requires --trust-operator-keys: the operator public keys whose signatures it accepts")
	}
	pemBytes, err := os.ReadFile(cfg.trustOperatorKeys)
	if err != nil {
		return nil, fmt.Errorf("read --trust-operator-keys: %w", err)
	}
	keys, err := operatorauth.ParsePublicKeysPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("--trust-operator-keys: %w", err)
	}
	return keys, nil
}

// applyPinPolicy enforces --pin-policy: every policy the node enforced since
// boot, and the one the leaf was issued under, must be pinned. It fails a
// partial verdict too, so it holds wherever it runs among the demotions.
func applyPinPolicy(oc *Outcome, cfg config, ev *evidence) {
	if len(cfg.pinPolicies) == 0 || (!oc.Verified && !oc.Partial) {
		return
	}
	fail := func(format string, args ...any) {
		oc.Verified, oc.Partial = false, false
		if oc.Error == "" {
			oc.Error = fmt.Sprintf(format, args...)
		}
	}
	if len(oc.MeasuredPolicies) == 0 {
		fail("policy_history_absent: %s", noHistory)
		return
	}
	for _, d := range oc.MeasuredPolicies {
		if !slices.Contains(cfg.pinPolicies, d) {
			fail("policy_history_not_pinned: the node enforced policy %s since boot and it is not pinned; review it at /allowlist/objects/sha256/%s", d, strings.TrimPrefix(d, "sha256:"))
			return
		}
	}
	switch d, err := leafPolicy(ev); {
	case err != nil:
		fail("policy_history_not_pinned: %v", err)
	case d != "" && !slices.Contains(cfg.pinPolicies, d):
		fail("policy_history_not_pinned: the leaf was issued under policy %s, which is not pinned", d)
	}
}

// leafPolicy returns the digest of the policy the leaf was issued under, ""
// when the evidence speaks for no leaf.
func leafPolicy(ev *evidence) (string, error) {
	switch {
	case ev.workload != nil:
		return "sha256:" + hex.EncodeToString(ev.workload.AllowlistDigest), nil
	case ev.workloadErr != nil:
		return "", fmt.Errorf("the leaf's issuing policy cannot be read: %w", ev.workloadErr)
	case ev.leaf != nil:
		return "", errors.New("the leaf carries no issuing policy to check")
	}
	return "", nil
}

// noHistory explains an empty replayed history: a node that does not measure
// its policies proves nothing about which ones it enforced.
const noHistory = "no measured policy replayed against RTMR[3]; target a node that measures its policies (nriImagePolicy.measurePolicies)"

// checkPolicyHistory fetches each policy in the replayed history from the
// target and checks it hashes to its digest, then saves it (--fetch-allowlists)
// and requires its stored operator signature to verify under keys
// (--trust-operator), which also covers the policy the leaf was issued under. The bytes authenticate themselves against the replayed
// digest and the token against keys, so the fetch needs no attested channel:
// binding it to one serving leaf would only fail on a different replica.
func checkPolicyHistory(ctx context.Context, oc *Outcome, cfg config, ev *evidence, keys []*ecdsa.PublicKey) {
	if (!cfg.trustOperator && cfg.fetchAllowlists == "") || (!oc.Verified && !oc.Partial) {
		return
	}
	fail := func(format string, args ...any) {
		oc.Verified, oc.Partial = false, false
		oc.Error = fmt.Sprintf(format, args...)
	}
	code := "allowlist_fetch_failed"
	if cfg.trustOperator {
		code = "policy_history_unsigned"
	}
	if len(oc.MeasuredPolicies) == 0 {
		if cfg.trustOperator {
			fail("policy_history_absent: %s", noHistory)
			return
		}
		oc.Warnings = append(oc.Warnings, "--fetch-allowlists saved nothing: "+noHistory)
		return
	}
	digests := oc.MeasuredPolicies
	if cfg.trustOperator {
		d, err := leafPolicy(ev)
		if err != nil {
			fail("policy_history_unsigned: %v", err)
			return
		}
		if d != "" && !slices.Contains(digests, d) {
			digests = append(slices.Clone(digests), d)
		}
	}
	if cfg.url == "" {
		fail("%s: fetching the policy history needs a target URL", code)
		return
	}
	_, baseURL, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		fail("%s: %v", code, err)
		return
	}
	if cfg.fetchAllowlists != "" {
		if err := os.MkdirAll(cfg.fetchAllowlists, 0o755); err != nil {
			fail("allowlist_fetch_failed: %v", err)
			return
		}
	}
	for _, digest := range digests {
		hexDigest, ok := strings.CutPrefix(digest, "sha256:")
		if !ok || !policyDigestRE.MatchString(digest) {
			fail("%s: malformed digest %q in the node's policy history", code, digest)
			return
		}
		object := baseURL + "/allowlist/objects/sha256/" + hexDigest
		body, err := fetchPolicy(ctx, object, cfg.server, cfg.timeout)
		if err != nil {
			fail("%s: fetch %s: %v", code, digest, err)
			return
		}
		if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != hexDigest {
			fail("allowlist_digest_mismatch: the target served bytes for %s that hash to sha256:%x", digest, sum)
			return
		}
		if cfg.fetchAllowlists != "" {
			if err := os.WriteFile(filepath.Join(cfg.fetchAllowlists, hexDigest+".json"), body, 0o644); err != nil {
				fail("allowlist_fetch_failed: %v", err)
				return
			}
		}
		if !cfg.trustOperator {
			continue
		}
		token, err := fetchPolicy(ctx, object+"/signature", cfg.server, cfg.timeout)
		if errors.Is(err, errNotFound) {
			fail("policy_history_unsigned: policy %s carries no operator signature; upload the whole document to sign it (c8s allowlist upload)", digest)
			return
		}
		if err != nil {
			fail("policy_history_unsigned: fetch the signature of %s: %v", digest, err)
			return
		}
		if err := operatorauth.VerifyStored(keys, strings.TrimSpace(string(token)), http.MethodPut, "/allowlist", body); err != nil {
			fail("policy_history_unsigned: policy %s: %v", digest, err)
			return
		}
	}
}
