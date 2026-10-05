package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// trustOperator enforces --trust-operator: every policy in the attested bound
// must carry the operator's signature, the write token that published it,
// under the key set the attested state names. The key set is
// --trust-operator-keys when given, else the one the router serves, checked
// against the state.
func trustOperator(ctx context.Context, cfg config, ev *evidence, oc *Outcome) {
	if !cfg.trustOperator || (!oc.Verified && !oc.Partial) {
		return
	}
	fail := func(format string, args ...any) {
		oc.Verified, oc.Partial = false, false
		oc.Error = fmt.Sprintf(format, args...)
	}
	switch {
	case ev.rolloutErr != nil:
		fail("pinned_state_invalid: %v", ev.rolloutErr)
		return
	case ev.rollout == nil:
		fail("pinned_state_absent: --trust-operator needs an attest-pq or attest-lb target serving the CDS rollout state (router.attest.pinnedAllowlist)")
		return
	case !ev.fresh:
		fail("pinned_state_stale: the rollout state is not bound to a nonce this run chose")
		return
	case ev.rollout.Lease <= 0:
		fail("pinned_state_unleased: CDS applies allowlist writes without an activation lease, so open sessions are not fenced")
		return
	case cfg.url == "":
		fail("policy_signature_unchecked: --trust-operator needs a live target, not --from-file")
		return
	}
	_, baseURL, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		fail("policy_signature_unchecked: %v", err)
		return
	}
	client := insecureClient(cfg.server, cfg.timeout)
	keys, err := operatorKeySet(ctx, cfg, client, baseURL)
	if err != nil {
		fail("operator_keys_unavailable: %v", err)
		return
	}
	if hash, err := operatorauth.KeySetHash(keys); err != nil || hash != ev.rollout.OperatorKeys {
		fail("operator_keys_mismatch: the attested state names operator key set %q, not this one (%s)", ev.rollout.OperatorKeys, hash)
		return
	}
	for _, digest := range ev.rollout.Bound {
		if !policyDigestRE.MatchString(digest) {
			fail("policy_not_signed: malformed digest %q in the rollout state", digest)
			return
		}
		object := baseURL + "/.well-known/c8s/objects/sha256/" + strings.TrimPrefix(digest, "sha256:")
		body, err := fetchPolicy(ctx, client, object)
		if err != nil {
			fail("policy_not_signed: fetch %s: %v", digest, err)
			return
		}
		if sum := sha256.Sum256(body); "sha256:"+hex.EncodeToString(sum[:]) != digest {
			fail("allowlist_digest_mismatch: the router served bytes for %s that hash to sha256:%x", digest, sum)
			return
		}
		token, err := fetchPolicy(ctx, client, object+"/signature")
		if err != nil {
			fail("policy_not_signed: policy %s carries no operator signature (%v); sign it with a whole-document write (c8s allowlist upload)", digest, err)
			return
		}
		if err := operatorauth.VerifyStored(keys, strings.TrimSpace(string(token)), http.MethodPut, "/allowlist", body); err != nil {
			fail("policy_not_signed: policy %s: %v", digest, err)
			return
		}
	}
	oc.AllowlistBound = ev.rollout.Bound
	oc.VerifiedState = ev.rollout.Head
}

func operatorKeySet(ctx context.Context, cfg config, client *http.Client, baseURL string) ([]*ecdsa.PublicKey, error) {
	var pemBytes []byte
	var err error
	if cfg.trustOperatorKeys != "" {
		pemBytes, err = os.ReadFile(cfg.trustOperatorKeys)
	} else {
		pemBytes, err = fetchPolicy(ctx, client, baseURL+"/.well-known/c8s/operator-keys")
	}
	if err != nil {
		return nil, err
	}
	return operatorauth.ParsePublicKeysPEM(pemBytes)
}
