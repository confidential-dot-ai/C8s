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

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// policyDigestRE is the form of an allowlist policy digest.
var policyDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// checkHistoryFlags validates --pin-policy, --trust-operator and
// --fetch-allowlists against images, the parsed --image-policy-file pins, and
// returns the parsed --trust-operator-keys.
func checkHistoryFlags(cfg config, images []remote.ImagePin) ([]*ecdsa.PublicKey, error) {
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
	if cfg.operatorPubkey == "" && !slices.ContainsFunc(images, anchored) {
		return nil, fmt.Errorf("%s requires --operator-pkey or an --image-policy-file image pinning an approver_key: the node's policy history counts only as far as it replays against RTMR[3] after the operator-key seed", flag)
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
	case errors.Is(err, errLeafUnstamped):
		demoteUnstamped(oc, "pinned")
	case err != nil:
		fail("policy_history_not_pinned: %v", err)
	case d != "" && !slices.Contains(cfg.pinPolicies, d):
		fail("policy_history_not_pinned: the leaf was issued under policy %s, which is not pinned", d)
	case d != "":
		demoteUnvouchedStamp(oc, cfg, "pinned")
	}
	demoteStaleHistory(oc, ev, "pinned")
}

// demoteStaleHistory leaves a verdict whose judged history comes from evidence
// not bound to this check's nonce partial at best: the operator may have
// pushed another policy since the quote, which that evidence cannot show.
func demoteStaleHistory(oc *Outcome, ev *evidence, judged string) {
	if ev.fresh {
		return
	}
	demoteNaming(oc, fmt.Sprintf("the node's current policy history: the history is %s up to the evidence's quote, which this check's nonce does not bind, so a policy enforced since is not shown (use --mode attest-pq or attest-lb)", judged))
}

// applyUncheckedHistoryPolicy demotes a verdict whose RTMR[3] replayed a
// non-empty policy history that neither --pin-policy nor --trust-operator
// judged: the replay proves which policies the node enforced, not that any of
// them is acceptable, and the list it replays may be host-supplied.
func applyUncheckedHistoryPolicy(oc *Outcome, cfg config) {
	if len(oc.MeasuredPolicies) == 0 || len(cfg.pinPolicies) > 0 || cfg.trustOperator {
		return
	}
	demoteToPartial(oc, fmt.Sprintf("the node's policy history: RTMR[3] replayed %d measured policies, but no policy over them was checked (pass --pin-policy or --trust-operator)", len(oc.MeasuredPolicies)))
}

// errLeafUnstamped reports a leaf without a matched-workload stamp: CDS
// issues one whenever the pod matches no single allowlist entry.
var errLeafUnstamped = errors.New("the leaf carries no matched-workload stamp")

// leafPolicy returns the digest of the policy the leaf was issued under, ""
// when the evidence speaks for no leaf, and errLeafUnstamped for a leaf
// without a stamp.
func leafPolicy(ev *evidence) (string, error) {
	switch {
	case ev.workload != nil && len(ev.workload.AllowlistDigest) != sha256.Size:
		return "", fmt.Errorf("the leaf's matched-workload stamp carries a %d-byte policy digest, want %d", len(ev.workload.AllowlistDigest), sha256.Size)
	case ev.workload != nil:
		return "sha256:" + hex.EncodeToString(ev.workload.AllowlistDigest), nil
	case ev.workloadErr != nil:
		return "", fmt.Errorf("the leaf's issuing policy cannot be read: %w", ev.workloadErr)
	case ev.leaf != nil:
		return "", errLeafUnstamped
	}
	return "", nil
}

// demoteUnstamped leaves a verdict whose history was judged but whose leaf is
// unstamped partial at best: an unstamped leaf is indistinguishable from one
// issued to a pod that presented no sandbox token.
func demoteUnstamped(oc *Outcome, judged string) {
	demoteNaming(oc, fmt.Sprintf("the policy the leaf was issued under: the policy history is %s, but the leaf carries no matched-workload stamp, so its issuing policy was not checked", judged))
}

// demoteUnvouchedStamp leaves a verdict partial at best when the leaf's stamp
// was judged without --mesh-ca: the stamp says CDS issued the leaf under that
// policy, which only a chain to the pinned CA proves (applySandboxPolicy has
// already failed the verdict when that chain does not verify).
func demoteUnvouchedStamp(oc *Outcome, cfg config, judged string) {
	if cfg.meshCA != "" {
		return
	}
	demoteNaming(oc, fmt.Sprintf("the policy the leaf was issued under: its matched-workload stamp is %s, but it is CA-vouched and no --mesh-ca chain authenticated it", judged))
}

// demoteNaming is demoteToPartial that also names the gap on an already
// partial verdict.
func demoteNaming(oc *Outcome, note string) {
	if oc.Partial {
		oc.NotProven = append(oc.NotProven, note)
		return
	}
	demoteToPartial(oc, note)
}

// noHistory explains an empty replayed history: a node that does not measure
// its policies proves nothing about which ones it enforced.
const noHistory = "no measured policy replayed against RTMR[3]; target a node that measures its policies (a measured worker image)"

// historyTimeouts is how many --timeout spans the whole history check gets, so
// a target answering each fetch just in time cannot stall verify for hours.
const historyTimeouts = 4

// checkPolicyHistory fetches each policy in the replayed history from the
// target and checks it hashes to its digest, then saves it (--fetch-allowlists)
// and requires its stored operator signature to verify under keys
// (--trust-operator), which also covers the policy the leaf was issued under.
// The bytes authenticate themselves against the replayed digest and the token
// against keys, so the fetch needs no attested channel: binding it to one
// serving leaf would only fail on a different replica. It reports whether the
// verdict failed because the target could not be reached.
func checkPolicyHistory(ctx context.Context, oc *Outcome, cfg config, ev *evidence, keys []*ecdsa.PublicKey) (unreachable bool) {
	if !policyHistoryRequested(cfg) || (!oc.Verified && !oc.Partial) {
		return false
	}
	var err error
	if cfg.trustOperator {
		err = checkSignedHistory(ctx, oc, cfg, ev, keys)
	} else {
		err = savePolicyHistory(ctx, oc, cfg)
	}
	if err != nil {
		oc.Verified, oc.Partial = false, false
		oc.Error = err.Error()
		return isConnectError(err)
	}
	return false
}

func policyHistoryRequested(cfg config) bool {
	return cfg.trustOperator || cfg.fetchAllowlists != ""
}

// savePolicyHistory is --fetch-allowlists without --trust-operator.
func savePolicyHistory(ctx context.Context, oc *Outcome, cfg config) error {
	if len(oc.MeasuredPolicies) == 0 {
		oc.Warnings = append(oc.Warnings, "--fetch-allowlists saved nothing: "+noHistory)
		return nil
	}
	return checkHistoryPolicies(ctx, cfg, oc.MeasuredPolicies, historyCheck{failureCode: "allowlist_fetch_failed"})
}

// checkSignedHistory also requires a signature on the policy the leaf was
// issued under.
func checkSignedHistory(
	ctx context.Context,
	oc *Outcome,
	cfg config,
	ev *evidence,
	keys []*ecdsa.PublicKey,
) error {
	if len(oc.MeasuredPolicies) == 0 {
		return fmt.Errorf("policy_history_absent: %s", noHistory)
	}
	leaf, err := leafPolicy(ev)
	unstamped := errors.Is(err, errLeafUnstamped)
	if err != nil && !unstamped {
		return fmt.Errorf("policy_history_unsigned: %v", err)
	}
	signed := historyCheck{
		failureCode:       "policy_history_unsigned",
		requireSignatures: true,
		signedBy:          keys,
	}
	if err := checkHistoryPolicies(ctx, cfg, withPolicy(oc.MeasuredPolicies, leaf), signed); err != nil {
		return err
	}
	switch {
	case unstamped:
		demoteUnstamped(oc, "signed")
	case leaf != "":
		demoteUnvouchedStamp(oc, cfg, "signed")
	}
	demoteStaleHistory(oc, ev, "signed")
	return nil
}

// withPolicy is a copy of digests with policy added when it is not among them.
func withPolicy(digests []string, policy string) []string {
	out := slices.Clone(digests)
	if policy != "" && !slices.Contains(out, policy) {
		out = append(out, policy)
	}
	return out
}

type historyCheck struct {
	// failureCode prefixes an error that names no code of its own.
	failureCode string
	// With requireSignatures set and no keys in signedBy, every policy fails.
	requireSignatures bool
	signedBy          []*ecdsa.PublicKey
}

// Only a failed fetch wraps its cause, so isConnectError tells an unreachable
// target from a failed check.
func checkHistoryPolicies(
	ctx context.Context,
	cfg config,
	digests []string,
	check historyCheck,
) error {
	if cfg.url == "" {
		return fmt.Errorf("%s: fetching the policy history needs a target URL", check.failureCode)
	}
	_, baseURL, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		return fmt.Errorf("%s: %v", check.failureCode, err)
	}
	if cfg.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, historyTimeouts*cfg.timeout)
		defer cancel()
	}
	if cfg.fetchAllowlists != "" {
		if err := os.MkdirAll(cfg.fetchAllowlists, 0o755); err != nil {
			return fmt.Errorf("allowlist_fetch_failed: %v", err)
		}
	}
	for _, digest := range digests {
		hexDigest, ok := strings.CutPrefix(digest, "sha256:")
		if !ok || !policyDigestRE.MatchString(digest) {
			return fmt.Errorf("%s: malformed digest %q in the node's policy history", check.failureCode, digest)
		}
		object := baseURL + "/allowlist/objects/sha256/" + hexDigest
		body, err := fetchPolicy(ctx, object, cfg.server, cfg.timeout)
		if err != nil {
			return fmt.Errorf("%s: fetch %s: %w", check.failureCode, digest, err)
		}
		if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != hexDigest {
			return fmt.Errorf("allowlist_digest_mismatch: the target served bytes for %s that hash to sha256:%x", digest, sum)
		}
		if cfg.fetchAllowlists != "" {
			if err := os.WriteFile(filepath.Join(cfg.fetchAllowlists, hexDigest+".json"), body, 0o644); err != nil {
				return fmt.Errorf("allowlist_fetch_failed: %v", err)
			}
		}
		if check.requireSignatures {
			if err := verifyOperatorSignature(ctx, cfg, check.signedBy, digest, object, body); err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyOperatorSignature(
	ctx context.Context,
	cfg config,
	keys []*ecdsa.PublicKey,
	digest string,
	object string,
	body []byte,
) error {
	token, err := fetchPolicy(ctx, object+"/signature", cfg.server, cfg.timeout)
	if errors.Is(err, errNotFound) {
		return fmt.Errorf("policy_history_unsigned: policy %s carries no operator signature; upload the whole document to sign it (c8s allowlist upload)", digest)
	}
	if err != nil {
		return fmt.Errorf("policy_history_unsigned: fetch the signature of %s: %w", digest, err)
	}
	if err := operatorauth.VerifyStored(keys, strings.TrimSpace(string(token)), http.MethodPut, "/allowlist", body); err != nil {
		return fmt.Errorf("policy_history_unsigned: policy %s: %v", digest, err)
	}
	return nil
}
