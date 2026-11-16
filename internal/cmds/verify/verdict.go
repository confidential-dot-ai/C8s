package verify

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// newOutcome maps a verifier verdict to the shared Outcome. The verifier proves
// the AMD chain, REPORTDATA binding, debug, and min-TCB; the launch-measurement
// allowlist (--measurements) and the TDX runtime-register pins have no
// verifier-side input, so they are enforced here on the signature-verified
// claims and fail closed.
func newOutcome(cfg config, ev *evidence, result *teetypes.VerificationResult, verr error, plan *verifyPlan) Outcome {
	oc := baseOutcome(cfg, ev, plan)
	if verr != nil {
		oc.Error = verr.Error()
		return oc
	}
	oc = withVerifiedClaims(oc, ev, result)
	if err := enforcePins(&oc, cfg, ev.measured, result, plan); err != nil {
		oc.Error = err.Error()
		return oc
	}
	oc.Verified = true
	return oc
}

// baseOutcome is what the evidence says before the verifier's verdict.
func baseOutcome(cfg config, ev *evidence, plan *verifyPlan) Outcome {
	oc := Outcome{
		Backend:           "attestation-go",
		VerifiedAt:        time.Now().UTC(),
		Source:            ev.source,
		Fresh:             ev.fresh,
		Binding:           ev.bindingNote,
		CertSHA256:        ev.certSHA256,
		ServingLeafSHA256: ev.servingLeafSHA256,
		Pinned:            plan.pinsLaunchMeasurement(),
	}
	if ev.leaf != nil {
		oc.CertBody = describeCertBody(cfg, ev)
		d, err := leafPolicy(ev)
		stamped := err == nil && d != ""
		oc.LeafStamped = &stamped
	}
	return oc
}

// withVerifiedClaims records the signature-verified claims. The platform is
// the one the verifier reported, else the one the evidence was sent as.
func withVerifiedClaims(oc Outcome, ev *evidence, result *teetypes.VerificationResult) Outcome {
	oc.Platform = string(result.Platform)
	if oc.Platform == "" {
		oc.Platform = ev.platform
	}
	oc.Measurement = result.Claims.LaunchDigest
	oc.CurrentTCB = formatTCB(result.Claims.TCB)
	oc.ReportData = hex.EncodeToString(result.Claims.ReportData)
	oc.Debug, oc.SMT = reportFlags(result.Claims)
	return oc
}

// enforcePins holds the verified claims to the run's pins, in this order, and
// stops at the first one they do not meet. It records on oc what it enforced
// and the gaps of a passing verdict.
func enforcePins(
	oc *Outcome,
	cfg config,
	measured []string,
	result *teetypes.VerificationResult,
	plan *verifyPlan,
) error {
	if err := requireTDXForRegisterPins(oc.Platform, plan.pins); err != nil {
		return err
	}
	if err := enforceMinTCB(oc.Platform, cfg, result); err != nil {
		return err
	}
	coverage, err := enforceImagePolicy(oc, measured, result, plan)
	if err != nil {
		return err
	}
	if plan.pinsLaunchMeasurement() {
		if err := enforceLaunchMeasurement(result, plan); err != nil {
			return err
		}
		if err := enforceTDXImageCoverage(oc, plan.meshCA, coverage.fullImage); err != nil {
			return err
		}
	}
	if err := enforceRTMRPins(oc, plan.pins, measured, result); err != nil {
		return err
	}
	warnUnreplayedHistory(oc, measured, coverage.historyBound)
	return nil
}

// pinsLaunchMeasurement reports whether the run pins the launch measurement.
// An image manifest is a measurement pin too — a strictly stronger one than an
// allowlist — so a run pinned only by --image-manifest must not report itself
// as unpinned.
func (p *verifyPlan) pinsLaunchMeasurement() bool {
	return len(p.policy.Policy.Measurements) > 0 || p.pins.image != nil || !p.refValues.Empty()
}

// requireTDXForRegisterPins runs before any register is compared: on non-TDX
// evidence an MRTD/RTMR pin cannot be enforced at all, and reporting a
// register mismatch would obscure that the policy was inapplicable.
func requireTDXForRegisterPins(platform string, pins rtmrPins) error {
	if pins.any() && !isTDX(platform) {
		return fmt.Errorf("an RTMR pin (--image-manifest / --expected-rtmr3 / --operator-pkey) is set but the evidence platform is %q: runtime measurement registers exist only on TDX, so this policy cannot be enforced against %q evidence", platform, platform)
	}
	return nil
}

// pinCoverage is what the run's pins prove beyond the launch digest.
type pinCoverage struct {
	// fullImage is set when the guest kernel and rootfs registers are pinned,
	// not only MRTD.
	fullImage bool
	// historyBound is set when RTMR[3] is checked against the measured policy
	// history the node reported: by the --operator-pkey pin, or under
	// --image-policy-file by an anchored image that replays it.
	historyBound bool
}

// enforceImagePolicy holds the evidence to --image-policy-file, when set, and
// records the measured policy history it replays.
func enforceImagePolicy(
	oc *Outcome,
	measured []string,
	result *teetypes.VerificationResult,
	plan *verifyPlan,
) (pinCoverage, error) {
	coverage := pinCoverage{fullImage: plan.pins.image != nil}
	if plan.refValues.Empty() {
		coverage.historyBound = plan.pins.anchor != nil
		return coverage, nil
	}
	platform := teetypes.NormalizePlatform(oc.Platform)
	if plan.refValues.Family != platform.Family() {
		return pinCoverage{}, fmt.Errorf("--image-policy-file is for %q but the evidence platform is %q", plan.refValues.Family, oc.Platform)
	}
	response := remote.VerifyResponse{Result: *result}
	if err := armtls.EnforceImages(response, plan.refValues.Images, platform, measured); err != nil {
		return pinCoverage{}, fmt.Errorf("--image-policy-file: %w", err)
	}
	oc.MeasuredPolicies, coverage.historyBound = replayedHistory(response, plan.refValues.Images, platform, measured)
	if matchesFullImageEntry(response, plan.refValues.Images, platform, measured) {
		coverage.fullImage = true
	}
	return coverage, nil
}

// matchesFullImageEntry reports whether an entry the evidence matches pins
// both the kernel and the rootfs registers. A weak alternative must not borrow
// the completeness of an unrelated entry in the same policy.
func matchesFullImageEntry(
	response remote.VerifyResponse,
	images []remote.ImagePin,
	platform teetypes.PlatformType,
	measured []string,
) bool {
	for _, entry := range images {
		if len(entry.Registers[1]) != 0 && len(entry.Registers[2]) != 0 &&
			armtls.EnforceImages(response, []remote.ImagePin{entry}, platform, measured) == nil {
			return true
		}
	}
	return false
}

// enforceLaunchMeasurement holds the launch digest to the --image-manifest
// MRTD and the --measurements allowlist.
func enforceLaunchMeasurement(result *teetypes.VerificationResult, plan *verifyPlan) error {
	launch := strings.ToLower(strings.TrimSpace(result.Claims.LaunchDigest))
	mb, err := hex.DecodeString(launch)
	if err != nil || len(mb) == 0 {
		return fmt.Errorf("cannot enforce the measurement policy: launch_digest is missing or malformed (%q)", result.Claims.LaunchDigest)
	}
	// The manifest's MRTD is compared exactly, not merged into the
	// allowlist: RTMR[1]/[2] are pinned against THIS manifest, so an MRTD
	// that merely appears somewhere in --measurements would let a launch
	// digest from a different build satisfy the tuple: one manifest, one
	// meaning.
	// buildPolicy now refuses a manifest and an allowlist in the same run,
	// so the two compares below cannot both fire on a CLI-built plan; the
	// exact compare stays exact anyway, because widening it is precisely
	// the bypass this rule exists to close.
	if plan.pins.image != nil {
		// A TDX identity has exactly one launch digest, its MRTD;
		// buildPolicy refuses any other family.
		mrtd := plan.pins.image.LaunchDigests()[0].Digest
		if !bytes.Equal(mb, mrtd[:]) {
			return fmt.Errorf("MRTD mismatch: launch measurement %s does not match the --image-manifest MRTD %s (a different guest firmware/image booted)",
				launch, hex.EncodeToString(mrtd[:]))
		}
	}
	if len(plan.policy.Policy.Measurements) > 0 && !remote.MeasurementAllowed(mb, plan.policy.Policy.Measurements) {
		return errors.New("launch measurement not in --measurements allowlist")
	}
	return nil
}

// enforceTDXImageCoverage handles a TDX pin that covers MRTD only. Whether that
// is rejected or warned about depends on whether an operator-pinned CA anchor
// (--mesh-ca) stands next to the measurements. Without one the verdict is
// deployment-class — the measurement pins are the entire trust anchor — and an
// incomplete image policy is a hard failure. A responder-committed CA
// (attest-pq's derived anchor) does not downgrade this: chosen by the
// responder, it anchors nothing the operator asked about — the same rule the JS
// verifier applies to a deployment-class verdict.
func enforceTDXImageCoverage(oc *Outcome, meshCA *x509.CertPool, fullImage bool) error {
	if !isTDX(oc.Platform) || fullImage {
		return nil
	}
	const mrtdOnly = "TDX measurement pin covers MRTD only — MRTD measures the TDVF firmware, so the guest kernel and rootfs are UNMEASURED by this policy; pass --image-manifest to pin the full image tuple"
	if meshCA == nil {
		return errors.New(mrtdOnly + " (with no pinned CA anchor this verdict is deployment-class — the measurement pins are the entire trust anchor — so an incomplete measurement policy is rejected; pin --mesh-ca to downgrade this to a warning)")
	}
	oc.Warnings = append(oc.Warnings, mrtdOnly)
	return nil
}

func warnUnreplayedHistory(oc *Outcome, measured []string, historyBound bool) {
	if len(measured) > 0 && !historyBound && isTDX(oc.Platform) {
		oc.Warnings = append(oc.Warnings, "the node reported a measured allowlist policy history that was not replayed: pass --operator-pkey, or an --image-policy-file whose matching image pins an approver_key, to check it against RTMR[3]")
	}
}

// checkMeasuredList bounds the evidence's measured list, which replaying costs
// one hash per entry, and requires each entry canonical, as the node extends
// nothing else.
func checkMeasuredList(measured []string) error {
	if len(measured) > armtls.MaxRuntimeExtensions {
		return fmt.Errorf("the evidence lists %d measured policies, at most %d allowed", len(measured), armtls.MaxRuntimeExtensions)
	}
	for i, d := range measured {
		if c, err := runtimemeasure.CanonicalDigest(d); err != nil || c != d {
			return fmt.Errorf("the evidence's measured policy %d (%q) is not a canonical sha256 digest", i, d)
		}
	}
	return nil
}

// anchored reports whether img pins a launch anchor.
func anchored(img remote.ImagePin) bool { return img.Anchor != nil }

// replayedHistory returns the prefix of measured that RTMR[3] proves on top of
// the seed of an anchored image the evidence matches on its own, and whether
// such an image bound RTMR[3]. Another image's anchor proves nothing about a
// guest that booted an unanchored one.
func replayedHistory(response remote.VerifyResponse, images []remote.ImagePin, platform teetypes.PlatformType, measured []string) ([]string, bool) {
	for _, img := range images {
		if !anchored(img) || armtls.EnforceImages(response, []remote.ImagePin{img}, platform, measured) != nil {
			continue
		}
		k, err := runtimemeasure.MatchBindingPrefix(&response.Result, img.Anchor, measured)
		if err != nil {
			continue
		}
		if k == 0 {
			return nil, true
		}
		return slices.Clone(measured[:k]), true
	}
	return nil, false
}

// enforceMinTCB settles the --min-tcb-* floor on the signature-verified
// claims. Two jobs, both of which the verification engine alone leaves open:
//
//   - the floor names SEV-SNP TCB components, and the TDX verification path
//     consumes none of them. Handed TDX evidence the engine silently drops the
//     floor, so the operator gets a green verdict for a policy that was never
//     applied. Like an RTMR pin against SNP, a flag that cannot apply to the
//     evidence at hand is a policy error, never an ignored option.
//   - on SNP the floor is re-checked here against the claims rather than
//     trusted to the engine, because an unenforced floor and a met floor
//     produce byte-identical output.
func enforceMinTCB(platform string, cfg config, result *teetypes.VerificationResult) error {
	floor := minTCBFromCfg(cfg)
	if floor == nil {
		return nil
	}
	if isTDX(platform) {
		return fmt.Errorf("a --min-tcb-* floor is set but the evidence platform is %q: the floor names SEV-SNP TCB components (bootloader/tee/snp/microcode), which TDX evidence does not carry and the TDX verification path does not consume, so this policy cannot be enforced against %q evidence", platform, platform)
	}
	for _, c := range []struct {
		flag string
		got  *uint8
		want uint8
	}{
		{"bootloader", result.Claims.TCB.Bootloader, floor.Bootloader},
		{"tee", result.Claims.TCB.Tee, floor.Tee},
		{"snp", result.Claims.TCB.Snp, floor.Snp},
		{"microcode", result.Claims.TCB.Microcode, floor.Microcode},
	} {
		if c.want == 0 {
			continue // component not floored (0 is "unset", per the flag default)
		}
		if c.got == nil {
			return fmt.Errorf("cannot enforce --min-tcb-%s: the verified claims carry no %s TCB component", c.flag, c.flag)
		}
		if *c.got < c.want {
			return fmt.Errorf("TCB component %s is %d, below the --min-tcb-%s floor of %d", c.flag, *c.got, c.flag, c.want)
		}
	}
	return nil
}

// isTDX reports whether a platform tag names TDX. The tag is chosen by the
// attester and travels as plain response JSON — it is in no transcript and no
// report — while attestation-go accepts "tdx", "az-tdx" and "gcp-tdx" and
// routes all three through one TDX verification path, the variants differing
// only in that unproven word. Comparing the raw string would let an attester
// pick "gcp-tdx" to slip past a TDX-only rule, or "tdx" to trip a TDX-only
// rejection, so every platform decision here normalizes first.
func isTDX(platform string) bool {
	return teetypes.NormalizePlatform(platform).IsTDX()
}

// enforceRTMRPins enforces the --image-manifest RTMR[1]/[2] and the RTMR[3] pin
// on the verified claims, recording what was enforced in RTMRsPinned. With an
// --operator-pkey seed, RTMR[3] may also be the seed extended by the longest
// prefix of measured that replays; that prefix becomes MeasuredPolicies.
// The pins come from the plan resolved once in buildPolicy, and newOutcome has
// already gated the platform. It fails on an absent or malformed claim, or a
// mismatch — never an ignored option.
func enforceRTMRPins(
	oc *Outcome,
	pins rtmrPins,
	measured []string,
	result *teetypes.VerificationResult,
) error {
	if !pins.any() {
		return nil
	}

	check := func(idx int, meaning string, want []byte) error {
		got, err := result.Claims.RTMR(idx)
		if err != nil {
			return fmt.Errorf("cannot enforce the RTMR[%d] pin: register claim absent or malformed: %v", idx, err)
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("RTMR[%d] (%s) is %x, expected %x", idx, meaning, got, want)
		}
		oc.RTMRsPinned = append(oc.RTMRsPinned, fmt.Sprintf("%d:%s", idx, hex.EncodeToString(want)))
		return nil
	}
	if pins.image != nil {
		regs := pins.image.RTMRs()
		// Ascending index, for the same reproducibility reason as the manual
		// pins below.
		for _, idx := range slices.Sorted(maps.Keys(regs)) {
			want := regs[idx]
			if err := check(idx, imageRTMRMeaning(idx), want[:]); err != nil {
				return err
			}
		}
	}
	if pins.rtmr3 != nil {
		want := pins.rtmr3
		replay := pins.anchor != nil && len(measured) > 0
		if replay {
			if err := checkMeasuredList(measured); err != nil {
				return err
			}
			if k, err := runtimemeasure.MatchBindingPrefix(result, pins.anchor, measured); err == nil && k > 0 {
				reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(pins.anchor), measured[:k])
				want, oc.MeasuredPolicies = reg[:], slices.Clone(measured[:k])
			}
		}
		if err := check(3, "runtime operator-key/workload chain", want); err != nil {
			if _, claimErr := result.Claims.RTMR(3); replay && claimErr == nil {
				return fmt.Errorf("%w; no prefix of the %d measured policies the evidence lists replays to it", err, len(measured))
			}
			return err
		}
	}
	// Ascending index, so a target missing several pinned registers always
	// names the same one first and a failing verdict is reproducible.
	for _, idx := range slices.Sorted(maps.Keys(pins.manual)) {
		if err := check(idx, rtmrMeaning(idx), pins.manual[idx]); err != nil {
			return err
		}
	}
	return nil
}

// imageRTMRMeaning labels the registers an image manifest pins. RTMR[2] reads
// differently here than in [rtmrMeaning]: the manifest measures the rootfs the
// command line names, so name the thing the pin identifies.
func imageRTMRMeaning(idx int) string {
	switch idx {
	case 1:
		return "guest kernel"
	case 2:
		return "guest rootfs"
	default:
		return rtmrMeaning(idx)
	}
}

// rtmrMeaning labels a register in operator-facing output. refvalues.ParseRegisterPins
// admits only 1, 2 and 3; the default keeps this total rather than printing an
// empty meaning if that ever widens.
func rtmrMeaning(idx int) string {
	switch idx {
	case 1:
		return "guest kernel"
	case 2:
		return "guest command line / dm-verity root hash"
	case 3:
		return "runtime operator-key/workload chain"
	default:
		return "runtime measurement register"
	}
}

// describeCertBody says what stands behind the leaf's body fields. Validity
// was already enforced when the evidence was gathered (authenticateLeafBody),
// so this reports the authentication class — and only claims validity was
// enforced where the bytes carrying it are authenticated. Checking NotAfter
// against a body nothing signed for bounds nothing: the attacker picked it.
func describeCertBody(_ config, ev *evidence) string {
	const skew = " (validity enforced, NotBefore skew ≤"
	switch {
	case ev.leafBody == certutil.BodySelfSigned:
		return "self-signed: body authenticated by the certificate's own attested key" + skew + certutil.LeafValiditySkew.String() + ")"
	case ev.leafChainVerified:
		return "CA-signed: body authenticated by a verified issuing chain (--mesh-ca)" + skew + certutil.LeafValiditySkew.String() + ")"
	case ev.leafChainDerived:
		return "CA-signed: body committed into the identity transcript — the hardware evidence binds these exact bytes" + skew + certutil.LeafValiditySkew.String() + ")"
	default:
		return "CA-signed: body fields are CA-vouched and UNAUTHENTICATED — pass --mesh-ca to check the chain"
	}
}

// minTCBFromCfg builds the verifier's min-TCB floor from the --min-tcb-* flags,
// or nil when none are set. buildPolicy already range-checked them (≤255).
func minTCBFromCfg(cfg config) *teetypes.SnpTcb {
	if cfg.minTCBBootloader == 0 && cfg.minTCBTEE == 0 && cfg.minTCBSNP == 0 && cfg.minTCBMicrocode == 0 {
		return nil
	}
	return &teetypes.SnpTcb{
		Bootloader: byte(cfg.minTCBBootloader),
		Tee:        byte(cfg.minTCBTEE),
		Snp:        byte(cfg.minTCBSNP),
		Microcode:  byte(cfg.minTCBMicrocode),
	}
}

// reportFlags reads the debug and SMT state the verifier extracted into the
// claims, for display. A flag the platform does not carry (SMT on TDX) renders
// as false; the verdict never depends on either.
func reportFlags(claims teetypes.Claims) (debug, smt bool) {
	debug, _ = claims.DebugEnabled()
	smt, _ = claims.SMTEnabled()
	return debug, smt
}

// formatTCB renders the verified TCB for display: SNP shows its components, TDX
// the raw SVN. Returns "" when the verifier reported no TCB.
func formatTCB(tcb teetypes.TcbInfo) string {
	deref := func(p *uint8) uint8 {
		if p == nil {
			return 0
		}
		return *p
	}
	switch tcb.Type {
	case "Snp":
		s := fmt.Sprintf("bootloader=%d tee=%d snp=%d microcode=%d",
			deref(tcb.Bootloader), deref(tcb.Tee), deref(tcb.Snp), deref(tcb.Microcode))
		if tcb.FMC != nil {
			s += fmt.Sprintf(" fmc=%d", *tcb.FMC)
		}
		return s
	case "Tdx":
		if len(tcb.TCBSvn) > 0 {
			return "svn=" + hex.EncodeToString(tcb.TCBSvn)
		}
	}
	return ""
}
