package verify

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// applyVerdictPolicies runs every post-verification policy in verdict order:
// the CA-vouched pins first (they authenticate the leaf's stamps and can fail
// the verdict), then the honesty demotions, which only ever turn a passing
// verdict partial. Ordering matters: applyChainAnchorPolicy reads the pinned
// chain check's outcome from oc.Verified.
func applyVerdictPolicies(oc *Outcome, cfg config, ev *evidence, held *heldAllowlist, opKeys operatorKeysReport, plan *verifyPlan, servedMeasurements measurementsReport) {
	applySandboxPolicy(oc, cfg, ev, opKeys, plan, servedMeasurements)
	applyWorkloadPolicy(oc, cfg, ev, held)
	applyClientDocumentPolicy(oc, cfg, ev)
	applyPinPolicy(oc, cfg, ev)
	applyUncheckedHistoryPolicy(oc, cfg)
	applyFrontDoorPolicy(oc, ev)
	applyChainAnchorPolicy(oc, cfg, ev)
	applyServedSetNote(oc, cfg, plan)
}

// applyServedSetNote says so when the /measurements cross-check did not run:
// a kind=cds verdict without --served-policy-file proves the target's own
// identity and nothing about the node identities it admits.
func applyServedSetNote(oc *Outcome, cfg config, plan *verifyPlan) {
	if cfg.kind == "cds" && plan.served == nil {
		oc.Warnings = append(oc.Warnings, "no --served-policy-file: the set this CDS reports enforcing at /measurements was not checked")
	}
}

// demoteToPartial turns a passing verdict into a partial one, naming the
// presented property that is not proven. It never rescues a failed verdict:
// a verification failure dominates and stays exit 2.
func demoteToPartial(oc *Outcome, notProven string) {
	if !oc.Verified {
		return
	}
	oc.Verified = false
	oc.Partial = true
	oc.NotProven = append(oc.NotProven, notProven)
}

// frontDoorAttestedNote states a verified discovery verdict's basis: the
// live handshake presented the attested serving certificate. It is appended
// only to a passing verdict, and applyFinalNotes strips it from one a later
// policy fails — on a refusal the gather-time fact must not read as the
// verdict's basis.
const frontDoorAttestedNote = "; the live handshake presented the attested serving certificate"

// frontDoorScopeWarning bounds an attested front door to the observation made.
const frontDoorScopeWarning = "the attested front door was observed on this verify's single connection to a single router replica at a single instant: serving certificates are per-replica, and a later or differently-routed client connection (TOCTOU, source-IP routing) can reach a different door — clients must verify their own connection (see internal/routerdiscovery)"

// applyFrontDoorPolicy settles what the verdict may claim about the front
// door's serving key, keying on the live handshake the discovery gather
// observed. A door presenting the attestation-bound certificate leaves the
// verdict standing, scoped to the one observation made; any other serving
// key, or no TLS observation at all, leaves the endpoint clients reach
// unproven. A lying door is named on every verdict shape — partial or failed —
// so a dominating verification failure never buries the signal.
func applyFrontDoorPolicy(oc *Outcome, ev *evidence) {
	switch ev.frontDoor {
	case frontDoorAttested:
		if oc.Verified {
			oc.Binding += frontDoorAttestedNote
			oc.Warnings = append(oc.Warnings, frontDoorScopeWarning)
		}
	case frontDoorOther:
		digests := fmt.Sprintf(
			"the front door's live TLS handshake presented serving certificate sha256 %s, not the sha256 %s this evidence attests",
			ev.frontDoorCertSHA256, ev.certSHA256)
		if !oc.Verified {
			oc.Error += "; " + digests + " — the TLS endpoint clients reach is not attestation-bound"
			return
		}
		demoteToPartial(oc, digests+" — the router pod's TEE residency and measurement are proven; the TLS endpoint clients reach is not attestation-bound")
	case frontDoorUnobserved:
		demoteToPartial(oc, "the front door's serving key: the target connection was not TLS, so no live handshake showed what the door serves, and the discovery document's declared public_tls.mode is a host-served claim nothing authenticates — the router pod's TEE residency and measurement are proven; the TLS endpoint clients reach is not")
	}
}

// applyChainAnchorPolicy settles what the verdict may claim about an
// endpoint-presented mesh chain (attest-pq / saved bundle). At gather time
// the chain was checked against the CA the responder committed into its own
// transcript — an anchor the responder chose. Only --mesh-ca turns that into
// a verified chain (applySandboxPolicy has already enforced the pinned check
// when it is set); a responder-chosen anchor leaves the endpoint's deployment
// identity unproven, so a passing verdict is partial.
func applyChainAnchorPolicy(oc *Outcome, cfg config, ev *evidence) {
	if !ev.leafChainDerived {
		return
	}
	if cfg.meshCA != "" {
		if oc.Verified {
			oc.ChainAnchor = "verified against the pinned --mesh-ca bundle"
		}
		return
	}
	demoteToPartial(oc, "the mesh chain anchor: the leaf chains to a CA the responder committed into its own attestation transcript — the evidence binds those CA bytes, but the anchor is responder-chosen, so which deployment this endpoint belongs to is not proven (pass --mesh-ca to pin it)")
}

// applyFinalNotes settles every note on the FINAL verdict, after every policy
// that can fail it (applyVerdictPolicies, checkPolicyHistory). A policy writes
// its note when its own check passes, and a later one can still fail the
// verdict, so on a hard failure (oc.Error set, the gate renderText applies)
// only the notes saying what was NOT checked survive: JSON and text then agree
// that a refusal asserts no passed check.
func applyFinalNotes(oc *Outcome, ev *evidence, result *teetypes.VerificationResult, plan *verifyPlan) {
	if oc.Error != "" {
		// A value never appears without the note qualifying it.
		// buildPolicy refuses --sandbox-id without --mesh-ca, so the CLI never
		// appends the pin clause to the unverified note; trim it regardless.
		if strings.HasPrefix(oc.SandboxIDNote, sandboxIDUnverifiedNote) {
			oc.SandboxIDNote = sandboxIDUnverifiedNote
		} else {
			oc.SandboxID, oc.SandboxIDNote = "", ""
		}
		if oc.WorkloadNote != workloadUnverifiedNote {
			oc.Workload, oc.WorkloadAllowlistVersion, oc.WorkloadAllowlistDigest, oc.WorkloadNote = "", "", "", ""
		}
		if oc.OperatorKeysNote == "" || oc.OperatorKeysNote == operatorKeysMatchedNote {
			oc.OperatorKeys, oc.OperatorKeysNote = nil, ""
		}
		oc.ChainAnchor = ""
		// A replayed history is a passed check too; cert_body stays, as a
		// description of how the leaf's body was authenticated.
		oc.MeasuredPolicies = nil
		oc.Binding = strings.TrimSuffix(oc.Binding, frontDoorAttestedNote)
		oc.Warnings = slices.DeleteFunc(oc.Warnings, func(w string) bool { return w == frontDoorScopeWarning })
		return
	}
	if ev.route != nil {
		oc.RouteDigest = hex.EncodeToString(ev.route.digest)
		oc.RouteRevision = ev.route.revision
		oc.RouteNote = ev.route.note
	}
	applyInitDataNote(oc, result, plan)
}

// applyInitDataNote records what the init-data digest was compared against.
// On az-* the pin binds vTPM PCR[8], not result.Claims.InitData (the inner
// report's HOST_DATA), so a pinned az verdict reports the enforced pin without
// presenting that field.
func applyInitDataNote(oc *Outcome, result *teetypes.VerificationResult, plan *verifyPlan) {
	switch {
	case oc.Platform == string(teetypes.PlatformAzSNP) || oc.Platform == string(teetypes.PlatformAzTDX):
		if plan.initDataHash != nil {
			oc.InitDataNote = "verified: pinned via vTPM PCR[8] (matches --init-data)"
		}
	case len(result.Claims.InitData) > 0:
		oc.InitData = hex.EncodeToString(result.Claims.InitData)
		oc.InitDataNote = initDataNote(oc.Platform, plan)
	}
}

// initDataNote says what stands behind the init-data digest the evidence
// commits: the --init-data pin, the launch file an image policy binds, or
// nothing at all.
func initDataNote(platform string, plan *verifyPlan) string {
	switch {
	case plan.initDataHash != nil:
		return "verified: matches --init-data"
	case launchBindingPinned(platform, plan.refValues.Images):
		return "verified: matches the launch file --image-policy-file pins (HOST_DATA)"
	}
	return "not pinned: the digest the evidence commits, compared against nothing (pass --init-data to pin it)"
}

// launchBindingPinned reports whether a launch-file pin enforced the init-data
// field this verdict reports. On SEV-SNP that field is HOST_DATA, which such a
// pin compares whole; TDX reports MR_CONFIG_ID there and carries its launch
// binding in RTMR[3]. Every image must bind the file: the evidence matched one
// of them, and another entry's binding says nothing about the one that did.
func launchBindingPinned(platform string, images []remote.ImagePin) bool {
	if isTDX(platform) || len(images) == 0 {
		return false
	}
	for _, img := range images {
		if len(img.LaunchFile) == 0 {
			return false
		}
	}
	return true
}

// The notes applyFinalNotes recognises: the unverified ones survive a failed
// verdict, the matched one does not.
const (
	sandboxIDUnverifiedNote = "not verified: CDS's signature on the leaf vouches for this ID; pass --mesh-ca to check it"
	workloadUnverifiedNote  = "not verified: CDS's signature on the leaf vouches for this name; pass --mesh-ca to check it"
	operatorKeysMatchedNote = "matched: the set served over the attested cert equals --operator-keys"
)

// applySandboxPolicy surfaces the leaf's sandbox ID and enforces --sandbox-id /
// --operator-keys. It only ever demotes Verified — nothing here can rescue a
// failed hardware verification (docs/armtls.md).
func applySandboxPolicy(oc *Outcome, cfg config, ev *evidence, opKeys operatorKeysReport, plan *verifyPlan, servedMeasurements measurementsReport) {
	fail := func(format string, args ...any) {
		oc.Verified = false
		if oc.Error == "" {
			oc.Error = fmt.Sprintf(format, args...)
		}
	}
	if ev.sandboxErr != nil {
		fail("sandbox-ID extension unparseable (newer target than this CLI?): %v", ev.sandboxErr)
		return
	}

	// The chain check runs before the ID is reported, so the note can never
	// claim "verified" for a check that then failed.
	if plan.meshCA != nil {
		if ev.leaf == nil {
			fail("--mesh-ca needs the target's leaf certificate (this evidence source carries none — use a cert, discovery, or attest-pq target)")
			return
		}
		if _, err := ev.leaf.Verify(x509.VerifyOptions{
			Roots:     plan.meshCA,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			fail("leaf does not chain to the --mesh-ca bundle: %v", err)
			return
		}
	}

	// Report the ID only once the hardware evidence verified, and always say
	// what stands behind it: an unqualified "sandbox: X" would read as
	// attested, which it is not.
	if oc.Verified && ev.sandboxID != "" {
		oc.SandboxID = ev.sandboxID
		if plan.meshCA == nil {
			oc.SandboxIDNote = sandboxIDUnverifiedNote
		} else {
			oc.SandboxIDNote = "verified: the leaf chains to the supplied mesh CA"
		}
	}
	if cfg.sandboxID != "" {
		if ev.leaf == nil {
			fail("--sandbox-id needs the target's leaf certificate (this evidence source carries none — use a cert, discovery, or attest-pq target)")
			return
		}
		// One implementation of the pin, shared with the mesh's CA path — and
		// reached only after the chain check above, which is what authenticates
		// the ID.
		if err := armtls.CheckSandboxPin(ev.leaf, cfg.sandboxID); err != nil {
			fail("%v", err)
		} else if oc.SandboxIDNote != "" {
			oc.SandboxIDNote += ", and the ID matches --sandbox-id"
		}
	}

	checkServedPolicy(plan, servedMeasurements, fail)
	checkServedOperatorKeys(oc, plan.operatorKeysDigest, opKeys, fail)
}

// checkServedOperatorKeys compares the key set a kind=cds target serves at
// /operator-keys with the --operator-keys digest the plan resolved.
func checkServedOperatorKeys(oc *Outcome, expected []byte, opKeys operatorKeysReport, fail func(string, ...any)) {
	if len(expected) == 0 {
		if oc.Verified && len(opKeys.fingerprints) > 0 {
			oc.OperatorKeysNote = "not pinned: the set the target reports, compared against nothing (pass --operator-keys to pin it)"
		}
		return
	}
	// The served key list is authenticated by being fetched over the attested
	// serving cert. A failed fetch fails closed when the operator asked for the
	// check (a 404 is not an error — it maps to the empty-set digest in
	// fetchOperatorKeyFingerprints).
	if opKeys.fetchErr != nil {
		fail("could not fetch /operator-keys to check it against --operator-keys: %v", opKeys.fetchErr)
		return
	}
	if opKeys.digest == nil {
		// Never fetched (wrong --kind, or a --from-file target). Say that,
		// rather than comparing against an empty digest and reporting a
		// mismatch the operator cannot act on.
		fail("--operator-keys cannot be checked: %s", orDefault(opKeys.note, "the target was never queried for its key set"))
		return
	}
	if !bytes.Equal(opKeys.digest, expected) {
		fail("served /operator-keys digest %x does not match the --operator-keys set (%x)", opKeys.digest, expected)
		return
	}
	if oc.Verified {
		oc.OperatorKeysNote = operatorKeysMatchedNote
	}
}

// checkServedPolicy compares the set the target reports enforcing against
// the operator's own file. A swapped config leaves the launch measurement
// untouched, so this is what makes the substitution visible.
func checkServedPolicy(plan *verifyPlan, report measurementsReport, fail func(string, ...any)) {
	if plan.served == nil {
		return
	}
	checkServedMeasurements(*plan.served, report, fail)
}

// applyClientDocumentPolicy surfaces a Pod CVM leaf's client document digest
// and enforces --client-document. The mesh-CA chain check (applySandboxPolicy,
// which runs first) authenticates the digest; the pin only ever demotes
// Verified.
func applyClientDocumentPolicy(oc *Outcome, cfg config, ev *evidence) {
	fail := func(format string, args ...any) {
		oc.Verified = false
		if oc.Error == "" {
			oc.Error = fmt.Sprintf(format, args...)
		}
	}
	var digest []byte
	if ev.leaf != nil {
		digest, _ = armtls.ClientDocumentDigest(ev.leaf)
	}
	if oc.Verified && digest != nil {
		oc.ClientDocumentDigest = hex.EncodeToString(digest)
		oc.AgentLabel = armtls.AgentLabel(digest)
		if cfg.meshCA == "" {
			oc.ClientDocumentNote = "not verified: CDS's signature on the leaf vouches for this digest; pass --mesh-ca to check it"
		} else {
			oc.ClientDocumentNote = "ca-vouched: the leaf chains to the supplied mesh CA"
		}
	}
	if cfg.clientDocument == "" {
		return
	}
	document, err := os.ReadFile(cfg.clientDocument)
	if err != nil {
		fail("--client-document: %v", err)
		return
	}
	if digest == nil {
		fail("client_document_absent: --client-document is pinned but the leaf carries no well-formed client document digest")
		return
	}
	want := sha256.Sum256(document)
	if !bytes.Equal(digest, want[:]) {
		fail("client_document_mismatch: the leaf names client document sha256:%x, --client-document hashes to sha256:%x", digest, want)
		return
	}
	if oc.Verified {
		oc.ClientDocumentNote += ", and the digest matches --client-document"
	}
}

// applyWorkloadPolicy surfaces the leaf's matched-workload stamp and enforces
// --workload / --allowlist, mirroring applySandboxPolicy's ordering: an
// unparseable stamp fails closed; the mesh-CA chain check (applySandboxPolicy,
// which always runs first) authenticates the stamp before anything from it is
// reported or compared; the pins only ever demote Verified.
func applyWorkloadPolicy(oc *Outcome, cfg config, ev *evidence, held *heldAllowlist) {
	fail := func(format string, args ...any) {
		oc.Verified = false
		if oc.Error == "" {
			oc.Error = fmt.Sprintf(format, args...)
		}
	}
	if ev.workloadErr != nil {
		fail("workload_malformed: matched-workload extension unparseable or duplicated (newer target than this CLI?): %v", ev.workloadErr)
		return
	}

	// Report the stamp only once the hardware evidence (and, with --mesh-ca,
	// the chain) verified, and always say what stands behind it.
	if oc.Verified && ev.workload != nil {
		oc.Workload = ev.workload.Name
		oc.WorkloadAllowlistVersion = ev.workload.AllowlistVersion
		oc.WorkloadAllowlistDigest = hex.EncodeToString(ev.workload.AllowlistDigest)
		if cfg.meshCA == "" {
			oc.WorkloadNote = workloadUnverifiedNote
		} else {
			oc.WorkloadNote = "ca-vouched: the leaf chains to the supplied mesh CA"
		}
	}

	if cfg.workload == "" && held == nil {
		return
	}
	if ev.leaf == nil {
		fail("--workload/--allowlist need the target's leaf certificate (this evidence source carries none — use a cert, discovery, or attest-pq target)")
		return
	}
	if ev.workload == nil {
		fail("workload_absent: a workload policy is pinned but the leaf carries no matched-workload extension")
		return
	}
	if cfg.workload != "" && ev.workload.Name != cfg.workload {
		fail("workload_name_mismatch: leaf matched workload %q does not match pinned %q", ev.workload.Name, cfg.workload)
		return
	}
	if held != nil {
		digest := sha256.Sum256(held.raw)
		if !bytes.Equal(digest[:], ev.workload.AllowlistDigest) {
			fail("allowlist_digest_mismatch: stamped policy digest %x does not match SHA-256 %x of the held --allowlist bytes", ev.workload.AllowlistDigest, digest[:])
			return
		}
		if _, ok := held.doc.Workloads[ev.workload.Name]; !ok {
			fail("workload_unresolved: stamped name %q does not resolve in the held allowlist document", ev.workload.Name)
			return
		}
	}
	if oc.Verified {
		oc.WorkloadNote = "workload_verified: the leaf chains to the supplied mesh CA and the stamp satisfies the pinned policy"
	}
}
