package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// Exit codes. These are a stable contract for CI: a wrong measurement (2) is
// distinguishable from an unreachable endpoint (3), and a partial verdict (4)
// — evidence verified, but a property the evidence presents is not proven —
// from both a full pass and a failure.
const (
	exitVerified   = 0
	exitUsage      = 1
	exitFailed     = 2 // evidence obtained, but verification/policy failed
	exitNoEvidence = 3 // could not obtain evidence (connect/parse/file)
	exitPartial    = 4 // evidence verified, but a presented property is not proven
)

// verdictExitCode maps a rendered verdict to the process exit code.
func verdictExitCode(oc Outcome) int {
	switch {
	case oc.Verified:
		return exitVerified
	case oc.Partial:
		return exitPartial
	default:
		return exitFailed
	}
}

// connectError marks a failure to obtain evidence or verification collateral
// (vs. a verification verdict), so the orchestration can map it to exit code 3.
type connectError struct{ err error }

func (e *connectError) Error() string { return e.err.Error() }
func (e *connectError) Unwrap() error { return e.err }

func isConnectError(err error) bool {
	var ce *connectError
	return errors.As(err, &ce)
}

// securityError marks a response that was reachable and well-formed but failed a
// security check (e.g. the attestation endpoint did not echo our nonce). Unlike
// a connectError it must NOT be swallowed by auto-mode's fall-through to the
// serving cert — a wrong nonce can signal replay or an active MITM.
type securityError struct{ err error }

func (e *securityError) Error() string { return e.err.Error() }
func (e *securityError) Unwrap() error { return e.err }

func isSecurityError(err error) bool {
	var se *securityError
	return errors.As(err, &se)
}

// Defaults preset a command's target shape so `c8s cds verify` is a thin
// shorthand for `c8s verify` with CDS conventions, sharing one implementation.
type Defaults struct {
	// Use is the command's name ("verify").
	Use string
	// Short is the one-line help.
	Short string
	// Kind preselects the component (cds|lb|workload|auto).
	Kind string
	// Mode preselects the evidence mode (auto|ratls-cert|discovery|attest-pq).
	Mode string
	// DefaultPort is the port assumed when the target omits one (0 = by kind).
	DefaultPort int
}

type config struct {
	url           string
	kind          string
	mode          string
	server        string
	timeout       time.Duration
	fromFile      string
	discoveryPath string

	measurements       []string
	measurementsFile   string
	imageManifest      string
	expectedRTMR3Hex   string
	operatorPubkey     string
	rtmrs              []string
	operatorKeys       string
	measurementsConfig string
	sandboxID          string
	workload           string
	allowlistFile      string
	pinPolicies        []string
	fetchAllowlists    string
	meshCA             string
	initDataHex        string
	allowDebug         bool
	minTCBBootloader   uint
	minTCBTEE          uint
	minTCBSNP          uint
	minTCBMicrocode    uint
	expectedRDHex      string

	output       string
	showEvidence bool

	defaults Defaults
}

// NewCmd builds the verify command. The same constructor backs both the generic
// `c8s verify` and the `c8s cds verify` shorthand; d only changes defaults.
func NewCmd(d Defaults) *cobra.Command {
	cfg := config{defaults: d}
	use := d.Use
	if use == "" {
		use = "verify [target]"
	}
	short := d.Short
	if short == "" {
		short = "Verify a c8s component's TEE attestation"
	}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long: short + `.

Fetches a component's TEE attestation evidence (AMD SEV-SNP or Intel TDX) and
verifies it against the hardware signature chain plus a measurement / TCB /
policy, then reports the verdict.

Verification runs in-process using attestation-go — the Go port of the
attestation-rs engine the cluster runs. It auto-detects the platform and AMD
product — including Zen4c (Siena/Bergamo), which stock go-sev-guest cannot — so
the product line never has to be supplied by hand, and it fetches the VCEK for a
bare report from AMD KDS (bounded by --timeout), so the machine running it needs
outbound HTTPS to kdsintf.amd.com (no container runtime required).

Evidence sources:
  https://host:port      GET the discovery endpoint (/v1/discovery — cert +
                         evidence with the VCEK inline), or, in --mode ratls-cert,
                         dial the RA-TLS serving cert (bare report; the VCEK is
                         fetched from AMD KDS). Default mode: cds → ratls-cert,
                         lb → discovery, auto → discovery then serving cert.
  --from-file FILE       verify a saved PEM cert or attestation-response JSON.

  c8s cds verify https://cds.example.com:8443 --measurements <sha384-hex>
  c8s verify https://lb.example.com:443 --kind lb --measurements <sha384-hex>

Exit codes: 0 verified · 1 usage · 2 verification/policy failed · 3 evidence
unavailable (unreachable / unparseable) · 4 partially verified (the evidence
verified, but a property it presents is not proven — the front door's live
handshake presented a serving key the evidence does not attest, no handshake
could be observed (a non-TLS discovery target), or a chain anchor the
responder chose).`,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				cfg.url = args[0]
			}
			os.Exit(run(cmd.Context(), cfg, cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&cfg.url, "url", "", "target URL or host:port (alternative to the positional argument)")
	f.StringVar(&cfg.kind, "kind", orDefault(d.Kind, "auto"), "component being verified: cds, lb, workload, or auto")
	f.StringVar(&cfg.mode, "mode", orDefault(d.Mode, "auto"), "evidence mode: auto, ratls-cert, discovery, attest-pq, or attest-lb")
	f.StringVar(&cfg.discoveryPath, "discovery-path", defaultDiscoveryPath, "path of the LB discovery document (discovery mode)")
	f.StringVar(&cfg.server, "server-name", "", "TLS SNI server name (for port-forward / routed domains)")
	f.DurationVar(&cfg.timeout, "timeout", 15*time.Second, "per-attempt timeout (evidence fetch and AMD KDS collateral fetch)")
	f.StringVar(&cfg.fromFile, "from-file", "", "verify evidence from a saved PEM certificate or attestation-response JSON instead of dialing")

	f.StringSliceVar(&cfg.measurements, "measurements", nil, "allowed SHA-384 hex launch measurement(s) (repeatable / comma-separated); empty = no pinning (UNSAFE). On TDX this pins MRTD only, which covers just the TDVF firmware — use --image-manifest to pin the whole guest image instead (the two are mutually exclusive: the manifest already pins MRTD exactly)")
	f.StringVar(&cfg.measurementsFile, "measurements-file", "", "text file of allowed launch measurements, one hex digest per line; use --image-policy-file for complete JSON policies; excludes --image-manifest")
	f.StringVar(&cfg.imageManifest, "image-manifest", "", "build-artifact manifest of the expected TDX guest image (JSON object with mrtd, rtmr1, rtmr2, each 96 lowercase hex chars, published with the image build); all three registers are pinned exactly against this one manifest, so the guest kernel and rootfs are verified rather than only the firmware. Since it pins MRTD exactly it replaces --measurements/--measurements-file rather than combining with them. TDX evidence only — with SNP evidence this is a policy error")
	f.StringVar(&cfg.expectedRTMR3Hex, "expected-rtmr3", "", "DEPRECATED, prefer --rtmr 3=<sha384-hex>: identical pin under identical rules, one flag for every register. Retained so existing invocations keep working")
	f.StringVar(&cfg.operatorPubkey, "operator-pkey", "", "path to the operator PUBLIC key PEM (the verbatim file bytes the guest initrd hashed, as written by `openssl ec -pubout`) — derives and pins RTMR[3] as the bare operator-key seed, SHA-384(0x00*48 ‖ SHA-384(pubkey)), so the register need not be computed by hand. Mutually exclusive with --expected-rtmr3, and like it a deployment property, NOT a cluster identity, so it requires --image-manifest. The bare seed is the value a node with no per-workload RTMR[3] extends reports, which today is every node. TDX evidence only — with SNP evidence this is a policy error")
	f.StringSliceVar(&cfg.rtmrs, "rtmr", nil, "expected TDX runtime measurement register(s) as <index>=<sha384-hex> (repeatable). RTMR[1] pins the guest kernel and RTMR[2] the kernel command line carrying the dm-verity root hash: these ARE the image, so pinning them by hand cannot be combined with --image-manifest, which pins the same two plus the MRTD from one provenanced build. RTMR[3] is the operator-key/workload chain extended inside whatever image the host booted, so --rtmr 3= REQUIRES --image-manifest — alone it would read as proof of identity while proving none. RTMR[0] is not pinnable. TDX evidence only — with SNP evidence any pin here is a policy error")
	cmdsutil.BindImagePolicyFlags(f, &cfg.measurementsConfig, nil, "", "pins complete target identities; for kind=cds also checks the served /measurements policy; excludes --measurements, --measurements-file and --image-manifest")
	f.StringVar(&cfg.operatorKeys, "operator-keys", "", "PEM bundle of expected operator public keys; verification fails unless the key set the attested target serves at /operator-keys matches it (kind=cds targets)")
	f.StringVar(&cfg.sandboxID, "sandbox-id", "", "expected CRI pod sandbox ID on the target's leaf; requires --mesh-ca, since CDS's signature on the leaf is what vouches for the ID (docs/ratls.md)")
	f.StringVar(&cfg.workload, "workload", "", "expected matched-workload name on the target's leaf; requires --mesh-ca, since CDS's signature on the leaf is what vouches for the stamp (docs/ratls.md)")
	f.StringVar(&cfg.allowlistFile, "allowlist", "", "file holding the exact canonical allowlist bytes (as served by GET /allowlist); the leaf's stamped policy digest must equal SHA-256 of these bytes and the stamped name must resolve in the document. Requires --mesh-ca")
	f.StringSliceVar(&cfg.pinPolicies, "pin-policy", nil, "accepted allowlist policy digest(s) sha256:<hex> (repeatable / comma-separated). attest-pq and attest-lb only: the bundle's CDS rollout state must verify against the committed mesh CA, answer this request's nonce, carry a positive activation lease, and bound every policy that may run to these digests")
	f.StringVar(&cfg.fetchAllowlists, "fetch-allowlists", "", "directory to write every policy in the attested rollout bound to, fetched from the target and checked against its attested digest (attest-pq and attest-lb)")
	f.StringVar(&cfg.meshCA, "mesh-ca", "", "PEM bundle of the CDS mesh CA; when set, the target's leaf must chain to it, which is what authenticates the reported sandbox ID. On attest-pq and attest-lb it is also what upgrades the chain anchor from responder-chosen (partial verdict) to verified")
	f.StringVar(&cfg.initDataHex, "init-data", "", "expected init-data digest: SHA-256 hex of the init-data document the target guest must carry. Verification fails unless the evidence commits exactly this digest")
	f.BoolVar(&cfg.allowDebug, "allow-debug", false, "accept debug-enabled guests")
	const tcbSNPOnly = " (SEV-SNP evidence only — TDX carries no such component, so against TDX evidence this is a policy error rather than an ignored flag)"
	f.UintVar(&cfg.minTCBBootloader, "min-tcb-bootloader", 0, "minimum bootloader TCB component"+tcbSNPOnly)
	f.UintVar(&cfg.minTCBTEE, "min-tcb-tee", 0, "minimum TEE TCB component"+tcbSNPOnly)
	f.UintVar(&cfg.minTCBSNP, "min-tcb-snp", 0, "minimum SNP firmware TCB component"+tcbSNPOnly)
	f.UintVar(&cfg.minTCBMicrocode, "min-tcb-microcode", 0, "minimum microcode TCB component"+tcbSNPOnly)
	f.StringVar(&cfg.expectedRDHex, "expected-report-data", "", "hex REPORTDATA / TPM-nonce anchor override for bare evidence files (1–64 bytes, exactly as bound by the producer)")

	f.StringVarP(&cfg.output, "output", "o", "text", "output format: text or json")
	f.BoolVar(&cfg.showEvidence, "show-evidence", false, "print the raw report fields")

	return cmd
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// run performs the whole verification and renders the result, returning the
// process exit code. It is the unit-testable core (no os.Exit inside).
func run(ctx context.Context, cfg config, out, errOut io.Writer) int {
	// No mode alias: the retired "attestation-endpoint" name (and anything
	// else unknown) is a usage error, not a silent fall-through to auto.
	switch cfg.mode {
	case "", "auto", "ratls-cert", "discovery", "attest-pq", "attest-lb":
	default:
		fmt.Fprintf(errOut, "error: unknown --mode %q (valid modes: auto, ratls-cert, discovery, attest-pq, attest-lb)\n", cfg.mode)
		return exitUsage
	}

	plan, err := buildPolicy(cfg)
	if err != nil {
		fmt.Fprintf(errOut, "error: %v\n", err)
		return exitUsage
	}
	held, err := loadHeldAllowlist(cfg.allowlistFile)
	if err != nil {
		fmt.Fprintf(errOut, "error: %v\n", err)
		return exitUsage
	}

	if cfg.url == "" && cfg.fromFile == "" {
		fmt.Fprintf(errOut, "error: no target: pass a component's discovery URL / host:port (or --from-file)\n")
		return exitUsage
	}

	// Verify in-process with attestation-go — the Go port of the engine the
	// cluster runs. It auto-detects the platform and AMD product (incl. Siena)
	// and fetches the VCEK from AMD KDS itself, so a bare RA-TLS report, a
	// discovery doc, and an endpoint response all verify through one path.
	var overrideERD []byte
	if cfg.expectedRDHex != "" {
		erd, perr := parseExpectedReportData(cfg.expectedRDHex)
		if perr != nil {
			fmt.Fprintf(errOut, "error: %v\n", perr)
			return exitUsage
		}
		overrideERD = erd
	}
	ev, err := gatherEvidence(ctx, cfg, plan, overrideERD)
	if err != nil {
		// A securityError means the target was reachable and its response
		// well-formed, but a check on it failed (a nonce that does not echo,
		// a re-signed certificate body, a substituted CA). That is a verdict,
		// not an unavailability: exit 3 is the code a CI gate retries on, and
		// retrying against an actively tampered target is exactly the wrong
		// move. Render it as a failed verdict so it reads like one too.
		if isSecurityError(err) {
			render(cfg, Outcome{
				Backend:    "attestation-go",
				VerifiedAt: time.Now().UTC(),
				Source:     targetDescription(cfg),
				Error:      err.Error(),
			}, out)
			return exitFailed
		}
		fmt.Fprintf(errOut, "error: could not obtain evidence: %v\n", err)
		return exitNoEvidence
	}
	return verifyEvidence(ctx, cfg, plan, ev, held, gatherOperatorKeys(ctx, cfg, ev), gatherMeasurements(ctx, cfg, ev), out, errOut)
}

// targetDescription names the evidence source for a verdict produced before
// any evidence struct exists (a gather-time security failure).
func targetDescription(cfg config) string {
	if cfg.fromFile != "" {
		return "file " + cfg.fromFile
	}
	return cfg.url
}

// operatorKeysReport is the pinned-operator-key section of the verdict. Keys
// authorize allowlist writes on CDS. The list is CDS-reported config, fetched
// over the attested serving cert; --operator-keys turns it into a check.
type operatorKeysReport struct {
	fingerprints []string
	digest       []byte // KeySetDigest of the served list (nil when not fetched)
	note         string // non-empty when keys are absent/unavailable, explains why
	fetchErr     error  // non-nil when the fetch was attempted and failed
}

// gatherOperatorKeys fetches the CDS-pinned operator key fingerprints for
// kind=cds network targets. For any other kind (including the default auto)
// the fetch is skipped, and the skip is announced via a note so the rendered
// verdict never silently omits it. The fetch is bound to the attested serving
// cert (see fetchOperatorKeyFingerprints). A failed fetch degrades to a note,
// but records fetchErr so applySandboxPolicy can fail the verdict when
// --operator-keys asked for a check: an endpoint erroring on /operator-keys
// must not dodge it.
func gatherOperatorKeys(ctx context.Context, cfg config, ev *evidence) operatorKeysReport {
	if cfg.kind != "cds" {
		return operatorKeysReport{note: "operator-keys cross-check skipped: target kind is not cds (use --kind cds to enable)"}
	}
	if cfg.url == "" {
		return operatorKeysReport{}
	}
	if ev.certSHA256 == "" {
		return operatorKeysReport{note: "not fetched (no serving cert to bind to)"}
	}
	_, baseURL, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		return operatorKeysReport{note: "not fetched: " + err.Error()}
	}
	fps, digest, note, err := fetchOperatorKeyFingerprints(ctx, baseURL, cfg.server, ev.certSHA256, cfg.timeout)
	if err != nil {
		return operatorKeysReport{note: "not fetched: " + err.Error(), fetchErr: err}
	}
	return operatorKeysReport{fingerprints: fps, digest: digest, note: note}
}

// verifyEvidence verifies already-gathered evidence (from any source/mode)
// in-process with attestation-go (the Go port of the attestation-rs engine the
// cluster runs), which auto-detects the product and fetches the VCEK from KDS
// when it is not shipped inline — so a bare RA-TLS report and a discovery doc
// both work — then renders the verdict. The verification attempt (including the
// KDS fetch) is bounded by --timeout; an unobtainable-collateral failure is
// exit 3, not a verification verdict.
func verifyEvidence(ctx context.Context, cfg config, plan *verifyPlan, ev *evidence, held *heldAllowlist, opKeys operatorKeysReport, servedMeasurements measurementsReport, out, errOut io.Writer) int {
	if cfg.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.timeout)
		defer cancel()
	}
	result, verr := verifyInProcess(ctx, ev, plan.policy, plan.initDataHash, minTCBFromCfg(cfg))
	if isConnectError(verr) {
		fmt.Fprintf(errOut, "error: could not fetch verification collateral: %v\n", verr)
		return exitNoEvidence
	}
	oc := newOutcome(cfg, ev, result, verr, plan)
	oc.OperatorKeys = opKeys.fingerprints
	oc.OperatorKeysNote = opKeys.note
	applyVerdictPolicies(&oc, cfg, ev, held, opKeys, plan, servedMeasurements)
	applyInitDataNote(&oc, result, plan)
	fetchAllowlists(ctx, cfg, &oc)
	render(cfg, oc, out)
	return verdictExitCode(oc)
}

// applyVerdictPolicies runs every post-verification policy in verdict order:
// the CA-vouched pins first (they authenticate the leaf's stamps and can fail
// the verdict), then the honesty demotions, which only ever turn a passing
// verdict partial. Ordering matters: applyChainAnchorPolicy reads the pinned
// chain check's outcome from oc.Verified.
func applyVerdictPolicies(oc *Outcome, cfg config, ev *evidence, held *heldAllowlist, opKeys operatorKeysReport, plan *verifyPlan, servedMeasurements measurementsReport) {
	applySandboxPolicy(oc, cfg, ev, opKeys, plan, servedMeasurements)
	applyWorkloadPolicy(oc, cfg, ev, held)
	applyPinPolicy(oc, cfg, ev)
	applyFrontDoorPolicy(oc, ev)
	applyChainAnchorPolicy(oc, cfg, ev)
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
// only to a passing verdict — on a refusal the gather-time fact must not
// read as the verdict's basis.
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

// applyInitDataNote records what --init-data bound to, on the FINAL verdict:
// it runs after applyVerdictPolicies (which can fail the verdict past
// newOutcome) and skips a hard failure (oc.Error set) — the gate renderText
// also applies. On az-* the pin binds vTPM PCR[8], not result.Claims.InitData
// (the inner report's HOST_DATA), so a pinned az verdict reports the enforced
// pin without presenting that field.
func applyInitDataNote(oc *Outcome, result *teetypes.VerificationResult, plan *verifyPlan) {
	if oc.Error != "" {
		return
	}
	switch {
	case oc.Platform == string(teetypes.PlatformAzSNP) || oc.Platform == string(teetypes.PlatformAzTDX):
		if plan.initDataHash != nil {
			oc.InitDataNote = "verified: pinned via vTPM PCR[8] (matches --init-data)"
		}
	case len(result.Claims.InitData) > 0:
		oc.InitData = hex.EncodeToString(result.Claims.InitData)
		if plan.initDataHash != nil {
			oc.InitDataNote = "verified: matches --init-data"
		} else {
			oc.InitDataNote = "not pinned: the digest the evidence commits, compared against nothing (pass --init-data to pin it)"
		}
	}
}

// verifyPlan is one run's parsed, validated policy: the verifier policy, the
// TDX register pins, and the --mesh-ca anchor. Everything file-backed is read
// exactly ONCE, here, and threaded downstream — a pin resolved twice can be
// split by swapping the file between reads, which for --image-manifest would
// mean an MRTD from one build and RTMR[1]/[2] from another, defeating the
// whole point of loading the tuple atomically.
type verifyPlan struct {
	policy *ratls.VerifyPolicy
	pins   rtmrPins
	// meshCA is the parsed --mesh-ca bundle, nil when the flag is unset.
	meshCA *x509.CertPool
	// initDataHash is the parsed --init-data pin, nil when the flag is unset.
	initDataHash []byte
	// refValues is the parsed --image-policy-file, empty when unset. It
	// both pins the target and is compared against what the target serves.
	refValues refvalues.ReferenceValues
}

// buildPolicy parses the measurement allowlist, resolves the register pins and
// the mesh CA anchor, and validates TCB bounds. The launch-measurement pin and
// min-TCB are enforced on the verifier verdict (newOutcome / verifyInProcess);
// only Measurements and AllowDebug are read by the verifier itself.
func buildPolicy(cfg config) (*verifyPlan, error) {
	// Each TCB component is a single byte; reject >255 rather than silently
	// truncating it (byte(256)==0 would weaken the policy without warning).
	for name, v := range map[string]uint{
		"--min-tcb-bootloader": cfg.minTCBBootloader,
		"--min-tcb-tee":        cfg.minTCBTEE,
		"--min-tcb-snp":        cfg.minTCBSNP,
		"--min-tcb-microcode":  cfg.minTCBMicrocode,
	} {
		if v > 255 {
			return nil, fmt.Errorf("%s is %d, must be 0-255", name, v)
		}
	}

	// The launch-measurement allowlist and --image-manifest are alternatives,
	// not complements. The manifest pins MRTD to exactly one value and that
	// value is deliberately NOT unioned into the allowlist (see below), so an
	// allowlist standing beside it can only restate the manifest's digest or
	// exclude it — and the exclusion is a policy no guest can ever satisfy:
	// every run fails on the MRTD compare, which reads like an attestation
	// failure rather than the typo it is. Refuse the pair up front, before any
	// file is read, so a contradictory invocation is a usage error here just as
	// it already is in the client-side verifier.
	if cfg.measurementsConfig != "" && cfg.imageManifest != "" {
		return nil, fmt.Errorf("--image-policy-file cannot be combined with --image-manifest: select one complete image policy")
	}
	if cfg.imageManifest != "" && (len(cfg.measurements) > 0 || cfg.measurementsFile != "") {
		used := allowlistFlagsUsed(cfg)
		return nil, fmt.Errorf("%s cannot be combined with --image-manifest: the manifest pins MRTD exactly (together with RTMR[1] and RTMR[2] from the same build), so a launch-measurement allowlist beside it can only narrow that single digest or contradict it, and a contradiction is a policy no guest can ever satisfy. To pin this image, drop %s; to accept several firmware images instead, drop --image-manifest — which also gives up its RTMR[1]/RTMR[2] guest kernel and rootfs pins", used, used)
	}

	// Read once, keeping complete image policies separate from digest lists.
	refValues, err := (cmdsutil.ImagePolicySource{File: cfg.measurementsConfig}).LoadValues(
		cmdsutil.MeasurementPins{Measurements: cfg.measurements, MeasurementsFile: cfg.measurementsFile})
	if err != nil {
		return nil, err
	}
	measurements, err := cmdsutil.LoadMeasurements(cfg.measurements, cfg.measurementsFile)
	if err != nil {
		return nil, err
	}

	// --image-manifest carries MRTD in the same tuple as RTMR[1]/[2]. It is
	// deliberately NOT unioned into the --measurements allowlist: an allowlist
	// is satisfied by ANY member, so a launch digest from some other pinned
	// build would pass while RTMR[1]/[2] were pinned against this manifest,
	// splitting the atomic tuple. MRTD is instead compared exactly, the same
	// rule get-kubeconfig's gate applies to the same manifest (newOutcome).
	pins, err := resolveRTMRPins(cfg)
	if err != nil {
		return nil, err
	}
	// RTMR[3] is the runtime extend chain of a guest whose image the host
	// chose. Without an image pin the host can boot anything and reproduce the
	// chain, so a lone RTMR[3] verdict reads like a proof of identity while
	// proving none — the same reason get-kubeconfig makes the manifest
	// mandatory. One check for both ways of supplying the pin: a second,
	// parallel rule is a second place for the requirement to be forgotten.
	if pins.rtmr3 != nil && pins.image == nil {
		return nil, fmt.Errorf("%s requires --image-manifest: RTMR[3] records events extended into a guest whose image the untrusted host selects, so pinning it without pinning the image proves nothing about what is running", rtmr3FlagUsed(cfg))
	}

	if _, err := expectedOperatorKeysDigest(cfg); err != nil {
		return nil, err
	}

	var caPool *x509.CertPool
	if cfg.meshCA != "" {
		caPool, err = meshCAPool(cfg.meshCA)
		if err != nil {
			return nil, err
		}
	}

	if cfg.sandboxID != "" {
		if err := ratls.ValidateSandboxID(cfg.sandboxID); err != nil {
			return nil, fmt.Errorf("--sandbox-id: %w", err)
		}
		if cfg.meshCA == "" {
			// The ID lives in the leaf's signed area, not in REPORTDATA, so
			// only the mesh CA signature authenticates it. Pinning without
			// checking that signature would pin a string the presenter chose.
			return nil, fmt.Errorf("--sandbox-id requires --mesh-ca: the sandbox ID is vouched by CDS's signature on the leaf, not by the hardware evidence")
		}
	}

	// The matched-workload stamp is CA-vouched exactly like the sandbox ID, so
	// both workload-policy flags demand the chain check that authenticates it.
	if cfg.workload != "" {
		if !pkgallowlist.ValidWorkloadName(cfg.workload) {
			return nil, fmt.Errorf("--workload: %q is not a valid workload entry name (1..%d bytes, [A-Za-z0-9][A-Za-z0-9._-]*)", cfg.workload, pkgallowlist.MaxWorkloadNameLen)
		}
		if cfg.meshCA == "" {
			return nil, fmt.Errorf("--workload requires --mesh-ca: the matched workload is vouched by CDS's signature on the leaf, not by the hardware evidence")
		}
	}
	// The file itself is read by run, once, and threaded through — see
	// loadHeldAllowlist.
	if cfg.allowlistFile != "" && cfg.meshCA == "" {
		return nil, fmt.Errorf("--allowlist requires --mesh-ca: the stamped policy digest is vouched by CDS's signature on the leaf, not by the hardware evidence")
	}
	for _, d := range cfg.pinPolicies {
		if !policyDigestRE.MatchString(d) {
			return nil, fmt.Errorf("--pin-policy %q is not sha256:<64 lowercase hex>", d)
		}
	}

	initDataHash, err := parseInitDataPin(cfg.initDataHex)
	if err != nil {
		return nil, err
	}

	return &verifyPlan{
		// RTMRs is still set: it is what enforces the pin if this policy is
		// ever verified through the delegated attestation-api path. It is not
		// what enforces it today — see rtmrPins.manual.
		policy: &ratls.VerifyPolicy{Policy: remote.Policy{
			Images:       refValues.Images,
			Measurements: measurements,
			Registers:    pins.manual,
			AllowDebug:   cfg.allowDebug,
		}},
		pins:         pins,
		meshCA:       caPool,
		initDataHash: initDataHash,
		refValues:    refValues,
	}, nil
}

// parseInitDataPin parses --init-data: the SHA-256 hex digest of the init-data
// document the target guest must carry. Empty means unpinned.
func parseInitDataPin(flag string) ([]byte, error) {
	if flag == "" {
		return nil, nil
	}
	digest, err := hex.DecodeString(strings.TrimSpace(flag))
	if err != nil {
		return nil, fmt.Errorf("--init-data is not hex: %v", err)
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("--init-data is %d bytes, want %d (SHA-256 of the init-data document)", len(digest), sha256.Size)
	}
	return digest, nil
}

// rtmrPins are every TDX register pin resolved from the flags: the image tuple
// (--image-manifest; MRTD, RTMR[1] and RTMR[2] all compare exactly), the
// optional runtime-register pin (--expected-rtmr3, or --operator-pkey, which
// derives the same register from the operator public key), and the by-hand
// pins (--rtmr <index>=<hex>). Any non-nil pin against non-TDX evidence is a
// policy error, never an ignored option.
//
// All of them are enforced in one place — applyRTMRPins, against the verified
// claims — so a pin cannot be accepted by the CLI and then enforced by nobody.
// buildPolicy still refuses --rtmr together with --image-manifest, because the
// two would otherwise pin RTMR[1]/[2] from different sources and a
// disagreement is a policy no guest can satisfy.
type rtmrPins struct {
	image runtimemeasure.ImageIdentity
	rtmr3 []byte
	// manual holds --rtmr <index>=<hex>. It is enforced here, next to the
	// other two, rather than left to ratls.VerifyPolicy.Policy.RTMRs: that field is
	// read only by attestation-go/remote, on the delegated attestation-api
	// path, and `c8s verify` always verifies in process (verifyInProcess ->
	// localverify.Verify, whose Params carries no registers). Setting the
	// policy field alone made the flag a silent no-op.
	manual map[int][]byte
}

func (p rtmrPins) any() bool {
	return p.image != nil || p.rtmr3 != nil || len(p.manual) > 0
}

// allowlistFlagsUsed names the launch-measurement allowlist flags the operator
// actually passed, so the --image-manifest conflict blames what was typed.
func allowlistFlagsUsed(cfg config) string {
	switch {
	case len(cfg.measurements) > 0 && cfg.measurementsFile != "":
		return "--measurements/--measurements-file"
	case cfg.measurementsFile != "":
		return "--measurements-file"
	default:
		return "--measurements"
	}
}

// rtmr3FlagUsed names whichever flag supplied the RTMR[3] pin. Both feed one
// slot, so the shared rules must be able to blame the right one.
func rtmr3FlagUsed(cfg config) string {
	switch {
	case cfg.operatorPubkey != "":
		return "--operator-pkey"
	case cfg.expectedRTMR3Hex != "":
		return "--expected-rtmr3"
	default:
		return "--rtmr 3="
	}
}

// resolveRTMRPins parses --image-manifest and the RTMR[3] pin. Called exactly
// once, from buildPolicy, so a bad flag is a usage error and the manifest's
// three registers can never come from two different reads of the file.
func resolveRTMRPins(cfg config) (rtmrPins, error) {
	manual, err := refvalues.ParseRegisterPins(cfg.rtmrs)
	if err != nil {
		return rtmrPins{}, fmt.Errorf("--rtmr: %w", err)
	}
	// RTMR[3] has three spellings — --rtmr 3=, --expected-rtmr3, and
	// --operator-pkey (which derives the value) — and they write one slot, so
	// accepting two would silently let one win. An operator naming two
	// expected values wants a verdict on neither.
	var rtmr3Flags []string
	if _, ok := manual[3]; ok {
		rtmr3Flags = append(rtmr3Flags, "--rtmr 3=")
	}
	if cfg.expectedRTMR3Hex != "" {
		rtmr3Flags = append(rtmr3Flags, "--expected-rtmr3")
	}
	if cfg.operatorPubkey != "" {
		rtmr3Flags = append(rtmr3Flags, "--operator-pkey")
	}
	if len(rtmr3Flags) > 1 {
		return rtmrPins{}, fmt.Errorf("%s all pin RTMR[3]: name the register once", strings.Join(rtmr3Flags, " and "))
	}

	var pins rtmrPins
	if cfg.imageManifest != "" {
		img, err := runtimemeasure.LoadImageManifest(cfg.imageManifest)
		if err != nil {
			return rtmrPins{}, fmt.Errorf("--image-manifest: %w", err)
		}
		// The pins below (MRTD, RTMR[1], RTMR[2]) exist only on TDX, so an
		// SNP manifest would load and then pin nothing. Refuse it here rather
		// than report an enforcement that never ran.
		if img.Family() != teetypes.FamilyTDX {
			return rtmrPins{}, fmt.Errorf("--image-manifest: %s pins a %s image; c8s verify pins the TDX image tuple (MRTD + RTMR[1] + RTMR[2]) and has no gate for another family",
				cfg.imageManifest, img.Family())
		}
		pins.image = img
	}
	if cfg.expectedRTMR3Hex != "" {
		b, err := hex.DecodeString(strings.TrimSpace(cfg.expectedRTMR3Hex))
		if err != nil {
			return rtmrPins{}, fmt.Errorf("--expected-rtmr3 is not hex: %w", err)
		}
		if len(b) != runtimemeasure.Size {
			return rtmrPins{}, fmt.Errorf("--expected-rtmr3 is %d bytes, want %d (%d hex chars)",
				len(b), runtimemeasure.Size, runtimemeasure.Size*2)
		}
		pins.rtmr3 = b
	}
	if cfg.operatorPubkey != "" {
		pubPEM, err := os.ReadFile(cfg.operatorPubkey)
		if err != nil {
			return rtmrPins{}, fmt.Errorf("read --operator-pkey: %w", err)
		}
		if err := checkOperatorPublicKeyPEM(pubPEM); err != nil {
			return rtmrPins{}, fmt.Errorf("--operator-pkey %s: %w", cfg.operatorPubkey, err)
		}
		// The seed is derived by the shared convention package, never
		// recomputed here: the initrd, cred-release and get-kubeconfig all go
		// through runtimemeasure.Seed, and a second implementation of the same
		// arithmetic is a second thing to drift. It hashes the file bytes
		// verbatim — the check above only inspects them.
		seed := runtimemeasure.Seed(pubPEM)
		pins.rtmr3 = seed[:]
	}
	if v, ok := manual[3]; ok {
		pins.rtmr3 = v
		// rtmr3 owns index 3 from here; manual is the by-hand 1/2 set, which
		// is the half that conflicts with a manifest rather than requiring it.
		delete(manual, 3)
	}

	// The two halves relate to the image pin in opposite directions, so the
	// rules cannot be one rule.
	//
	// RTMR[1] and [2] ARE the image — guest kernel, and the command line
	// carrying the dm-verity root hash. A manifest pins both, tied to the MRTD
	// from the same build, so a by-hand pin beside it can only restate that or
	// contradict it, and a contradiction is a policy no guest satisfies.
	if len(manual) > 0 && pins.image != nil {
		return rtmrPins{}, fmt.Errorf("--rtmr %s cannot be combined with --image-manifest: the manifest already pins RTMR[1] and RTMR[2] exactly, together with the MRTD from the same build. Drop --rtmr to pin the published image, or drop --image-manifest to pin registers by hand (giving up the MRTD tie to the same build)", manualIndexList(manual))
	}
	// RTMR[3] is the opposite: it records events extended inside a guest whose
	// image the untrusted host selects, so without an image pin the host boots
	// anything and reproduces the chain. A lone RTMR[3] verdict then reads as
	// proof of identity while proving none — the same reason get-kubeconfig
	// makes the manifest mandatory.
	if pins.rtmr3 != nil && pins.image == nil {
		return rtmrPins{}, fmt.Errorf("%s requires --image-manifest: RTMR[3] records events extended into a guest whose image the untrusted host selects, so pinning it without pinning the image proves nothing about what is running", rtmr3FlagUsed(cfg))
	}

	pins.manual = manual
	return pins, nil
}

// manualIndexList renders the by-hand indices in ascending order, so the
// conflict names what was actually typed.
func manualIndexList(manual map[int][]byte) string {
	idx := slices.Sorted(maps.Keys(manual))
	parts := make([]string, len(idx))
	for i, n := range idx {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, "/")
}

// checkOperatorPublicKeyPEM rejects a file that is not a PKIX public key before
// its bytes become a register pin. runtimemeasure.Seed hashes whatever it is given,
// so any file yields some digest: without this check a mistyped path or a
// private key handed over by mistake produces a pin no node can ever match, and
// the resulting RTMR[3] mismatch would read like a compromised node rather than
// a wrong file.
func checkOperatorPublicKeyPEM(pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("file is not PEM: expected a PKIX public key (\"-----BEGIN PUBLIC KEY-----\", as written by `openssl ec -pubout`)")
	}
	if strings.Contains(block.Type, "PRIVATE KEY") {
		return fmt.Errorf("file holds a %q PEM block, but this flag takes the operator PUBLIC key — the exact bytes the guest initrd hashed; pass the `openssl ec -pubout` output instead", block.Type)
	}
	if block.Type != "PUBLIC KEY" {
		return fmt.Errorf("PEM block type is %q, want \"PUBLIC KEY\" (a PKIX public key)", block.Type)
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return fmt.Errorf("PEM block is not a parseable PKIX public key: %w", err)
	}
	return nil
}

// expectedOperatorKeysDigest is the KeySetDigest of the --operator-keys bundle,
// or nil when the flag is unset.
func expectedOperatorKeysDigest(cfg config) ([]byte, error) {
	if cfg.operatorKeys == "" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(cfg.operatorKeys)
	if err != nil {
		return nil, fmt.Errorf("read --operator-keys: %w", err)
	}
	keys, err := operatorauth.ParsePublicKeysPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("--operator-keys: %w", err)
	}
	return operatorauth.KeySetDigest(keys)
}

// heldAllowlist is the --allowlist file: the exact bytes (which are what gets
// hashed — no reserialization, per the canonical-bytes rule) and the parsed
// document the stamped name resolves against.
type heldAllowlist struct {
	raw []byte
	doc *pkgallowlist.Allowlist
}

// loadHeldAllowlist reads --allowlist once, or returns nil when the flag is
// unset. Once, deliberately: a second read would let the verdict validate one
// version of the file and hash another.
func loadHeldAllowlist(path string) (*heldAllowlist, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --allowlist: %w", err)
	}
	doc, err := pkgallowlist.ParseServedJSON(data)
	if err != nil {
		return nil, fmt.Errorf("--allowlist: %w", err)
	}
	return &heldAllowlist{raw: data, doc: doc}, nil
}

// meshCAPool loads the mesh CA bundle used to authenticate a leaf's sandbox ID.
func meshCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --mesh-ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("--mesh-ca %s contains no PEM certificates", path)
	}
	return pool, nil
}

func gatherEvidence(ctx context.Context, cfg config, plan *verifyPlan, overrideERD []byte) (*evidence, error) {
	// The --mesh-ca anchor travels with the gather, not just the verdict: a
	// leaf whose body nothing authenticates is not usable evidence, so the
	// chain check that authenticates it has to happen before the leaf's
	// contents are believed (authorizeLeafBody).
	trust := leafTrust{meshCA: plan.meshCA}

	if cfg.fromFile != "" {
		data, err := os.ReadFile(cfg.fromFile)
		if err != nil {
			return nil, err
		}
		return gatherFromFile(data, overrideERD, "file "+cfg.fromFile, trust)
	}
	if cfg.url == "" {
		return nil, fmt.Errorf("no target: pass a host:port / URL argument or --from-file")
	}

	dialAddr, baseURL, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		return nil, err
	}

	switch resolveMode(cfg) {
	case "ratls-cert":
		return gatherFromRATLSCert(ctx, dialAddr, cfg.server, cfg.timeout, trust)
	case "discovery":
		return gatherFromDiscovery(ctx, baseURL, cfg.discoveryPath, cfg.server, cfg.timeout, trust)
	case "attest-pq":
		return gatherFromEndpoint(ctx, baseURL, cfg.server, cfg.timeout)
	case "attest-lb":
		return gatherFromAttestLB(ctx, baseURL, cfg.server, cfg.timeout)
	default: // auto: try the LB discovery doc (what the chart serves), then the
		// serving cert. Don't fall back on a security error — surface it.
		ev, err := gatherFromDiscovery(ctx, baseURL, cfg.discoveryPath, cfg.server, cfg.timeout, trust)
		if err != nil && !isSecurityError(err) {
			return gatherFromRATLSCert(ctx, dialAddr, cfg.server, cfg.timeout, trust)
		}
		return ev, err
	}
}

// resolveMode maps mode+kind to a concrete evidence mode.
func resolveMode(cfg config) string {
	if cfg.mode != "" && cfg.mode != "auto" {
		return cfg.mode
	}
	switch cfg.kind {
	case "lb":
		return "discovery"
	case "cds", "workload":
		return "ratls-cert"
	default: // auto (or unknown kind): let gatherEvidence try the LB discovery
		// doc, then the RA-TLS serving cert, so a bare target with no --kind is
		// detected either way. Returning a concrete mode here would defeat that.
		return "auto"
	}
}

func defaultPort(cfg config) int {
	if cfg.defaults.DefaultPort != 0 {
		return cfg.defaults.DefaultPort
	}
	switch cfg.kind {
	case "cds":
		return 8443
	default:
		return 443
	}
}

// normalizeTarget turns a URL or host[:port] into (dialAddr, baseURL).
// IPv6 literals are handled via net.JoinHostPort so they are bracketed correctly.
func normalizeTarget(raw string, port int) (dialAddr, baseURL string, err error) {
	defPort := strconv.Itoa(port)
	if strings.Contains(raw, "://") {
		u, perr := url.Parse(raw)
		if perr != nil {
			return "", "", fmt.Errorf("parse url %q: %w", raw, perr)
		}
		host := u.Hostname()
		if host == "" {
			return "", "", fmt.Errorf("url %q has no host", raw)
		}
		p := u.Port()
		if p == "" {
			p = defPort
		}
		dialAddr = net.JoinHostPort(host, p)
		return dialAddr, u.Scheme + "://" + dialAddr, nil
	}
	// SplitHostPort distinguishes "host:port" from a bare IPv6 literal (which has
	// colons but no port); on failure we treat raw as a host needing defPort.
	if host, p, splitErr := net.SplitHostPort(raw); splitErr == nil {
		dialAddr = net.JoinHostPort(host, p)
	} else {
		dialAddr = net.JoinHostPort(raw, defPort)
	}
	return dialAddr, "https://" + dialAddr, nil
}

// Outcome is the JSON-serializable verdict.
type Outcome struct {
	Verified    bool      `json:"verified"`
	VerifiedAt  time.Time `json:"verified_at"`
	Backend     string    `json:"backend"`
	Source      string    `json:"source"`
	Fresh       bool      `json:"fresh"`
	Binding     string    `json:"binding"`
	Platform    string    `json:"platform,omitempty"`
	Measurement string    `json:"measurement,omitempty"`
	ReportData  string    `json:"report_data,omitempty"`
	// Debug and SMT always serialize, even when false: an absent key reads as false to a CI gate.
	Debug      bool   `json:"debug"`
	SMT        bool   `json:"smt"`
	CurrentTCB string `json:"current_tcb,omitempty"`
	CertSHA256 string `json:"cert_sha256,omitempty"`
	Pinned     bool   `json:"measurement_pinned"`
	Error      string `json:"error,omitempty"`

	// InitData is the init-data digest the verified evidence commits, and
	// InitDataNote says what stands behind it: compared against --init-data,
	// or reported unpinned.
	InitData     string `json:"init_data,omitempty"`
	InitDataNote string `json:"init_data_note,omitempty"`

	// RTMRsPinned lists the TDX runtime measurement registers this verdict
	// enforced, as "<index>:<hex>". On TDX the --measurements pin covers only
	// MRTD (the TDVF firmware): without RTMR[1]/[2] the guest kernel and
	// rootfs are unverified, and without RTMR[3] the runtime chain is. A
	// verdict that proves neither must not look like one that proves both.
	RTMRsPinned []string `json:"rtmrs_pinned,omitempty"`

	// Warnings are policy gaps in an otherwise passing verdict — verified
	// true, but with named limits a relying party should read.
	Warnings []string `json:"warnings,omitempty"`

	// Partial is true when the hardware evidence verified but a property the
	// evidence presents is not proven (a front door whose live handshake
	// presented a serving key the evidence does not attest — or offered no
	// handshake to observe —, a responder-chosen chain anchor). Verified
	// stays false, so a CI gate checking verified==true fails closed; the
	// exit code distinguishes the case (4) from a failure (2). NotProven
	// names each unproven property.
	Partial   bool     `json:"partial,omitempty"`
	NotProven []string `json:"not_proven,omitempty"`

	// ChainAnchor states what an endpoint-presented mesh chain (attest-pq /
	// saved bundle) was verified against: set only when the chain verified
	// against the pinned --mesh-ca bundle. A responder-chosen anchor is never
	// reported here — it lands in NotProven.
	ChainAnchor string `json:"chain_anchor,omitempty"`

	// CertBody says what authenticates the leaf certificate's body fields
	// (subject/serial/validity): the leaf's own attested key when
	// self-signed, a verified issuing chain, possession of the attested key
	// proven by a live TLS handshake (the RA-TLS dial, or the discovery
	// gather's front-door probe), or — on attest-pq — the identity
	// transcript the hardware evidence binds (whose chain anchor is
	// responder-chosen; see ChainAnchor). A leaf with none of these is not
	// accepted as evidence at all (authorizeLeafBody), because checking a
	// validity window inside an unsigned body bounds nothing.
	CertBody string `json:"cert_body,omitempty"`

	// OperatorKeys are hex SHA-256 fingerprints (of the PKIX/SPKI DER) of the
	// operator public keys the target pins for allowlist writes (served list,
	// kind=cds only), fetched over the attested serving cert.
	// OperatorKeysNote says what stands behind them: matched against
	// --operator-keys, reported unpinned, or why the set is absent.
	OperatorKeys     []string `json:"operator_keys,omitempty"`
	OperatorKeysNote string   `json:"operator_keys_note,omitempty"`

	// SandboxID is the CRI pod sandbox the leaf names, and SandboxIDNote says
	// what authenticates it. CDS stamps the ID into the leaf's signed area
	// after verifying the inventory-signed sandbox token, so it is vouched by
	// the mesh CA — not bound into REPORTDATA like the rest of this verdict.
	// Without --mesh-ca it is reported unverified.
	SandboxID     string `json:"sandbox_id,omitempty"`
	SandboxIDNote string `json:"sandbox_id_note,omitempty"`

	// Workload is the allowlist entry the leaf's matched-workload stamp names,
	// with the allowlist version and policy digest it was decided under.
	// CA-vouched like the sandbox ID; WorkloadNote carries the §8 verdict
	// (workload_verified, or why it is only reported). Failures land in Error
	// with the same taxonomy (workload_absent, workload_malformed,
	// workload_name_mismatch, allowlist_digest_mismatch, workload_unresolved).
	Workload                 string `json:"workload,omitempty"`
	WorkloadAllowlistVersion string `json:"workload_allowlist_version,omitempty"`
	WorkloadAllowlistDigest  string `json:"workload_allowlist_digest,omitempty"`
	WorkloadNote             string `json:"workload_note,omitempty"`

	// AllowlistBound lists the policy digests CDS says may be running, from
	// the attest-pq bundle's signed rollout state. Failures of --pin-policy
	// land in Error (pinned_state_absent, pinned_state_invalid,
	// pinned_state_stale, pinned_state_unleased, policy_not_pinned).
	AllowlistBound []string `json:"allowlist_bound,omitempty"`
	// AllowlistFiles are the --fetch-allowlists files, one per bound policy.
	AllowlistFiles []string `json:"allowlist_files,omitempty"`
}

// applySandboxPolicy surfaces the leaf's sandbox ID and enforces --sandbox-id /
// --operator-keys. It only ever demotes Verified — nothing here can rescue a
// failed hardware verification (docs/ratls.md).
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
	if cfg.meshCA != "" {
		if ev.leaf == nil {
			fail("--mesh-ca needs the target's leaf certificate (this evidence source carries none — use a cert, discovery, or attest-pq target)")
			return
		}
		pool, err := meshCAPool(cfg.meshCA)
		if err != nil {
			fail("%v", err)
			return
		}
		if _, err := ev.leaf.Verify(x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
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
		if cfg.meshCA == "" {
			oc.SandboxIDNote = "not verified: CDS's signature on the leaf vouches for this ID; pass --mesh-ca to check it"
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
		if err := ratls.CheckSandboxPin(ev.leaf, cfg.sandboxID); err != nil {
			fail("%v", err)
		} else if oc.SandboxIDNote != "" {
			oc.SandboxIDNote += ", and the ID matches --sandbox-id"
		}
	}

	checkMeasurementsConfig(cfg, plan, servedMeasurements, fail)

	// The served key list is authenticated by being fetched over the attested
	// serving cert. A failed fetch fails closed when the operator asked for the
	// check (a 404 is not an error — it maps to the empty-set digest in
	// fetchOperatorKeyFingerprints).
	expected, err := expectedOperatorKeysDigest(cfg)
	if err != nil {
		fail("%v", err)
		return
	}
	if len(expected) == 0 {
		if oc.Verified && len(opKeys.fingerprints) > 0 {
			oc.OperatorKeysNote = "not pinned: the set the target reports, compared against nothing (pass --operator-keys to pin it)"
		}
		return
	}
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
		oc.OperatorKeysNote = "matched: the set served over the attested cert equals --operator-keys"
	}
}

// checkMeasurementsConfig compares the set the target reports enforcing against
// the operator's own file. A swapped config leaves the launch measurement
// untouched, so this is what makes the substitution visible.
func checkMeasurementsConfig(cfg config, plan *verifyPlan, served measurementsReport, fail func(string, ...any)) {
	if cfg.measurementsConfig == "" {
		return
	}
	checkServedMeasurements(plan.refValues, served, fail)
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
			oc.WorkloadNote = "not verified: CDS's signature on the leaf vouches for this name; pass --mesh-ca to check it"
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

// policyDigestRE is the form of a policy digest in the rollout state.
var policyDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// applyPinPolicy reports the rollout bound and enforces --pin-policy: every
// policy that may run must be one the caller reviewed and pinned.
func applyPinPolicy(oc *Outcome, cfg config, ev *evidence) {
	if oc.Verified && ev.fresh && ev.rollout != nil && ev.rolloutErr == nil {
		oc.AllowlistBound = ev.rollout.Bound
	}
	if len(cfg.pinPolicies) == 0 {
		return
	}
	fail := func(format string, args ...any) {
		oc.Verified = false
		if oc.Error == "" {
			oc.Error = fmt.Sprintf(format, args...)
		}
	}
	switch {
	case ev.rolloutErr != nil:
		fail("pinned_state_invalid: %v", ev.rolloutErr)
	case ev.rollout == nil:
		fail("pinned_state_absent: --pin-policy needs an attest-pq or attest-lb target serving the CDS rollout state (router.attest.pinnedAllowlist)")
	case !ev.fresh:
		fail("pinned_state_stale: the rollout state is not bound to a nonce this run chose")
	case ev.rollout.Lease <= 0:
		fail("pinned_state_unleased: CDS applies allowlist writes without an activation lease, so open sessions are not fenced")
	default:
		for _, d := range ev.rollout.Bound {
			if !slices.Contains(cfg.pinPolicies, d) {
				fail("policy_not_pinned: policy %s may be running and is not pinned; review it at /.well-known/c8s/objects/sha256/%s", d, strings.TrimPrefix(d, "sha256:"))
				return
			}
		}
	}
}

// newOutcome maps a verifier verdict to the shared Outcome. The verifier proves
// the AMD chain, REPORTDATA binding, debug, and min-TCB; the launch-measurement
// allowlist (--measurements) and the TDX runtime-register pins have no
// verifier-side input, so they are enforced here on the signature-verified
// claims and fail closed.
func newOutcome(cfg config, ev *evidence, result *teetypes.VerificationResult, verr error, plan *verifyPlan) Outcome {
	// An image manifest is a measurement pin too — a strictly stronger one
	// than an allowlist — so a run pinned only by --image-manifest must not
	// report itself as unpinned.
	pinned := len(plan.policy.Policy.Measurements) > 0 || plan.pins.image != nil || !plan.refValues.Empty()
	oc := Outcome{
		Backend:    "attestation-go",
		VerifiedAt: time.Now().UTC(),
		Source:     ev.source,
		Fresh:      ev.fresh,
		Binding:    ev.bindingNote,
		CertSHA256: ev.certSHA256,
		Pinned:     pinned,
	}
	if ev.leaf != nil {
		oc.CertBody = describeCertBody(cfg, ev)
	}
	if verr != nil {
		oc.Error = verr.Error()
		return oc
	}
	// Prefer the platform the verifier reported; fall back to what we sent.
	oc.Platform = string(result.Platform)
	if oc.Platform == "" {
		oc.Platform = ev.platform
	}
	oc.Measurement = result.Claims.LaunchDigest
	oc.CurrentTCB = formatTCB(result.Claims.TCB)
	oc.ReportData = hex.EncodeToString(result.Claims.ReportData)
	oc.Debug, oc.SMT = reportFlags(result.Claims)

	// The TDX-only gate runs before any register is compared: on non-TDX
	// evidence an MRTD/RTMR pin cannot be enforced at all, and reporting a
	// register mismatch would obscure that the policy was inapplicable.
	if plan.pins.any() && !isTDX(oc.Platform) {
		oc.Error = fmt.Sprintf("an RTMR pin (--image-manifest / --expected-rtmr3 / --operator-pkey) is set but the evidence platform is %q: runtime measurement registers exist only on TDX, so this policy cannot be enforced against %q evidence", oc.Platform, oc.Platform)
		return oc
	}
	if !enforceMinTCB(&oc, cfg, result) {
		return oc
	}

	fullImagePinned := plan.pins.image != nil
	if !plan.refValues.Empty() {
		if plan.refValues.Family != teetypes.NormalizePlatform(oc.Platform).Family() {
			oc.Error = fmt.Sprintf("--image-policy-file is for %q but the evidence platform is %q", plan.refValues.Family, oc.Platform)
			return oc
		}
		response := remote.VerifyResponse{Result: *result}
		if err := remote.EnforceImages(response, plan.refValues.Images, teetypes.NormalizePlatform(oc.Platform)); err != nil {
			oc.Error = fmt.Sprintf("--image-policy-file: %v", err)
			return oc
		}
		// A TDX tuple covers the guest only when the matching entry pins both
		// kernel and rootfs registers. A weak alternative must not borrow the
		// completeness of an unrelated entry in the same policy.
		for _, entry := range plan.refValues.Images {
			if len(entry.Registers[1]) != 0 && len(entry.Registers[2]) != 0 &&
				remote.EnforceImages(response, []remote.ImagePin{entry}, teetypes.NormalizePlatform(oc.Platform)) == nil {
				fullImagePinned = true
				break
			}
		}
	}

	if pinned {
		launch := strings.ToLower(strings.TrimSpace(result.Claims.LaunchDigest))
		mb, err := hex.DecodeString(launch)
		if err != nil || len(mb) == 0 {
			oc.Error = fmt.Sprintf("cannot enforce the measurement policy: launch_digest is missing or malformed (%q)", result.Claims.LaunchDigest)
			return oc
		}
		// The manifest's MRTD is compared exactly, not merged into the
		// allowlist: RTMR[1]/[2] are pinned against THIS manifest, so an MRTD
		// that merely appears somewhere in --measurements would let a launch
		// digest from a different build satisfy the tuple. Same rule as
		// getkubeconfig's measuredPolicy.checkIdentity — one manifest, one
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
				oc.Error = fmt.Sprintf("MRTD mismatch: launch measurement %s does not match the --image-manifest MRTD %s (a different guest firmware/image booted)",
					launch, hex.EncodeToString(mrtd[:]))
				return oc
			}
		}
		if len(plan.policy.Policy.Measurements) > 0 && !remote.MeasurementAllowed(mb, plan.policy.Policy.Measurements) {
			oc.Error = "launch measurement not in --measurements allowlist"
			return oc
		}

		// What decides between rejecting an MRTD-only TDX verdict and warning
		// about it is whether an operator-pinned CA anchor (--mesh-ca) stands next
		// to the measurements. Without one the verdict is deployment-class — the
		// measurement pins are the entire trust anchor — and an incomplete image
		// policy is a hard failure. A responder-committed CA (attest-pq's derived
		// anchor) does not downgrade this: chosen by the responder, it anchors
		// nothing the operator asked about — the same rule the JS verifier applies
		// to a deployment-class verdict.
		if isTDX(oc.Platform) && !fullImagePinned {
			const mrtdOnly = "TDX measurement pin covers MRTD only — MRTD measures the TDVF firmware, so the guest kernel and rootfs are UNMEASURED by this policy; pass --image-manifest to pin the full image tuple"
			if plan.meshCA == nil {
				oc.Error = mrtdOnly + " (with no pinned CA anchor this verdict is deployment-class — the measurement pins are the entire trust anchor — so an incomplete measurement policy is rejected; pin --mesh-ca to downgrade this to a warning)"
				return oc
			}
			oc.Warnings = append(oc.Warnings, mrtdOnly)
		}
	}
	if !applyRTMRPins(&oc, plan.pins, result) {
		return oc
	}
	oc.Verified = true

	return oc
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
//
// Returns false with oc.Error set on any failure.
func enforceMinTCB(oc *Outcome, cfg config, result *teetypes.VerificationResult) bool {
	floor := minTCBFromCfg(cfg)
	if floor == nil {
		return true
	}
	if isTDX(oc.Platform) {
		oc.Error = fmt.Sprintf("a --min-tcb-* floor is set but the evidence platform is %q: the floor names SEV-SNP TCB components (bootloader/tee/snp/microcode), which TDX evidence does not carry and the TDX verification path does not consume, so this policy cannot be enforced against %q evidence", oc.Platform, oc.Platform)
		return false
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
			oc.Error = fmt.Sprintf("cannot enforce --min-tcb-%s: the verified claims carry no %s TCB component", c.flag, c.flag)
			return false
		}
		if *c.got < c.want {
			oc.Error = fmt.Sprintf("TCB component %s is %d, below the --min-tcb-%s floor of %d", c.flag, *c.got, c.flag, c.want)
			return false
		}
	}
	return true
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

// applyRTMRPins enforces the --image-manifest RTMR[1]/[2] and the RTMR[3] pin
// on the verified claims, recording what was enforced in RTMRsPinned.
// The pins come from the plan resolved once in buildPolicy, and newOutcome has
// already gated the platform. Returns false (with oc.Error set) on an absent
// or malformed claim, or a mismatch — never an ignored option.
func applyRTMRPins(oc *Outcome, pins rtmrPins, result *teetypes.VerificationResult) bool {
	if !pins.any() {
		return true
	}

	check := func(idx int, meaning string, want []byte) bool {
		got, err := result.Claims.RTMR(idx)
		if err != nil {
			oc.Error = fmt.Sprintf("cannot enforce the RTMR[%d] pin: register claim absent or malformed: %v", idx, err)
			return false
		}
		if !bytes.Equal(got, want) {
			oc.Error = fmt.Sprintf("RTMR[%d] (%s) is %x, expected %x", idx, meaning, got, want)
			return false
		}
		oc.RTMRsPinned = append(oc.RTMRsPinned, fmt.Sprintf("%d:%s", idx, hex.EncodeToString(want)))
		return true
	}
	if pins.image != nil {
		regs := pins.image.RTMRs()
		// Ascending index, for the same reproducibility reason as the manual
		// pins below.
		for _, idx := range slices.Sorted(maps.Keys(regs)) {
			want := regs[idx]
			if !check(idx, imageRTMRMeaning(idx), want[:]) {
				return false
			}
		}
	}
	if pins.rtmr3 != nil && !check(3, "runtime operator-key/workload chain", pins.rtmr3) {
		return false
	}
	// Ascending index, so a target missing several pinned registers always
	// names the same one first and a failing verdict is reproducible.
	for _, idx := range slices.Sorted(maps.Keys(pins.manual)) {
		if !check(idx, rtmrMeaning(idx), pins.manual[idx]) {
			return false
		}
	}
	return true
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
	case ev.leafKeyProven:
		return "CA-signed: body not chain-checked, but the live TLS handshake proves the peer holds the attested key, so this body could not have been minted around it — pass --mesh-ca to also check the issuing chain"
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

func render(cfg config, oc Outcome, out io.Writer) {
	if cfg.output == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(oc)
		return
	}
	renderText(cfg, oc, out)
}

func renderText(cfg config, oc Outcome, out io.Writer) {
	switch {
	case oc.Verified:
		fmt.Fprintf(out, "✓ VERIFIED  (%s backend)\n", oc.Backend)
	case oc.Partial:
		fmt.Fprintf(out, "~ PARTIALLY VERIFIED  (%s backend)\n", oc.Backend)
	default:
		fmt.Fprintf(out, "✗ NOT VERIFIED  (%s backend)\n", oc.Backend)
	}
	fmt.Fprintf(out, "  source:       %s\n", oc.Source)
	fmt.Fprintf(out, "  verified at:  %s\n", oc.VerifiedAt.Format(time.RFC3339))
	if oc.Error != "" {
		fmt.Fprintf(out, "  reason:       %s\n", oc.Error)
		return
	}
	fmt.Fprintf(out, "  platform:     %s\n", oc.Platform)
	fmt.Fprintf(out, "  measurement:  %s\n", oc.Measurement)
	for _, p := range oc.RTMRsPinned {
		idx, hexVal, _ := strings.Cut(p, ":")
		fmt.Fprintf(out, "  RTMR[%s]:      %s (matched)\n", idx, hexVal)
	}
	if oc.InitDataNote != "" {
		if oc.InitData != "" {
			fmt.Fprintf(out, "  init-data:    %s\n", oc.InitData)
			fmt.Fprintf(out, "                %s\n", oc.InitDataNote)
		} else {
			fmt.Fprintf(out, "  init-data:    %s\n", oc.InitDataNote)
		}
	}
	fmt.Fprintf(out, "  TCB:          %s   debug=%t smt=%t\n", oc.CurrentTCB, oc.Debug, oc.SMT)
	if oc.CertSHA256 != "" {
		fmt.Fprintf(out, "  cert sha256:  %s\n", oc.CertSHA256)
	}
	if oc.CertBody != "" {
		fmt.Fprintf(out, "  cert body:    %s\n", oc.CertBody)
	}
	if oc.ChainAnchor != "" {
		fmt.Fprintf(out, "  chain anchor: %s\n", oc.ChainAnchor)
	}
	fmt.Fprintf(out, "  binding:      %s\n", oc.Binding)
	for _, np := range oc.NotProven {
		fmt.Fprintf(out, "  not proven:   %s\n", np)
	}
	for _, w := range oc.Warnings {
		fmt.Fprintf(out, "  WARNING:      %s\n", w)
	}
	if oc.SandboxID != "" {
		fmt.Fprintf(out, "  sandbox id:   %s\n", oc.SandboxID)
		fmt.Fprintf(out, "                %s\n", oc.SandboxIDNote)
	}
	if oc.Workload != "" {
		fmt.Fprintf(out, "  workload:     %s  (allowlist version %s, digest %s)\n", oc.Workload, oc.WorkloadAllowlistVersion, oc.WorkloadAllowlistDigest)
		fmt.Fprintf(out, "                %s\n", oc.WorkloadNote)
	}
	if len(oc.AllowlistBound) > 0 {
		fmt.Fprintf(out, "  allowlist:    %s\n", strings.Join(oc.AllowlistBound, ", "))
	}
	for _, path := range oc.AllowlistFiles {
		fmt.Fprintf(out, "                wrote %s\n", path)
	}
	if len(oc.OperatorKeys) > 0 {
		label := "operator keys (allowlist writes; CDS-reported config, NOT covered by the measurement):"
		fmt.Fprintf(out, "  %s\n", label)
		for _, fp := range oc.OperatorKeys {
			fmt.Fprintf(out, "    sha256(SPKI DER):%s\n", fp)
		}
		if oc.OperatorKeysNote != "" {
			fmt.Fprintf(out, "    %s\n", oc.OperatorKeysNote)
		}
	} else if oc.OperatorKeysNote != "" {
		fmt.Fprintf(out, "  operator keys: %s\n", oc.OperatorKeysNote)
	}
	if !oc.Fresh {
		fmt.Fprintf(out, "  note:         freshness NOT proven (no per-request nonce bound)\n")
	}
	if !oc.Pinned {
		fmt.Fprintf(out, "  WARNING:      no --measurements pinned — any genuine TEE is accepted (UNSAFE for production)\n")
	}
	if cfg.showEvidence {
		fmt.Fprintf(out, "  report_data:  %s\n", oc.ReportData)
	}
}
