package verify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/routerdiscovery"
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
	// Mode preselects the evidence mode (auto|armtls-cert|discovery|attest-pq).
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

	// observedServingCert and attestationNonce are what a saved attest-lb
	// receipt binds besides itself.
	observedServingCert string
	attestationNonce    string

	measurements       []string
	measurementsFile   string
	imageManifest      string
	expectedRTMR3Hex   string
	operatorPubkey     string
	rtmrs              []string
	operatorKeys       string
	routeDigests       []string
	routesFloor        string
	measurementsConfig string
	servedPolicyFile   string
	sandboxID          string
	clientDocument     string
	workload           string
	allowlistFile      string
	meshCA             string
	initDataHex        string
	allowDebug         bool
	minTCBBootloader   uint
	minTCBTEE          uint
	minTCBSNP          uint
	minTCBMicrocode    uint
	expectedRDHex      string
	pinPolicies        []string
	trustOperator      bool
	trustOperatorKeys  string
	fetchAllowlists    string

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
                         evidence with the VCEK inline), or, in --mode armtls-cert,
                         dial the armTLS serving cert (bare report; the VCEK is
                         fetched from AMD KDS). Default mode: cds → armtls-cert,
                         lb → discovery, auto → discovery then serving cert.
  --from-file FILE       verify a saved PEM cert or attestation-response JSON.
                         With --mode attest-lb, also pass the
                         --observed-serving-cert and --attestation-nonce the
                         receipt was fetched with.

  c8s cds verify https://cds.example.com:8443 --image-policy-file cds-pin.json
  c8s verify https://lb.example.com:443 --kind lb --measurements <sha384-hex> --mesh-ca mesh-ca.pem

A front door serving a CA-issued leaf is verified only with its mesh anchor;
'c8s cds ca --out mesh-ca.pem' writes that file.

--mode attest-pq and attest-lb evidence binds the digest of the route
manifest the router applied. Check it with exactly one of:
  --route-digest HEX     the digest ` + "`c8s routes show`" + ` prints; any other fails.
                         Repeat it to accept the old and the new digest
                         while a route change rolls out.
  --operator-keys FILE   fetch /.well-known/c8s/routes (published when
                         router.routePublication.enabled), verify its write
                         token under these keys and require the evidence
                         to bind its digest; add
                         --routes-floor REV:HEX to refuse a rollback.

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
	f.StringVar(&cfg.mode, "mode", orDefault(d.Mode, "auto"), "evidence mode: auto, armtls-cert, discovery, attest-pq, or attest-lb")
	f.StringVar(&cfg.discoveryPath, "discovery-path", routerdiscovery.DefaultPath, "path of the LB discovery document (discovery mode)")
	f.StringVar(&cfg.server, "server-name", "", "TLS SNI server name (for port-forward / routed domains)")
	f.DurationVar(&cfg.timeout, "timeout", 15*time.Second, "per-attempt timeout (evidence fetch and AMD KDS collateral fetch)")
	f.StringVar(&cfg.fromFile, "from-file", "", "verify evidence from a saved PEM certificate or attestation-response JSON instead of dialing")
	f.StringVar(&cfg.observedServingCert, "observed-serving-cert", "", "with --mode attest-lb --from-file: PEM serving leaf observed on the connection that fetched the receipt")
	f.StringVar(&cfg.attestationNonce, "attestation-nonce", "", "with --mode attest-lb --from-file: unpadded base64url nonce sent to fetch the receipt")

	f.StringSliceVar(&cfg.measurements, "measurements", nil, "allowed SHA-384 hex launch measurement(s) (repeatable / comma-separated); empty = no pinning (UNSAFE). On TDX this pins MRTD only, which covers just the TDVF firmware — use --image-manifest to pin the whole guest image instead (the two are mutually exclusive: the manifest already pins MRTD exactly)")
	f.StringVar(&cfg.measurementsFile, "measurements-file", "", "text file of allowed launch measurements, one hex digest per line; use --image-policy-file for complete JSON policies; excludes --image-manifest")
	f.StringVar(&cfg.imageManifest, "image-manifest", "", "build-artifact manifest of the expected TDX guest image (JSON object with mrtd, rtmr1, rtmr2, each 96 lowercase hex chars, published with the image build); all three registers are pinned exactly against this one manifest, so the guest kernel and rootfs are verified rather than only the firmware. Since it pins MRTD exactly it replaces --measurements/--measurements-file rather than combining with them. TDX evidence only — with SNP evidence this is a policy error")
	f.StringVar(&cfg.expectedRTMR3Hex, "expected-rtmr3", "", "DEPRECATED, prefer --rtmr 3=<sha384-hex>: identical pin under identical rules, one flag for every register. Retained so existing invocations keep working")
	f.StringVar(&cfg.operatorPubkey, "operator-pkey", "", "path to the launch PUBLIC key PEM (the verbatim file bytes the guest initrd hashed, as written by 'openssl ec -pubout') — derives and pins RTMR[3] as the bare launch-key seed, SHA-384(0x00*48 ‖ SHA-384(pubkey)), so the register need not be computed by hand. Mutually exclusive with --expected-rtmr3, and like it a deployment property, NOT a cluster identity, so it requires --image-manifest. A node that measures its allowlist policies reports the seed followed by them: verify then replays the list the evidence carries (an attest-pq or attest-lb bundle's measured_policies, or a TDX certificate's or discovery document's runtime extensions) and reports the longest prefix that matches as the node's policy history, which --pin-policy and --trust-operator check; without either, a non-empty history leaves the verdict partial. TDX evidence only — with SNP evidence this is a policy error")
	f.StringSliceVar(&cfg.rtmrs, "rtmr", nil, "expected TDX runtime measurement register(s) as <index>=<sha384-hex> (repeatable). RTMR[1] pins the guest kernel and RTMR[2] the kernel command line carrying the dm-verity root hash: these ARE the image, so pinning them by hand cannot be combined with --image-manifest, which pins the same two plus the MRTD from one provenanced build. RTMR[3] is the operator-key/workload chain extended inside whatever image the host booted, so --rtmr 3= REQUIRES --image-manifest — alone it would read as proof of identity while proving none. RTMR[0] is not pinnable. TDX evidence only — with SNP evidence any pin here is a policy error")
	cmdsutil.BindImagePolicyFlags(f, &cfg.measurementsConfig, nil, "pins complete target identities; required for kind=cds, where every entry must bind the launch file that CDS runs on; excludes --measurements, --measurements-file and --image-manifest")
	f.StringVar(&cfg.operatorKeys, "operator-keys", "", "PEM bundle of expected operator public keys. kind=cds: verification fails unless the key set the attested target serves at /operator-keys matches it. --mode attest-pq/attest-lb: the manifest the router publishes at /.well-known/c8s/routes must verify under these keys, and its digest must be the one the evidence binds; refused with --kind cds")
	f.StringVar(&cfg.routesFloor, "routes-floor", "", "with --operator-keys in attest-pq/attest-lb: <revision>:<route digest hex> last accepted; a published manifest with a lower revision, or the same revision and another digest, fails (rollback)")
	f.StringSliceVar(&cfg.routeDigests, "route-digest", nil, "expected route digest(s) (repeatable / comma-separated), the hex SHA-256 of the route manifest bytes as 'c8s routes show' prints it; attest-pq and attest-lb evidence binds one, so evidence binding any other digest fails verification. These modes require this or --operator-keys")
	f.StringVar(&cfg.servedPolicyFile, "served-policy-file", "", "path to a complete JSON image policy naming the exact set the target must serve and enforce at /measurements (kind=cds targets): the node identities a CDS admits, which are not its own. It asks for the served-set equality check; --image-policy-file pins the target's own identity. For a singleton CDS this is the file given to 'c8s cds config new --node-pins'")
	const refusedWithKindCDS = ". Refused with --kind cds: CDS's serving certificate is self-signed"
	f.StringVar(&cfg.sandboxID, "sandbox-id", "", "expected CRI pod sandbox ID on the target's leaf; requires --mesh-ca, since CDS's signature on the leaf is what vouches for the ID (docs/armtls.md)"+refusedWithKindCDS)
	f.StringVar(&cfg.clientDocument, "client-document", "", "file holding the exact client document the target Pod CVM was assigned; the leaf's client document digest must equal SHA-256 of these bytes. Requires --mesh-ca, since CDS's signature on the leaf is what vouches for the digest"+refusedWithKindCDS)
	f.StringVar(&cfg.workload, "workload", "", "expected matched-workload name on the target's leaf; requires --mesh-ca, since CDS's signature on the leaf is what vouches for the stamp (docs/armtls.md)"+refusedWithKindCDS)
	f.StringVar(&cfg.allowlistFile, "allowlist", "", "file holding the exact canonical allowlist bytes (as served by GET /allowlist); the leaf's stamped policy digest must equal SHA-256 of these bytes and the stamped name must resolve in the document. Requires --mesh-ca"+refusedWithKindCDS)
	f.StringVar(&cfg.meshCA, "mesh-ca", "", "PEM bundle of the CDS mesh CA; when set, the target's leaf must chain to it, which is what authenticates the reported sandbox ID. On attest-pq and attest-lb it is also what upgrades the chain anchor from responder-chosen (partial verdict) to verified"+refusedWithKindCDS)
	f.StringVar(&cfg.initDataHex, "init-data", "", "expected init-data digest: SHA-256 hex of the init-data document the target guest must carry. Verification fails unless the evidence commits exactly this digest")
	f.BoolVar(&cfg.allowDebug, "allow-debug", false, "accept debug-enabled guests")
	const tcbSNPOnly = " (SEV-SNP evidence only — TDX carries no such component, so against TDX evidence this is a policy error rather than an ignored flag)"
	f.UintVar(&cfg.minTCBBootloader, "min-tcb-bootloader", 0, "minimum bootloader TCB component"+tcbSNPOnly)
	f.UintVar(&cfg.minTCBTEE, "min-tcb-tee", 0, "minimum TEE TCB component"+tcbSNPOnly)
	f.UintVar(&cfg.minTCBSNP, "min-tcb-snp", 0, "minimum SNP firmware TCB component"+tcbSNPOnly)
	f.UintVar(&cfg.minTCBMicrocode, "min-tcb-microcode", 0, "minimum microcode TCB component"+tcbSNPOnly)
	f.StringSliceVar(&cfg.pinPolicies, "pin-policy", nil, "accepted allowlist policy digest(s) sha256:<hex> (repeatable / comma-separated): every policy in the node's replayed history, and the policy the leaf was issued under, must be one of these. The leaf's stamp counts as proven only with --mesh-ca; without it the verdict stays partial. Requires --operator-pkey or an --image-policy-file image pinning an approver_key; excludes --trust-operator")
	f.BoolVar(&cfg.trustOperator, "trust-operator", false, "accept every policy in the node's replayed history, and the policy the leaf was issued under, only when it carries a valid operator signature: each one is fetched from <target>/allowlist/objects/sha256/<hex>, re-hashed, and its stored write token checked against --trust-operator-keys. Only a document uploaded whole with a signed PUT /allowlist carries a token; a per-workload edit yields an unsigned policy. The leaf's stamp counts as proven only with --mesh-ca; without it the verdict stays partial. Requires --operator-pkey or an --image-policy-file image pinning an approver_key, and --trust-operator-keys")
	f.StringVar(&cfg.trustOperatorKeys, "trust-operator-keys", "", "PEM bundle of the operator public keys --trust-operator accepts signatures from. Requires --trust-operator; --operator-keys does not feed it")
	f.StringVar(&cfg.fetchAllowlists, "fetch-allowlists", "", "directory to save each policy in the node's replayed history to, as <hex>.json, after checking it hashes to its digest. A failed fetch or write fails the verdict (allowlist_fetch_failed). Requires --operator-pkey or an --image-policy-file image pinning an approver_key")
	f.StringVar(&cfg.expectedRDHex, "expected-report-data", "", "hex REPORTDATA / TPM-nonce anchor override for bare evidence files (1–64 bytes, exactly as bound by the producer); refused in --mode attest-pq and attest-lb")

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
	case "", "auto", "armtls-cert", "discovery", "attest-pq", "attest-lb":
	default:
		fmt.Fprintf(errOut, "error: unknown --mode %q (valid modes: auto, armtls-cert, discovery, attest-pq, attest-lb)\n", cfg.mode)
		return exitUsage
	}
	switch cfg.kind {
	case "", "auto", "cds", "lb", "workload":
	default:
		fmt.Fprintf(errOut, "error: unknown --kind %q (valid kinds: auto, cds, lb, workload)\n", cfg.kind)
		return exitUsage
	}
	switch cfg.output {
	case "", "text", "json":
	default:
		fmt.Fprintf(errOut, "error: unknown --output %q (valid formats: text, json)\n", cfg.output)
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
	offlineLB := cfg.mode == "attest-lb" && cfg.fromFile != ""
	if offlineLB != (cfg.observedServingCert != "") || offlineLB != (cfg.attestationNonce != "") {
		fmt.Fprintf(errOut, "error: --mode attest-lb --from-file requires --observed-serving-cert and --attestation-nonce, which apply to nothing else\n")
		return exitUsage
	}

	// Verify in-process with attestation-go — the Go port of the engine the
	// cluster runs. It auto-detects the platform and AMD product (incl. Siena)
	// and fetches the VCEK from AMD KDS itself, so a bare armTLS report, a
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
	var ev *evidence
	fetch := attestedFetcher(fetchAttested)
	if cfg.fromFile == "" && cfg.kind == "cds" && resolveMode(cfg) == "armtls-cert" {
		var attempt *cdsAttempt
		attempt, err = openCDSAttempt(ctx, cfg, leafTrust{meshCA: plan.meshCA})
		if err == nil {
			defer attempt.close()
			ev, fetch = attempt.evidence, attempt.fetch
		}
	} else {
		ev, err = gatherEvidence(ctx, cfg, plan, overrideERD)
	}
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
		if errors.Is(err, errRouteRequired) || errors.Is(err, errRouteNotBound) {
			fmt.Fprintf(errOut, "error: %v\n", err)
			return exitUsage
		}
		fmt.Fprintf(errOut, "error: could not obtain evidence: %v\n", err)
		return exitNoEvidence
	}
	return verifyEvidence(ctx, cfg, plan, ev, held, gatherOperatorKeys(ctx, cfg, ev, fetch), gatherMeasurements(ctx, cfg, plan, ev, fetch), out, errOut)
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
// must not dodge it. The attested modes skip it silently: there
// --operator-keys checks the published route manifest.
func gatherOperatorKeys(ctx context.Context, cfg config, ev *evidence, fetch attestedFetcher) operatorKeysReport {
	if attestedMode(cfg) {
		return operatorKeysReport{}
	}
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
	fps, digest, note, err := fetchOperatorKeyFingerprints(ctx, baseURL, cfg.server, ev.certSHA256, cfg.timeout, fetch)
	if err != nil {
		return operatorKeysReport{note: "not fetched: " + err.Error(), fetchErr: err}
	}
	return operatorKeysReport{fingerprints: fps, digest: digest, note: note}
}

// verifyEvidence verifies already-gathered evidence (from any source/mode)
// in-process with attestation-go (the Go port of the attestation-rs engine the
// cluster runs), which auto-detects the product and fetches the VCEK from KDS
// when it is not shipped inline — so a bare armTLS report and a discovery doc
// both work — then renders the verdict. The verification attempt (including the
// KDS fetch) is bounded by --timeout; an unobtainable-collateral failure is
// exit 3, not a verification verdict.
func verifyEvidence(ctx context.Context, cfg config, plan *verifyPlan, ev *evidence, held *heldAllowlist, opKeys operatorKeysReport, servedMeasurements measurementsReport, out, errOut io.Writer) int {
	if ev.podLeaf {
		return verifyPodLeaf(cfg, plan, ev, held, out)
	}
	verifyCtx := ctx
	if cfg.timeout > 0 {
		var cancel context.CancelFunc
		verifyCtx, cancel = context.WithTimeout(ctx, cfg.timeout)
		defer cancel()
	}
	result, verr := verifyInProcess(verifyCtx, ev, plan.policy, plan.initDataHash, minTCBFromCfg(cfg))
	if isConnectError(verr) {
		fmt.Fprintf(errOut, "error: could not fetch verification collateral: %v\n", verr)
		return exitNoEvidence
	}
	oc := newOutcome(cfg, ev, result, verr, plan)
	oc.OperatorKeys = opKeys.fingerprints
	oc.OperatorKeysNote = opKeys.note
	applyVerdictPolicies(&oc, cfg, ev, held, opKeys, plan, servedMeasurements)
	// The history check gets its own --timeout budget, not what the
	// verification left of it.
	unreachable := checkPolicyHistory(ctx, &oc, cfg, ev, plan.trustKeys)
	applyFinalNotes(&oc, ev, result, plan)
	render(cfg, oc, out)
	if unreachable {
		return exitNoEvidence
	}
	return verdictExitCode(oc)
}

// backendMeshChain names the verdict on a leaf that carries no hardware
// evidence: only its chain to --mesh-ca stands behind it.
const backendMeshChain = "mesh CA chain"

// verifyPodLeaf renders the verdict on a Pod CVM leaf (podLeafEvidence): the
// chain to --mesh-ca, already checked, and the CA-vouched stamps the leaf
// carries and the pins ask for. A pin on hardware evidence cannot hold for a
// leaf that carries none, so it fails the verdict.
func verifyPodLeaf(cfg config, plan *verifyPlan, ev *evidence, held *heldAllowlist, out io.Writer) int {
	oc := Outcome{
		Backend:    backendMeshChain,
		VerifiedAt: time.Now().UTC(),
		Source:     ev.source,
		Binding:    ev.bindingNote,
		CertSHA256: ev.certSHA256,
		CertBody:   describeCertBody(cfg, ev),
		Verified:   true,
	}
	if len(plan.policy.Policy.Measurements) > 0 || plan.pins.any() || !plan.refValues.Empty() || plan.initDataHash != nil ||
		minTCBFromCfg(cfg) != nil {
		oc.Verified = false
		oc.Error = "a Pod CVM leaf carries no hardware evidence, so measurement, register, init-data, TCB and policy-history pins cannot be checked against it; pin its stamps (--workload, --client-document, --sandbox-id, --allowlist) instead"
	}
	applySandboxPolicy(&oc, cfg, ev, operatorKeysReport{}, plan, measurementsReport{})
	applyWorkloadPolicy(&oc, cfg, ev, held)
	applyClientDocumentPolicy(&oc, cfg, ev)
	if oc.Verified {
		oc.ChainAnchor = "verified against the pinned --mesh-ca bundle"
	}
	render(cfg, oc, out)
	return verdictExitCode(oc)
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
		route, err := plan.routes.bind(ctx, "", "", 0)
		if err != nil {
			return nil, err
		}
		if cfg.mode == "attest-lb" {
			return gatherAttestLBFromFile(data, cfg.observedServingCert, cfg.attestationNonce, route, "file "+cfg.fromFile)
		}
		return gatherFromFile(data, overrideERD, route, "file "+cfg.fromFile, trust)
	}
	if cfg.url == "" {
		return nil, fmt.Errorf("no target: pass a host:port / URL argument or --from-file")
	}

	dialAddr, baseURL, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		return nil, err
	}

	switch resolveMode(cfg) {
	case "armtls-cert":
		return gatherFromARMTLSCert(ctx, dialAddr, cfg.server, cfg.timeout, trust)
	case "discovery":
		return gatherFromDiscovery(ctx, baseURL, cfg.discoveryPath, cfg.server, cfg.timeout, trust)
	case "attest-pq", "attest-lb":
		route, err := plan.routes.bind(ctx, baseURL, cfg.server, cfg.timeout)
		if err != nil {
			return nil, err
		}
		if resolveMode(cfg) == "attest-pq" {
			return gatherFromEndpoint(ctx, baseURL, cfg.server, cfg.timeout, route)
		}
		return gatherFromAttestLB(ctx, baseURL, cfg.server, cfg.timeout, route)
	default: // auto: try the LB discovery doc (what the chart serves), then the
		// serving cert. Don't fall back on a security error — surface it.
		ev, err := gatherFromDiscovery(ctx, baseURL, cfg.discoveryPath, cfg.server, cfg.timeout, trust)
		if err != nil && !isSecurityError(err) {
			return gatherFromARMTLSCert(ctx, dialAddr, cfg.server, cfg.timeout, trust)
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
		return "armtls-cert"
	default: // auto: let gatherEvidence try the LB discovery
		// doc, then the armTLS serving cert, so a bare target with no --kind is
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
