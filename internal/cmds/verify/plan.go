package verify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/workloadname"
)

// verifyPlan is one run's parsed, validated policy: the verifier policy, the
// TDX register pins, and the --mesh-ca anchor. Everything file-backed is read
// exactly ONCE, here, and threaded downstream — a pin resolved twice can be
// split by swapping the file between reads, which for --image-manifest would
// mean an MRTD from one build and RTMR[1]/[2] from another, defeating the
// whole point of loading the tuple atomically.
type verifyPlan struct {
	policy *armtls.VerifyPolicy
	pins   rtmrPins
	// meshCA is the parsed --mesh-ca bundle, nil when the flag is unset.
	meshCA *x509.CertPool
	// initDataHash is the parsed --init-data pin, nil when the flag is unset.
	initDataHash []byte
	// refValues is the parsed --image-policy-file, empty when unset. It
	// pins the target's own identity.
	refValues refvalues.ReferenceValues
	// served is the /measurements equality check's input, the set
	// --served-policy-file named, nil when it named none. It never feeds the
	// target's own identity pin (refValues above).
	served *refvalues.ReferenceValues
	// routes is the route digest check, nil when the run checks none.
	routes *routeCheck
	// trustKeys is the parsed --trust-operator-keys bundle, nil when unset.
	trustKeys []*ecdsa.PublicKey
	// operatorKeysDigest is the digest the set a kind=cds target serves at
	// /operator-keys must equal, nil when no --operator-keys bundle pins it.
	operatorKeysDigest []byte
}

// buildPolicy parses the measurement allowlist, resolves the register pins and
// the mesh CA anchor, and validates TCB bounds. The launch-measurement pin and
// min-TCB are enforced on the verifier verdict (newOutcome / verifyInProcess);
// only Measurements and AllowDebug are read by the verifier itself.
func buildPolicy(cfg config) (*verifyPlan, error) {
	if err := refuseMeshLeafFlagsWithKindCDS(cfg); err != nil {
		return nil, err
	}

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
	refValues, err := (cmdsutil.ImagePolicySource{File: cfg.measurementsConfig}).ValuesExcluding(
		cmdsutil.MeasurementPins{Measurements: cfg.measurements, MeasurementsFile: cfg.measurementsFile})
	if err != nil {
		return nil, err
	}
	if err := requireCDSIdentity(cfg, refValues); err != nil {
		return nil, err
	}
	measurements, err := cmdsutil.LoadMeasurements(cfg.measurements, cfg.measurementsFile)
	if err != nil {
		return nil, err
	}

	// --served-policy-file supplies the served-set equality check's expected
	// set: the node identities the target admits, which are not its own.
	var served *refvalues.ReferenceValues
	if cfg.servedPolicyFile != "" {
		values, err := refvalues.Load(cfg.servedPolicyFile)
		if err != nil {
			return nil, fmt.Errorf("--served-policy-file: %w", err)
		}
		served = &values
	}

	// --image-manifest carries MRTD in the same tuple as RTMR[1]/[2]. It is
	// deliberately NOT unioned into the --measurements allowlist: an allowlist
	// is satisfied by ANY member, so a launch digest from some other pinned
	// build would pass while RTMR[1]/[2] were pinned against this manifest,
	// splitting the atomic tuple. MRTD is instead compared exactly (see
	// newOutcome).
	pins, err := resolveAndCheckRTMRPins(cfg)
	if err != nil {
		return nil, err
	}
	// In the attested modes --operator-keys pins the published route manifest,
	// which parseRouteCheck reads below.
	var operatorKeysDigest []byte
	if !attestedMode(cfg) {
		operatorKeysDigest, err = expectedOperatorKeysDigest(cfg)
		if err != nil {
			return nil, err
		}
	}

	var caPool *x509.CertPool
	if cfg.meshCA != "" {
		caPool, err = meshCAPool(cfg.meshCA)
		if err != nil {
			return nil, err
		}
	}

	if cfg.sandboxID != "" {
		if err := armtls.ValidateSandboxID(cfg.sandboxID); err != nil {
			return nil, fmt.Errorf("--sandbox-id: %w", err)
		}
		if cfg.meshCA == "" {
			// The ID lives in the leaf's signed area, not in REPORTDATA, so
			// only the mesh CA signature authenticates it. Pinning without
			// checking that signature would pin a string the presenter chose.
			return nil, fmt.Errorf("--sandbox-id requires --mesh-ca: the sandbox ID is vouched by CDS's signature on the leaf, not by the hardware evidence")
		}
	}

	if cfg.clientDocument != "" && cfg.meshCA == "" {
		return nil, fmt.Errorf("--client-document requires --mesh-ca: the client document digest is vouched by CDS's signature on the leaf, not by the hardware evidence")
	}

	// The matched-workload stamp is CA-vouched exactly like the sandbox ID, so
	// both workload-policy flags demand the chain check that authenticates it.
	if cfg.workload != "" {
		if !workloadname.Valid(cfg.workload) {
			return nil, fmt.Errorf("--workload: %q is not a valid workload entry name (1..%d bytes, [A-Za-z0-9][A-Za-z0-9._-]*)", cfg.workload, workloadname.MaxLen)
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

	trustKeys, err := checkHistoryFlags(cfg, refValues.Images)
	if err != nil {
		return nil, err
	}

	initDataHash, err := parseInitDataPin(cfg.initDataHex)
	if err != nil {
		return nil, err
	}
	routes, err := parseRouteCheck(cfg)
	if err != nil {
		return nil, err
	}

	return &verifyPlan{
		// RTMRs is still set: it is what enforces the pin if this policy is
		// ever verified through the delegated attestation-api path. It is not
		// what enforces it today — see rtmrPins.manual.
		policy: &armtls.VerifyPolicy{Policy: remote.Policy{
			Images:       refValues.Images,
			Measurements: measurements,
			Registers:    pins.manual,
			AllowDebug:   cfg.allowDebug,
		}},
		pins:               pins,
		meshCA:             caPool,
		initDataHash:       initDataHash,
		refValues:          refValues,
		served:             served,
		routes:             routes,
		trustKeys:          trustKeys,
		operatorKeysDigest: operatorKeysDigest,
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
// All of them are enforced in one place — enforceRTMRPins, against the verified
// claims — so a pin cannot be accepted by the CLI and then enforced by nobody.
// buildPolicy still refuses --rtmr together with --image-manifest, because the
// two would otherwise pin RTMR[1]/[2] from different sources and a
// disagreement is a policy no guest can satisfy.
type rtmrPins struct {
	image runtimemeasure.ImageIdentity
	rtmr3 []byte
	// anchor is the --operator-pkey PEM rtmr3 was seeded from, nil otherwise.
	// Only with it can RTMR[3] be replayed as the seed followed by measured
	// policies.
	anchor []byte
	// manual holds --rtmr <index>=<hex>. It is enforced here, next to the
	// other two, rather than left to armtls.VerifyPolicy.Policy.RTMRs: that field is
	// read only by attestation-go/remote, on the delegated attestation-api
	// path, and `c8s verify` always verifies in process (verifyInProcess ->
	// localverify.Verify, whose Params carries no registers). Setting the
	// policy field alone made the flag a silent no-op.
	manual map[int][]byte
}

func (p rtmrPins) any() bool {
	return p.image != nil || p.rtmr3 != nil || len(p.manual) > 0
}

// requireCDSIdentity holds a kind=cds target to the identity of one CDS VM: a
// pin document binding every entry to the launch file that CDS runs on. A
// launch digest, with or without registers, names the CDS image, which says
// nothing about the cluster the VM serves.
func requireCDSIdentity(cfg config, refValues refvalues.ReferenceValues) error {
	if cfg.kind != "cds" {
		return nil
	}
	if len(cfg.measurements) > 0 || cfg.measurementsFile != "" {
		return fmt.Errorf("%s cannot pin a CDS, which is pinned to the configuration it runs on: pass --image-policy-file <cds-pin.json>", allowlistFlagsUsed(cfg))
	}
	if cfg.imageManifest != "" {
		return fmt.Errorf("--image-manifest cannot pin a CDS, which is pinned to the configuration it runs on: pass --image-policy-file <cds-pin.json>")
	}
	if _, err := cmdsutil.CDSLaunchFile(refValues); err != nil {
		return fmt.Errorf("--image-policy-file %w", err)
	}
	return nil
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

// refuseMeshLeafFlagsWithKindCDS refuses, under --kind cds, the flags that
// check a leaf the mesh CA issued: its chain and the stamps CDS signs into it.
func refuseMeshLeafFlagsWithKindCDS(cfg config) error {
	if cfg.kind != "cds" {
		return nil
	}
	var used []string
	if cfg.meshCA != "" {
		used = append(used, "--mesh-ca")
	}
	if cfg.sandboxID != "" {
		used = append(used, "--sandbox-id")
	}
	if cfg.workload != "" {
		used = append(used, "--workload")
	}
	if cfg.clientDocument != "" {
		used = append(used, "--client-document")
	}
	if cfg.allowlistFile != "" {
		used = append(used, "--allowlist")
	}
	if len(used) == 0 {
		return nil
	}
	return fmt.Errorf("a CDS target (--kind cds) takes no %s: its serving certificate is self-signed, so it chains to no mesh CA and carries no sandbox ID or workload stamp. These flags check the certificates CDS issues to --kind lb and --kind workload targets", strings.Join(used, ", "))
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

// resolveAndCheckRTMRPins parses --image-manifest and the RTMR[3] pin and
// applies the rules relating them: the pins it returns are checked, so no
// caller repeats them. Called exactly once, from buildPolicy, so a bad flag is
// a usage error and the manifest's three registers can never come from two
// different reads of the file.
func resolveAndCheckRTMRPins(cfg config) (rtmrPins, error) {
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
		// recomputed here: the initrd and internal/launchbinding both go
		// through runtimemeasure.Seed, and a second implementation of the same
		// arithmetic is a second thing to drift. It hashes the file bytes
		// verbatim — the check above only inspects them.
		seed := runtimemeasure.Seed(pubPEM)
		pins.rtmr3 = seed[:]
		pins.anchor = pubPEM
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
	// proof of identity while proving none, which is why the manifest is
	// mandatory.
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
