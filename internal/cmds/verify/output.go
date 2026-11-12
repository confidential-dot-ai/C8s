package verify

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

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
	// ServingLeafSHA256 is the unpadded base64url digest of the serving leaf
	// an attest-lb verdict was bound to, matching the receipt's
	// serving_leaf_sha256; a client compares it with the leaf it observed.
	ServingLeafSHA256 string `json:"serving_leaf_sha256,omitempty"`
	Pinned            bool   `json:"measurement_pinned"`
	Error             string `json:"error,omitempty"`

	// InitData is the init-data digest the verified evidence commits, and
	// InitDataNote says what stands behind it: compared against --init-data,
	// enforced as a launch-file pin, or reported unpinned.
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
	// self-signed, a verified issuing chain (--mesh-ca), or — on attest-pq —
	// the identity transcript the hardware evidence binds (whose chain anchor
	// is responder-chosen; see ChainAnchor). A leaf with none of these is not
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

	// ClientDocumentDigest is the hex client document digest on a Pod CVM's
	// leaf and AgentLabel the DNS label derived from it. CA-vouched like the
	// sandbox ID; ClientDocumentNote says what stands behind it.
	ClientDocumentDigest string `json:"client_document_digest,omitempty"`
	AgentLabel           string `json:"agent_label,omitempty"`
	ClientDocumentNote   string `json:"client_document_note,omitempty"`

	// RouteDigest is the hex route digest the attested transcript binds
	// (attest-pq and attest-lb only); RouteRevision is the published
	// manifest's revision when --operator-keys checked it, and RouteNote says
	// which check supplied the digest.
	RouteDigest   string `json:"route_digest,omitempty"`
	RouteRevision uint64 `json:"route_revision,omitempty"`
	RouteNote     string `json:"route_note,omitempty"`

	// MeasuredPolicies is the node's allowlist policy history from boot up to
	// the evidence's quote: the prefix of the evidence's measured list that
	// replays against RTMR[3] after the operator-key seed (--operator-pkey or
	// an anchored --image-policy-file image). --pin-policy and --trust-operator
	// failures land in Error (policy_history_absent,
	// policy_history_not_pinned, policy_history_unsigned).
	MeasuredPolicies []string `json:"measured_policies,omitempty"`

	// LeafStamped says whether the leaf carries a readable matched-workload
	// stamp, nil when the evidence carries no leaf. An unstamped leaf caps
	// --pin-policy and --trust-operator at partial. True does not mean the
	// stamp was authenticated: that takes --mesh-ca (see WorkloadNote).
	LeafStamped *bool `json:"leaf_stamped,omitempty"`
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
	hardware := oc.Backend != backendMeshChain
	if hardware {
		fmt.Fprintf(out, "  platform:     %s\n", oc.Platform)
		fmt.Fprintf(out, "  measurement:  %s\n", oc.Measurement)
	}
	for _, p := range oc.RTMRsPinned {
		idx, hexVal, _ := strings.Cut(p, ":")
		fmt.Fprintf(out, "  RTMR[%s]:      %s (matched)\n", idx, hexVal)
	}
	if len(oc.MeasuredPolicies) > 0 {
		fmt.Fprintf(out, "  history:      %s (enforced on this node from boot up to the evidence's quote, RTMR[3])\n", strings.Join(oc.MeasuredPolicies, ", "))
	}
	if oc.InitDataNote != "" {
		if oc.InitData != "" {
			fmt.Fprintf(out, "  init-data:    %s\n", oc.InitData)
			fmt.Fprintf(out, "                %s\n", oc.InitDataNote)
		} else {
			fmt.Fprintf(out, "  init-data:    %s\n", oc.InitDataNote)
		}
	}
	if hardware {
		fmt.Fprintf(out, "  TCB:          %s   debug=%t smt=%t\n", oc.CurrentTCB, oc.Debug, oc.SMT)
	}
	if oc.CertSHA256 != "" {
		fmt.Fprintf(out, "  cert sha256:  %s\n", oc.CertSHA256)
	}
	if oc.ServingLeafSHA256 != "" {
		fmt.Fprintf(out, "  serving leaf: sha256 %s\n", oc.ServingLeafSHA256)
	}
	if oc.CertBody != "" {
		fmt.Fprintf(out, "  cert body:    %s\n", oc.CertBody)
	}
	if oc.ChainAnchor != "" {
		fmt.Fprintf(out, "  chain anchor: %s\n", oc.ChainAnchor)
	}
	fmt.Fprintf(out, "  binding:      %s\n", oc.Binding)
	if oc.RouteDigest != "" {
		fmt.Fprintf(out, "  route digest: %s\n", oc.RouteDigest)
		if oc.RouteRevision != 0 {
			fmt.Fprintf(out, "  route rev:    %d\n", oc.RouteRevision)
		}
		fmt.Fprintf(out, "                %s\n", oc.RouteNote)
	}
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
	if oc.ClientDocumentDigest != "" {
		fmt.Fprintf(out, "  client doc:   sha256:%s  (agent label %s)\n", oc.ClientDocumentDigest, oc.AgentLabel)
		fmt.Fprintf(out, "                %s\n", oc.ClientDocumentNote)
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
	switch {
	case oc.Fresh:
	case oc.ServingLeafSHA256 != "":
		// A non-fresh attest-lb verdict comes from a saved receipt: the nonce is
		// bound, but the caller chose it.
		fmt.Fprintf(out, "  note:         freshness NOT proven (nonce was caller-chosen, not verifier-generated; the receipt may be stale)\n")
	default:
		fmt.Fprintf(out, "  note:         freshness NOT proven (no per-request nonce bound)\n")
	}
	if !oc.Pinned && hardware {
		fmt.Fprintf(out, "  WARNING:      no --measurements pinned — any genuine TEE is accepted (UNSAFE for production)\n")
	}
	if cfg.showEvidence {
		fmt.Fprintf(out, "  report_data:  %s\n", oc.ReportData)
	}
}
