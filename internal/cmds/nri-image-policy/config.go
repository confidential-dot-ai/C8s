package nriimagepolicy

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// config represents the plugin configuration.
type config struct {
	// Platform types the armTLS identity the sandbox-digests endpoint serves
	// to CDS, as an attestation-api platform string; empty means snp. It must
	// name the node's actual CPU TEE — CDS fails closed when the certificate's
	// TEE type and the evidence envelope's platform disagree.
	Platform       string               `yaml:"platform"`
	Plugin         pluginConfig         `yaml:"plugin"`
	Allowlist      allowlistConfig      `yaml:"allowlist"`
	Containerd     containerdConfig     `yaml:"containerd"`
	Policy         policyConfig         `yaml:"policy"`
	Logging        loggingConfig        `yaml:"logging"`
	WorkloadClaims workloadClaimsConfig `yaml:"workload_claims"`
	// Mesh is the trusted mesh policy (roles.go); required.
	Mesh *meshPolicy `yaml:"mesh"`
	Measure        measureConfig        `yaml:"measure"`
}

// measureConfig extends each started workload's image digest into RTMR[3]
// (pod-role CVMs only; set by node-services prepare). The register already
// holds the seed of the operator key the initrd staged, so the journal opens
// seeded with it.
type measureConfig struct {
	RTMR3       bool   `yaml:"rtmr3"`
	JournalPath string `yaml:"journal_path"`
}

// pluginConfig contains plugin runtime settings.
type pluginConfig struct {
	// HealthAddr is the listen address for the readiness/liveness HTTP
	// server. `host:port` selects TCP; `unix:///path/to.sock` selects a
	// Unix socket. GET /healthz answers 200 once the first pull applied and
	// 503 before, with a JSON body carrying the applied allowlist version.
	HealthAddr string `yaml:"health_addr"`
}

// workloadClaimsConfig configures the node-CVM admission inventory
// (docs/armtls.md).
type workloadClaimsConfig struct {
	// SocketDir is the host directory the inventory creates its socket in (as the
	// compiled workloadclaims.SocketName); the plugin NRI-mounts it into c8s-cert
	// sidecars so get-cert can fetch its pod's digests. The filename is fixed
	// so get-cert can bake the dial path — see workloadclaims.InventoryEndpoint.
	// The attestation-api and volumed sockets live in the same directory, so
	// sidecar reachability of all three rides this setting.
	SocketDir string `yaml:"socket_dir"`
	// ProcRoot is the /proc mount used to resolve a caller PID to its
	// container cgroup. Defaults to "/proc".
	ProcRoot string `yaml:"proc_root"`
	// AdvertiseHost is the node address CDS dials to reach this inventory's
	// digests endpoint. Empty reads it from NodeIPFile.
	AdvertiseHost string `yaml:"advertise_host"`
	// PublishNodeIP makes the plugin write NodeIPFile at startup from the
	// node's own view (see publishNodeIP). The chart sets it; the node image
	// leaves it unset because nri-node-ip.service writes the file there.
	PublishNodeIP bool `yaml:"publish_node_ip"`

	// CDSNodePort is the port an injected credential client reaches CDS on, at
	// this node's own address. A measured mesh policy binds that endpoint
	// itself, so only an install sets this (cdsaddress.go).
	CDSNodePort uint16 `yaml:"cds_node_port"`
}

// allowlistConfig groups the digest-source mechanisms.
//
// Base is a static baseline in the allowlist document format, admitted ahead
// of every pulled snapshot (CDS and operator digests). Installer and busybox
// invocations are admitted by argv-pinned entries in the served document.
// Base entries enforce env and mounts at final admission just like served
// entries. The chart's component entries pin each container's argv and mount
// table and leave env open; the node image's generated RKE2 system entries
// leave command and args open.
// Pull is the runtime-update source: every plugin polls CDS.
type allowlistConfig struct {
	Base *allowlist.Allowlist `yaml:"base"`
	// NodeTCB marks the base allowlist as this node's trusted computing base:
	// its digests are the only ones exempt from the sandbox policy
	// (policy.sandbox). Only a MEASURED boot config may set it — the chart
	// leaves it unset, because a chart-rendered base is chosen by the same
	// cluster admin the policy defends against. It is a boot-config key, not
	// an allowlist field: a CDS-served document has no way to express it.
	NodeTCB bool       `yaml:"node_tcb"`
	Pull    pullConfig `yaml:"pull"`
}

// pullConfig configures the CDS polling source.
type pullConfig struct {
	URL                   string        `yaml:"url"`                     // empty disables pull
	Interval              time.Duration `yaml:"interval"`                // ticker cadence; > 0 required when URL is set
	Timeout               time.Duration `yaml:"timeout"`                 // per-request timeout; > 0 required when URL is set
	AttestationApiURL     string        `yaml:"attestation_api_url"`     // required for https pull
	CDSMeasurements       []string      `yaml:"cds_measurements"`        // SHA-384 hex launch digests
	CDSRTMRs              []string      `yaml:"cds_rtmrs"`               // TDX RTMR pins <index>=<sha384-hex>
	CDSMeasurementsConfig string        `yaml:"cds_measurements_config"` // complete CDS image and operator identity policy
	// MeasurePolicies extends RTMR[3] (TDX) with each pulled policy before
	// applying it. Off by default: verifiers on attestation-go predating
	// runtime extensions, and flat RTMR[3] pins, still require the bare
	// operator-key seed.
	MeasurePolicies bool `yaml:"measure_policies"`
}

// checkPolicySources rejects competing CDS identity policy sources, before any
// I/O: config validation runs where the configured document need not exist yet.
func (c pullConfig) checkPolicySources() error {
	if c.CDSMeasurementsConfig != "" && (len(c.CDSMeasurements) != 0 || len(c.CDSRTMRs) != 0) {
		return fmt.Errorf("allowlist.pull.cds_measurements_config cannot be combined with cds_measurements or cds_rtmrs")
	}
	return nil
}

// policySet is the CDS identity set this node's own clients and its injected
// credential clients are held to, whichever form the config names it in.
func (c pullConfig) policySet(platform string) (refvalues.ReferenceValues, error) {
	if err := c.checkPolicySources(); err != nil {
		return refvalues.ReferenceValues{}, err
	}
	set, err := cmdsutil.LoadImagePolicySet(cmdsutil.ImagePolicyValuesConfig{
		Source: cmdsutil.ImagePolicySource{File: c.CDSMeasurementsConfig},
		Pins: cmdsutil.MeasurementPins{
			Measurements: c.CDSMeasurements,
			Registers:    c.CDSRTMRs,
			Prefix:       "cds-",
		},
		Platform:     platform,
		PlatformFlag: "platform",
	})
	if err != nil {
		return refvalues.ReferenceValues{}, fmt.Errorf("allowlist.pull: %w", err)
	}
	return set, nil
}

// containerdConfig contains containerd connection settings for tag-to-digest resolution.
type containerdConfig struct {
	Socket    string `yaml:"socket"`
	Namespace string `yaml:"namespace"`
}

// policyConfig contains policy enforcement settings.
type policyConfig struct {
	Mode                  string      `yaml:"mode"`                    // fail-closed, audit
	EnforceExisting       bool        `yaml:"enforce_existing"`        // kill non-allowlisted containers on startup
	DenyMissingAnnotation bool        `yaml:"deny_missing_annotation"` // deny containers without image annotation
	LabelRules            []labelRule `yaml:"label_rules"`

	// Sandbox is the host-privilege policy applied to every container the
	// base allowlist does not admit: enforce denies, audit records the
	// observation and admits, off does not observe. A parsed config defaults to
	// enforce; see sandbox.go and docs/allowlist-and-capabilities.md.
	Sandbox sandboxMode `yaml:"sandbox"`

	// ExemptNamespaces admits a namespace's containers by the digests captured
	// running in it at first admission, not by a name the control plane picks.
	// See exempt.go and docs/getcert-workload-binding.md — Corner 8.
	ExemptNamespaces []string `yaml:"exempt_namespaces"`
	// ExemptSnapshotPath persists the captured per-namespace digest set. Required
	// when ExemptNamespaces is set; must sit on a filesystem that survives reboot.
	ExemptSnapshotPath string `yaml:"exempt_snapshot_path"`

	// FatalExisting powers the node off when a container is already running at
	// the plugin's first registration after boot, or when the startup check
	// denies one on a plugin restart. For the measured node image, where the
	// plugin is pre-registered and containerd's required_plugins gate means no
	// container can legitimately predate it. See bootgate.go.
	FatalExisting bool `yaml:"fatal_existing"`
	// BootMarkerPath separates the first registration since boot from a plugin
	// restart. Must be on tmpfs: a marker that survived a reboot would read
	// every boot as a restart. Required when FatalExisting is set.
	BootMarkerPath string `yaml:"boot_marker_path"`
}

// labelRule defines a constraint on pod labels. Pods that do not satisfy
// all match expressions are denied.
type labelRule struct {
	Name             string            `yaml:"name"`
	MatchExpressions []labelExpression `yaml:"match_expressions"`
	selector         labels.Selector   `yaml:"-"`
}

// labelExpression is a single label selector requirement (Kubernetes-style).
type labelExpression struct {
	Key      string   `yaml:"key"`
	Operator string   `yaml:"operator"` // In, NotIn, Exists, DoesNotExist
	Values   []string `yaml:"values"`
}

// Label expression operators.
const (
	OpIn           = "In"
	OpNotIn        = "NotIn"
	OpExists       = "Exists"
	OpDoesNotExist = "DoesNotExist"
)

// Policy modes.
const (
	ModeFailClosed = "fail-closed"
	ModeAudit      = "audit"
)

// loggingConfig contains logging settings.
type loggingConfig struct {
	Level string `yaml:"level"`
	// Syslog is the syslog socket the plugin logs to, such as journald's
	// /dev/log. Empty logs to stdout, which containerd discards for a
	// pre-installed plugin: it starts one with its standard streams on
	// /dev/null.
	Syslog string `yaml:"syslog"`
}

const defaultPullInterval = 5 * time.Second
const defaultPullTimeout = 30 * time.Second

// NodeIPFile is the filename, inside SocketDir, holding this node's address:
// components read it as their attestation-api host (cmdsutil.NodeIPPath), so
// only a host process may write it, never a pod.
const NodeIPFile = "node-ip"

// DefaultConfigPath is the plugin config containerd's plugin_config_path
// resolves for this plugin, the file set-cds-pins patches, and the measured
// policy the node's runtime wrapper reads (internal/cmds/c8srunc).
const DefaultConfigPath = "/etc/nri/conf.d/image-policy.yaml"

// loadConfig loads configuration from a YAML file, and completes the one
// binding a launched node makes itself (cdsaddress.go).
func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	cfg, err := parseConfig(data)
	if err != nil {
		return nil, err
	}
	if err := bindCredentialRole(cfg); err != nil {
		return nil, fmt.Errorf("bind the %s role to the CDS this node reaches: %w", CredentialRole, err)
	}
	if err := cfg.validateMeshRoleBindings(); err != nil {
		return nil, fmt.Errorf("validate mesh role bindings: %w", err)
	}
	return cfg, nil
}

// parseConfig validates static configuration for the plugin and set-cds-pins.
// loadConfig completes runtime role bindings before validating them.
func parseConfig(data []byte) (*config, error) {
	cfg := &config{
		Allowlist: allowlistConfig{
			Pull: pullConfig{
				Interval: defaultPullInterval,
				Timeout:  defaultPullTimeout,
			},
		},
		Containerd: containerdConfig{
			Socket:    "/run/containerd/containerd.sock",
			Namespace: "k8s.io",
		},
		Policy: policyConfig{
			Mode:                  ModeFailClosed,
			EnforceExisting:       true,
			DenyMissingAnnotation: true,
			Sandbox:               SandboxEnforce,
		},
		Logging: loggingConfig{
			Level: "info",
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// The pin parsers take one spelling of a digest, and this file is
	// hand-editable: fold the case an operator typed rather than refusing a
	// config the node has been booting with.
	cfg.Allowlist.Pull.CDSMeasurements = foldHexPins(cfg.Allowlist.Pull.CDSMeasurements)
	cfg.Allowlist.Pull.CDSRTMRs = foldHexPins(cfg.Allowlist.Pull.CDSRTMRs)

	if cfg.Allowlist.Base != nil {
		if err := cfg.Allowlist.Base.Normalize(); err != nil {
			return nil, fmt.Errorf("allowlist.base: %w", err)
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// foldHexPins lowercases each pin, leaving blanks and the "<index>=" prefix of
// an RTMR pin untouched: both halves are hex or digits, which fold to
// themselves.
func foldHexPins(vals []string) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = strings.ToLower(v)
	}
	return out
}

// NormalizedPlatform folds the az-/gcp- variants onto the two TEE families the
// armTLS extension records, matching what CDS does with its own
// --armtls-platform. Defaulting here rather than in loadConfig keeps every
// construction path on the same value, including callers that build a config
// literal and validate it directly.
func (c *config) NormalizedPlatform() string {
	if strings.TrimSpace(c.Platform) == "" {
		return teetypes.FamilySNP.String()
	}
	family, err := teetypes.ParseFamily(c.Platform)
	if err != nil {
		// Validate reports it; return the input so its message can quote it.
		return c.Platform
	}
	return family.String()
}

// injectsCredentialClients reports whether a pod of this node carries the
// webhook's credential clients: the inventory directory is what the plugin
// mounts into them, and without it no pod of this node is injected.
func (c *config) injectsCredentialClients() bool {
	return c.WorkloadClaims.SocketDir != ""
}

// PullEnabled reports whether the plugin should poll a remote CDS.
func (c *config) PullEnabled() bool { return c.Allowlist.Pull.URL != "" }

// baseEnabled reports whether the base allowlist carries any workload.
func (c *config) baseEnabled() bool {
	return c.Allowlist.Base != nil && len(c.Allowlist.Base.Workloads) > 0
}

// sandboxMode is the effective host-privilege policy. Empty means the config
// was built in code rather than parsed (tests, callers constructing a literal),
// where the policy was never chosen: parseConfig defaults it to enforce.
func (c *config) sandboxMode() sandboxMode {
	if c.Policy.Sandbox == "" {
		return SandboxOff
	}
	return c.Policy.Sandbox
}

// sandboxObserved reports whether the host-privilege observation runs at all.
func (c *config) sandboxObserved() bool { return c.sandboxMode() != SandboxOff }

// AllowlistEnabled reports whether any digest-based enforcement is active.
func (c *config) AllowlistEnabled() bool {
	return c.PullEnabled() || c.baseEnabled()
}

// Validate checks the configuration for errors.
func (c *config) Validate() error {
	// Reject at load rather than at the first CDS handshake: a wrong platform
	// produces a peer-attestation failure on the CDS side that names the
	// evidence platform, not this setting, so the cause is several hops from
	// the symptom.
	if _, err := teetypes.ParseFamily(c.NormalizedPlatform()); err != nil {
		return fmt.Errorf("platform %q is not a supported CPU TEE (want snp or tdx)", c.Platform)
	}
	if c.Policy.FatalExisting {
		// Both couplings are what makes the setting mean anything: audit mode
		// reaches no deny branch, and without enforce_existing the startup
		// check never evaluates a running container.
		if c.Policy.Mode != ModeFailClosed {
			return fmt.Errorf("policy.fatal_existing requires policy.mode %q, got %q", ModeFailClosed, c.Policy.Mode)
		}
		if !c.Policy.EnforceExisting {
			return fmt.Errorf("policy.fatal_existing requires policy.enforce_existing")
		}
		if !strings.HasPrefix(c.Policy.BootMarkerPath, "/") {
			return fmt.Errorf("policy.boot_marker_path must be an absolute path on tmpfs when policy.fatal_existing is set, got %q", c.Policy.BootMarkerPath)
		}
	}
	if c.PullEnabled() && !c.baseEnabled() {
		return fmt.Errorf("allowlist.base must carry at least one workload when pull is configured (cold-boot baseline)")
	}
	if c.PullEnabled() {
		if err := c.Allowlist.Pull.checkPolicySources(); err != nil {
			return err
		}
		if c.Allowlist.Pull.Timeout <= 0 {
			return fmt.Errorf("allowlist.pull.timeout must be > 0 when pull.url is set")
		}
		if c.Allowlist.Pull.Interval <= 0 {
			return fmt.Errorf("allowlist.pull.interval must be > 0 when pull.url is set")
		}
		parsed, err := url.Parse(c.Allowlist.Pull.URL)
		if err != nil {
			return fmt.Errorf("allowlist.pull.url: %w", err)
		}
		// CDS serves armTLS only, so the pull URL must be https — a plaintext
		// pull would defeat the attestation handshake entirely.
		if parsed.Scheme != "https" {
			return fmt.Errorf("allowlist.pull.url scheme must be https, got %q", parsed.Scheme)
		}
		if c.Allowlist.Pull.AttestationApiURL == "" {
			return fmt.Errorf("allowlist.pull.attestation_api_url must be set")
		}
		if _, err := refvalues.ParseHexMeasurementsList(c.Allowlist.Pull.CDSMeasurements); err != nil {
			return fmt.Errorf("allowlist.pull.cds_measurements: %w", err)
		}
		if _, err := refvalues.ParseRegisterPins(c.Allowlist.Pull.CDSRTMRs); err != nil {
			return fmt.Errorf("allowlist.pull.cds_rtmrs: %w", err)
		}
	}
	if !c.AllowlistEnabled() && len(c.Policy.LabelRules) == 0 {
		return fmt.Errorf("set allowlist.base (required when pull is enabled) or configure policy.label_rules")
	}
	if c.Policy.Mode != ModeFailClosed && c.Policy.Mode != ModeAudit {
		return fmt.Errorf("policy.mode must be '%s' or '%s'", ModeFailClosed, ModeAudit)
	}
	switch c.Policy.Sandbox {
	case SandboxEnforce, SandboxAudit, SandboxOff:
	case "":
		c.Policy.Sandbox = SandboxEnforce
	default:
		return fmt.Errorf("policy.sandbox must be '%s', '%s' or '%s'", SandboxEnforce, SandboxAudit, SandboxOff)
	}
	// The marker grants the base an exemption, so an empty base makes it a
	// statement about nothing — and a config that carries it without one is
	// more likely a key in the wrong section than an intent.
	if c.Allowlist.NodeTCB && !c.baseEnabled() {
		return fmt.Errorf("allowlist.node_tcb needs a non-empty allowlist.base: it exempts the base's digests from the sandbox policy")
	}
	if c.WorkloadClaims.SocketDir != "" && !c.AllowlistEnabled() {
		return fmt.Errorf("workload_claims.socket_dir requires allowlist.base or allowlist.pull: the inventory reports digests for CDS to match against the allowlist")
	}
	if c.WorkloadClaims.PublishNodeIP && c.WorkloadClaims.SocketDir == "" {
		return fmt.Errorf("workload_claims.publish_node_ip requires workload_claims.socket_dir: the node-ip file lives there")
	}
	// Certificate producers read the journal only from the default runtime directory.
	journalDir := filepath.Dir(armtls.NodeJournal)
	if c.Allowlist.Pull.MeasurePolicies && !c.PullEnabled() {
		return fmt.Errorf("allowlist.pull.measure_policies requires allowlist.pull.url: only pulled policies are measured")
	}
	if c.Allowlist.Pull.MeasurePolicies && filepath.Clean(c.WorkloadClaims.SocketDir) != journalDir {
		return fmt.Errorf("allowlist.pull.measure_policies requires workload_claims.socket_dir %s (got %q): certificate producers read the measured-policy journal there", journalDir, c.WorkloadClaims.SocketDir)
	}
	if len(c.Policy.ExemptNamespaces) > 0 && c.Policy.ExemptSnapshotPath == "" {
		return fmt.Errorf("policy.exempt_namespaces requires policy.exempt_snapshot_path: the captured digest set must persist across restarts")
	}
	if err := c.validateMesh(); err != nil {
		return err
	}
	return validateLabelRules(c.Policy.LabelRules)
}

// validateMesh requires a mesh policy this node can enforce.
func (c *config) validateMesh() error {
	if c.Mesh == nil {
		return errors.New("mesh is required: the enforcer verifies a pod's protection before any workload identity assertion")
	}
	if err := c.Mesh.validate(); err != nil {
		return err
	}
	if c.requiresTrustedMeshEnforcement() && (c.Policy.Mode != ModeFailClosed || !c.Policy.FatalExisting) {
		return fmt.Errorf("mesh requires policy.mode %q and policy.fatal_existing: a member pod needs trusted enforcement from node startup", ModeFailClosed)
	}
	// A namespace the admission carve-out keeps running across an enforcer
	// restart holds pods the gate refuses for their life, so the mesh exempts it.
	for _, namespace := range c.Policy.ExemptNamespaces {
		if !slices.Contains(c.Mesh.ExemptNamespaces, namespace) {
			return fmt.Errorf("policy.exempt_namespaces %q must also be in mesh.exempt_namespaces: the gate refuses a pod that was running before this enforcer connected", namespace)
		}
	}
	return nil
}

func (c *config) validateMeshRoleBindings() error {
	if c.Allowlist.Base == nil {
		return nil
	}
	identities := c.Mesh.reservedIdentities()
	for name, workload := range c.Allowlist.Base.Workloads {
		for _, container := range workload.Containers {
			if container.Role == "" {
				continue
			}
			if _, bound := identities[container.Role]; !bound {
				return fmt.Errorf("allowlist.base workload %s role %s has no mesh identity binding", name, container.Role)
			}
		}
	}
	return nil
}

// requiresTrustedMeshEnforcement reports whether this node's mesh policy is
// one the cluster admin could not write. A config claiming the node TCB is
// measured with a baked image, and its members' protection rests on
// fail-closed admission and the boot gate; a chart-rendered config is an
// install, where the mesh runs for test clusters and the admin who wrote the
// policy could undo the enforcement anyway.
func (c *config) requiresTrustedMeshEnforcement() bool {
	return c.Allowlist.NodeTCB
}

// validateLabelRules checks label rules for errors.
func validateLabelRules(rules []labelRule) error {
	seen := make(map[string]bool, len(rules))
	for i := range rules {
		r := rules[i]
		if r.Name == "" {
			return fmt.Errorf("label_rules[%d]: name must be set", i)
		}
		if seen[r.Name] {
			return fmt.Errorf("label_rules[%d]: duplicate name %q", i, r.Name)
		}
		seen[r.Name] = true
		if len(r.MatchExpressions) == 0 {
			return fmt.Errorf("label_rules[%d] %q: at least one match_expression required", i, r.Name)
		}
		selector, err := buildLabelSelector(r)
		if err != nil {
			return fmt.Errorf("label_rules[%d] %q: %w", i, r.Name, err)
		}
		rules[i].selector = selector
	}
	return nil
}

func buildLabelSelector(rule labelRule) (labels.Selector, error) {
	selector := labels.NewSelector()
	for j, expr := range rule.MatchExpressions {
		if expr.Key == "" {
			return nil, fmt.Errorf("expression[%d]: key must be set", j)
		}
		op, err := labelOperator(expr.Operator)
		if err != nil {
			return nil, fmt.Errorf("expression[%d]: %w", j, err)
		}
		req, err := labels.NewRequirement(expr.Key, op, expr.Values)
		if err != nil {
			return nil, fmt.Errorf("expression[%d]: %w", j, err)
		}
		selector = selector.Add(*req)
	}
	return selector, nil
}

func labelOperator(op string) (selection.Operator, error) {
	switch op {
	case OpIn:
		return selection.In, nil
	case OpNotIn:
		return selection.NotIn, nil
	case OpExists:
		return selection.Exists, nil
	case OpDoesNotExist:
		return selection.DoesNotExist, nil
	default:
		return "", fmt.Errorf("operator must be %s, %s, %s, or %s", OpIn, OpNotIn, OpExists, OpDoesNotExist)
	}
}
