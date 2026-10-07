package nriimagepolicy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

func validConfig() config {
	return config{
		Allowlist: allowlistConfig{
			Base: anyAllowlist(map[string]string{
				"sha256:0000000000000000000000000000000000000000000000000000000000000001": "test-installer",
			}),
			Pull: pullConfig{
				URL:               "https://127.0.0.1:30808",
				Timeout:           30 * time.Second,
				Interval:          30 * time.Second,
				AttestationApiURL: "http://localhost:30840",
			},
		},
		Policy: policyConfig{
			Mode: "fail-closed",
		},
	}
}

// baseYAML renders an allowlist.base config block: one any-argv entry.
func baseYAML(digest, image string) string {
	return fmt.Sprintf(`
  base:
    schema: c8s.allowlist/v1
    workloads:
      base-entry:
        label: %q
        containers:
          - digest: %q
            image: %q
            command: {policy: any}
            args: {policy: any}
`, image, digest, image)
}

func TestValidate_Valid(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_AuditMode(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.Mode = "audit"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_NoEnforcementMechanism(t *testing.T) {
	cfg := config{
		Policy: policyConfig{Mode: "fail-closed"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when neither allowlist nor label_rules configured")
	}
}

func TestValidate_ZeroTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.Timeout = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for zero timeout")
	}
}

func TestValidate_NegativeTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.Timeout = -1 * time.Second
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for negative timeout")
	}
}

func TestValidate_PullRequiresAttestationApi(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.AttestationApiURL = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when pull lacks attestation_api_url")
	}
}

func TestValidate_PullRejectsInvalidCDSMeasurement(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.CDSMeasurements = []string{"not-hex"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid CDS measurement")
	}
}

func TestValidate_PullRejectsPlaintextScheme(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.URL = "http://localhost:8080"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for plaintext http pull URL")
	}
}

func TestValidate_PullRejectsUnsupportedScheme(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.URL = "ftp://127.0.0.1/allowlist"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for unsupported pull URL scheme")
	}
}

func TestValidate_BaseRequiredWithPull(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Base = nil
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when pull is configured but the base allowlist is empty")
	}
}

// A malformed base allowlist fails at load: the digest type validates on
// decode, and the document's own validation catches a bad policy or schema.
func TestLoadConfig_RejectsMalformedBase(t *testing.T) {
	good := "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	for _, tc := range []struct {
		name string
		base string
	}{
		{"non-hex digest", baseYAML("sha256:not-hex", "installer")},
		{"non-sha256 digest", baseYAML("sha512:"+good[7:], "installer")},
		{"short digest", baseYAML(good[:len(good)-1], "installer")},
		{"unknown argv policy", strings.Replace(baseYAML(good, "installer"), "policy: any", "policy: anu", 1)},
		{"unknown schema", strings.Replace(baseYAML(good, "installer"), "c8s.allowlist/v1", "c8s.allowlist/v2", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "allowlist:" + tc.base + `
  pull:
    url: https://127.0.0.1:30808
    attestation_api_url: http://localhost:30840
`
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfig(path); err == nil {
				t.Fatalf("expected a load error for %s", tc.name)
			}
		})
	}
}

func TestValidate_InvalidMode(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.Mode = "permissive"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid policy mode")
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	yaml := "allowlist:" + baseYAML("sha256:0000000000000000000000000000000000000000000000000000000000000001", "installer") + `
  pull:
    url: https://127.0.0.1:30808
    attestation_api_url: http://localhost:30840
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Allowlist.Pull.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %s", cfg.Allowlist.Pull.Timeout)
	}
	if cfg.Allowlist.Pull.Interval != 5*time.Second {
		t.Errorf("expected default interval 5s, got %s", cfg.Allowlist.Pull.Interval)
	}
	if cfg.Policy.Mode != "fail-closed" {
		t.Errorf("expected default mode fail-closed, got %s", cfg.Policy.Mode)
	}
	if cfg.Containerd.Socket != "/run/containerd/containerd.sock" {
		t.Errorf("expected default socket, got %s", cfg.Containerd.Socket)
	}
}

// exempt_namespaces is parsed into the policy config alongside the snapshot
// path the plugin persists its captured digest set to.
func TestLoadConfig_ExemptNamespacesParsed(t *testing.T) {
	body := "allowlist:" + baseYAML("sha256:0000000000000000000000000000000000000000000000000000000000000001", "installer") + `
  pull:
    url: https://127.0.0.1:30808
    attestation_api_url: http://localhost:30840
policy:
  mode: fail-closed
  exempt_namespaces: [kube-system, local-path-storage]
  exempt_snapshot_path: /var/lib/nri-image-policy/exempt-snapshot.json
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got, want := cfg.Policy.ExemptNamespaces, []string{"kube-system", "local-path-storage"}; !slices.Equal(got, want) {
		t.Errorf("ExemptNamespaces = %v, want %v", got, want)
	}
	if cfg.Policy.ExemptSnapshotPath == "" {
		t.Error("ExemptSnapshotPath not parsed")
	}
}

// exempt_namespaces without a snapshot path is refused: the captured set must
// have somewhere to persist, or it would silently recapture (and on a reboot
// freeze empty) every restart.
func TestValidate_ExemptNamespacesRequireSnapshotPath(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.ExemptNamespaces = []string{"kube-system"}
	cfg.Policy.ExemptSnapshotPath = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when exempt_namespaces is set without exempt_snapshot_path")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(":::bad"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := loadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := loadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// --- AllowlistEnabled tests ---

func TestAllowlistEnabled_WithURL(t *testing.T) {
	cfg := validConfig()
	if !cfg.AllowlistEnabled() {
		t.Fatal("expected allowlist to be enabled")
	}
}

func TestAllowlistEnabled_WithoutURL(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.URL = ""
	cfg.Allowlist.Base = nil
	if cfg.AllowlistEnabled() {
		t.Fatal("expected allowlist to be disabled")
	}
}

// --- Label rules validation tests ---

func validLabelRule() labelRule {
	return labelRule{
		Name: "test-rule",
		MatchExpressions: []labelExpression{
			{Key: "tenant", Operator: "In", Values: []string{"acme"}},
		},
	}
}

func TestValidate_LabelRulesOnly(t *testing.T) {
	cfg := config{
		Policy: policyConfig{
			Mode:       "fail-closed",
			LabelRules: []labelRule{validLabelRule()},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Policy.LabelRules[0].selector == nil {
		t.Fatal("expected label rule selector to be compiled during validation")
	}
	if !evaluateRule(cfg.Policy.LabelRules[0], map[string]string{"tenant": "acme"}) {
		t.Fatal("compiled selector should match valid labels")
	}
}

func TestValidate_WorkloadClaimsRequireAllowlist(t *testing.T) {
	cfg := config{
		Policy:         policyConfig{Mode: "fail-closed", LabelRules: []labelRule{validLabelRule()}},
		WorkloadClaims: workloadClaimsConfig{SocketDir: "/var/run/nri-image-policy"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error: label-rules-only config never records for the inventory")
	}
}

func TestValidate_WorkloadClaimsWithAllowlist(t *testing.T) {
	cfg := validConfig()
	cfg.WorkloadClaims.SocketDir = "/var/run/nri-image-policy"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_LabelRuleMissingName(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{MatchExpressions: []labelExpression{{Key: "x", Operator: "Exists"}}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing rule name")
	}
}

func TestValidate_LabelRuleDuplicateName(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{Name: "dup", MatchExpressions: []labelExpression{{Key: "x", Operator: "Exists"}}},
		{Name: "dup", MatchExpressions: []labelExpression{{Key: "y", Operator: "Exists"}}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for duplicate rule name")
	}
}

func TestValidate_LabelRuleNoExpressions(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{Name: "empty", MatchExpressions: []labelExpression{}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty match_expressions")
	}
}

func TestValidate_LabelRuleInvalidOperator(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{Name: "test", MatchExpressions: []labelExpression{
			{Key: "x", Operator: "Equals", Values: []string{"y"}},
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid operator")
	}
}

func TestValidate_LabelRuleInRequiresValues(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{Name: "test", MatchExpressions: []labelExpression{
			{Key: "x", Operator: "In"},
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for In without values")
	}
}

func TestValidate_LabelRuleExistsMustNotHaveValues(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{Name: "test", MatchExpressions: []labelExpression{
			{Key: "x", Operator: "Exists", Values: []string{"y"}},
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for Exists with values")
	}
}

func TestValidate_LabelRuleExpressionMissingKey(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{Name: "test", MatchExpressions: []labelExpression{
			{Operator: "Exists"},
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestValidate_LabelRuleRejectsInvalidKubernetesLabelValue(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{Name: "test", MatchExpressions: []labelExpression{
			{Key: "tenant", Operator: "In", Values: []string{"not valid"}},
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected Kubernetes label selector validation to reject invalid value")
	}
}

// The chart's rendered boot config points attestation_api_url at the
// attest-proxy's node-local socket; pin that exact string loading through
// validation and driving the evidence client over a real socket (the
// construction path main.go uses for the CDS pull handshake).
func TestLoadConfig_UnixAttestationAPIURL(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "attestation-api.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/attest", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"platform":"snp","evidence":{}}`))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	yaml := "allowlist:" + baseYAML("sha256:0000000000000000000000000000000000000000000000000000000000000001", "installer") + `
  pull:
    url: https://127.0.0.1:30808
    attestation_api_url: unix://` + sock + `
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unix attestation_api_url must load and validate: %v", err)
	}
	resp, err := attestclient.NewClient("").GenerateEvidenceContext(
		context.Background(), cfg.Allowlist.Pull.AttestationApiURL, make([]byte, 48))
	if err != nil {
		t.Fatalf("evidence request over the configured unix socket: %v", err)
	}
	if resp.Platform != "snp" {
		t.Fatalf("evidence platform = %q, want snp (fake upstream)", resp.Platform)
	}
}

func TestLoadConfig_WithLabelRules(t *testing.T) {
	yaml := "allowlist:" + baseYAML("sha256:0000000000000000000000000000000000000000000000000000000000000001", "installer") + `
  pull:
    url: https://127.0.0.1:30808
    attestation_api_url: http://localhost:30840
policy:
  label_rules:
    - name: allowed-tenants
      match_expressions:
        - key: tenant
          operator: In
          values: [acme, beta]
    - name: must-have-team
      match_expressions:
        - key: team
          operator: Exists
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Policy.LabelRules) != 2 {
		t.Fatalf("expected 2 label rules, got %d", len(cfg.Policy.LabelRules))
	}
	if cfg.Policy.LabelRules[0].Name != "allowed-tenants" {
		t.Errorf("expected first rule name 'allowed-tenants', got %s", cfg.Policy.LabelRules[0].Name)
	}
	if cfg.Policy.LabelRules[0].MatchExpressions[0].Operator != "In" {
		t.Errorf("expected operator 'In', got %s", cfg.Policy.LabelRules[0].MatchExpressions[0].Operator)
	}
	if len(cfg.Policy.LabelRules[0].MatchExpressions[0].Values) != 2 {
		t.Errorf("expected 2 values, got %d", len(cfg.Policy.LabelRules[0].MatchExpressions[0].Values))
	}
}

func TestLoadConfig_LabelRulesOnly(t *testing.T) {
	yaml := `
policy:
  label_rules:
    - name: require-tenant
      match_expressions:
        - key: tenant
          operator: Exists
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.AllowlistEnabled() {
		t.Fatal("expected allowlist to be disabled")
	}
	if len(cfg.Policy.LabelRules) != 1 {
		t.Fatalf("expected 1 label rule, got %d", len(cfg.Policy.LabelRules))
	}
}

func TestLabelOperator(t *testing.T) {
	for _, op := range []string{OpIn, OpNotIn, OpExists, OpDoesNotExist} {
		if _, err := labelOperator(op); err != nil {
			t.Errorf("labelOperator(%q) returned error: %v", op, err)
		}
	}
	if _, err := labelOperator("Bogus"); err == nil {
		t.Fatal("expected error for unknown operator")
	}
}

// The sandbox-digests endpoint types its armTLS identity with this platform and
// CDS refuses a peer whose type disagrees with the evidence envelope the
// attestation-api returns. Hardcoding it to snp denied every sandbox token on a
// TDX node, and the resulting error names the evidence platform rather than this
// setting, so the cause sits several hops from the symptom.
func TestConfigPlatform(t *testing.T) {
	base := "allowlist:" + baseYAML(
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"example.com/img@sha256:0000000000000000000000000000000000000000000000000000000000000000")

	t.Run("defaults to snp so existing SNP deployments are unchanged", func(t *testing.T) {
		cfg := writeAndLoad(t, base)
		if got := cfg.NormalizedPlatform(); got != "sev-snp" {
			t.Errorf("NormalizedPlatform() = %q, want sev-snp", got)
		}
	})

	t.Run("tdx is carried through", func(t *testing.T) {
		cfg := writeAndLoad(t, "platform: tdx\n"+base)
		if got := cfg.NormalizedPlatform(); got != "tdx" {
			t.Errorf("NormalizedPlatform() = %q, want tdx", got)
		}
	})

	t.Run("az-tdx normalizes onto tdx, matching CDS", func(t *testing.T) {
		cfg := writeAndLoad(t, "platform: az-tdx\n"+base)
		if got := cfg.NormalizedPlatform(); got != "tdx" {
			t.Errorf("NormalizedPlatform() = %q, want tdx", got)
		}
	})

	t.Run("an unknown platform is refused at load", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(path, []byte("platform: nitro\n"+base), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadConfig(path)
		if err == nil {
			t.Fatal("loadConfig accepted an unsupported platform")
		}
		if !strings.Contains(err.Error(), "not a supported CPU TEE") {
			t.Errorf("error %q does not name the cause", err)
		}
	})
}

func writeAndLoad(t *testing.T, body string) *config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	return cfg
}

func TestValidateRejectsBadCDSRTMRs(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.CDSRTMRs = []string{"0=" + strings.Repeat("ab", 48)}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cds_rtmrs") {
		t.Fatalf("err = %v, want a cds_rtmrs parse failure", err)
	}
}

// A malformed RTMR pin fails the pull-client build rather than silently
// unpinning the registers.
func TestAllowlistPullHTTPClientRejectsBadRTMRs(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.CDSRTMRs = []string{"1=zz"}
	if _, err := allowlistPullHTTPClient(cfg.Allowlist.Pull, cfg.NormalizedPlatform()); err == nil || !strings.Contains(err.Error(), "--cds-rtmrs") {
		t.Fatalf("err = %v, want an RTMR parse failure", err)
	}
}
