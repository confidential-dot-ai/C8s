package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// meshYAML is the mesh policy every enforcer configuration carries.
const meshYAML = `
mesh:
  exempt_namespaces: [kube-system, local-path-storage]
  resolver: "10.43.0.10"
  capture: {outbound: 15001, inbound: 15006, health: 15021}
  roles:
    - name: mesh
      uid: 1337
`

func validConfig() config {
	return config{
		Mesh: meshRoles(),
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

// The enforcer verifies a member pod's protection before the inventory signs
// its identity, so a configuration carrying no mesh policy starts none.
func TestValidate_MeshRequired(t *testing.T) {
	cfg := validConfig()
	cfg.Mesh = nil
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "mesh is required") {
		t.Fatalf("err = %v, want a config with no mesh policy refused", err)
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
` + meshYAML
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

// exempt_namespaces and its repository set reach the policy config.
func TestLoadConfig_ExemptNamespacesParsed(t *testing.T) {
	body := "allowlist:" + baseYAML("sha256:0000000000000000000000000000000000000000000000000000000000000001", "installer") + `
  pull:
    url: https://127.0.0.1:30808
    attestation_api_url: http://localhost:30840
policy:
  mode: fail-closed
  exempt_namespaces: [kube-system, local-path-storage]
  exempt_repositories:
    kube-system: [mcr.microsoft.com/oss/kubernetes/]
    local-path-storage: [docker.io/rancher/]
` + meshYAML
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
	if !cfg.Policy.ExemptRepositories.Admits("kube-system", "mcr.microsoft.com/oss/kubernetes/coredns:v1.11.3") {
		t.Errorf("exempt_repositories = %v, want kube-system to admit an AKS add-on image", cfg.Policy.ExemptRepositories)
	}
	if cfg.Policy.ExemptRepositories.Admits("kube-system", "docker.io/rancher/local-path-provisioner:v0.0.31") {
		t.Error("a repository of another namespace's set must not admit")
	}
}

// bootConfigDocument is an installer's configuration document: the namespaces
// image admission exempts, each admitting one repository, and the mesh gate's.
func bootConfigDocument(exempt, meshExempt string) string {
	repositories := ""
	for _, namespace := range strings.Split(strings.Trim(exempt, "[]"), ",") {
		repositories += fmt.Sprintf("    %s: [mcr.microsoft.com/oss/kubernetes/]\n", strings.TrimSpace(namespace))
	}
	return "allowlist:" + baseYAML("sha256:0000000000000000000000000000000000000000000000000000000000000001", "installer") + fmt.Sprintf(`
  pull:
    url: https://127.0.0.1:30808
    attestation_api_url: http://localhost:30840
policy:
  mode: fail-closed
  exempt_namespaces: %s
  exempt_repositories:
%smesh:
  exempt_namespaces: %s
  resolver: "10.43.0.10"
  capture: {outbound: 15001, inbound: 15006, health: 15021}
  roles:
    - name: mesh
      uid: 1337
`, exempt, repositories, meshExempt)
}

// CheckBootConfig is how a caller validates a config document before a node is
// made to require the plugin that reads it: the same keys and the same
// refusals the plugin applies at start.
func TestCheckBootConfig(t *testing.T) {
	for _, tc := range []struct {
		name, config, want string
	}{
		{
			"an exemption the mesh exempts too",
			bootConfigDocument("[kube-system]", "[kube-system, local-path-storage]"),
			"",
		},
		{
			"an exemption the mesh does not",
			bootConfigDocument("[kube-system]", "[local-path-storage]"),
			"must also be in mesh.exempt_namespaces",
		},
		{
			"the router namespace",
			bootConfigDocument("[kube-system]", "[kube-system, c8s-router]"),
			"whose pods serve the router's ports",
		},
		{
			"a misspelt key",
			strings.Replace(bootConfigDocument("[kube-system]", "[kube-system]"), "\n  mode: fail-closed\n", "\n  modes: fail-closed\n", 1),
			"field modes not found",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckBootConfig([]byte(tc.config))
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("CheckBootConfig = %v, want the config accepted", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("CheckBootConfig = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
}

// A config that names an exempt namespace without repositories, or holds a
// prefix admission could match half a path segment of, or wildcards anything
// but the start of its registry host, is refused.
func TestValidate_ExemptRepositories(t *testing.T) {
	for _, tc := range []struct {
		name         string
		namespaces   []string
		repositories ExemptRepositories
		want         string
	}{
		{
			"a repository set per exempt namespace",
			[]string{"kube-system"},
			ExemptRepositories{"kube-system": {"mcr.microsoft.com/oss/kubernetes/"}},
			"",
		},
		{
			"exempt namespaces without repositories",
			[]string{"kube-system"},
			nil,
			"requires policy.exempt_repositories",
		},
		{
			"one of two exempt namespaces without repositories",
			[]string{"kube-system", "gmp-system"},
			ExemptRepositories{"kube-system": {"mcr.microsoft.com/oss/kubernetes/"}},
			`policy.exempt_namespaces "gmp-system" requires`,
		},
		{
			"a prefix that does not end on a path boundary",
			[]string{"kube-system"},
			ExemptRepositories{"kube-system": {"mcr.microsoft.com/oss/kubernetes"}},
			`policy.exempt_repositories["kube-system"] holds "mcr.microsoft.com/oss/kubernetes"`,
		},
		{
			"a prefix without a registry",
			[]string{"kube-system"},
			ExemptRepositories{"kube-system": {"oss/kubernetes/"}},
			`policy.exempt_repositories["kube-system"] holds "oss/kubernetes/"`,
		},
		{
			"a wildcard opening the registry host's first label",
			[]string{"kube-system"},
			ExemptRepositories{"kube-system": {"*-artifactregistry.gcr.io/gke-release/gke-release/"}},
			"",
		},
		{
			"a wildcard outside the registry host's first label",
			[]string{"kube-system"},
			ExemptRepositories{"kube-system": {"gcr.io/*/gke-release/"}},
			`policy.exempt_repositories["kube-system"] holds "gcr.io/*/gke-release/"`,
		},
		{
			"a wildcard taking a whole host label",
			[]string{"kube-system"},
			ExemptRepositories{"kube-system": {"*artifactregistry.gcr.io/gke-release/"}},
			`policy.exempt_repositories["kube-system"] holds "*artifactregistry.gcr.io/gke-release/"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Policy.ExemptNamespaces = tc.namespaces
			cfg.Policy.ExemptRepositories = tc.repositories
			cfg.Mesh.ExemptNamespaces = tc.namespaces
			err := cfg.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("Validate = %v, want the config accepted", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("Validate = %v, want a refusal naming %q", err, tc.want)
			}
		})
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
		Mesh: meshRoles(),
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
		WorkloadClaims: workloadClaimsConfig{SocketDir: "/run/nri-image-policy"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error: label-rules-only config never records for the inventory")
	}
}

func TestValidate_WorkloadClaimsWithAllowlist(t *testing.T) {
	cfg := validConfig()
	cfg.WorkloadClaims.SocketDir = "/run/nri-image-policy"
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
` + meshYAML
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
` + meshYAML
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
` + meshYAML
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
		"example.com/img@sha256:0000000000000000000000000000000000000000000000000000000000000000") + meshYAML

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

// An unreadable pin document fails the node's pin source rather than
// silently unpinning CDS.
func TestTheNodePinSourceRejectsAnUnreadablePin(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.CDSMeasurementsConfig = "missing-file"
	if _, _, err := cfg.Allowlist.Pull.cdsPinSource(discardLogger()); err == nil {
		t.Fatal("an unreadable CDS pin was accepted")
	}
}

// podRoleConfig is a valid assigned pod-role configuration: the measured
// endpoint in the base, the pod's own mesh policy and no node exemptions.
func podRoleConfig(t *testing.T) config {
	t.Helper()
	cfg := validConfig()
	cfg.WorkloadClaims.SocketDir = "/run/nri-image-policy"
	cfg.Measure.RTMR3 = true
	cfg.Platform = "tdx"
	cfg.Allowlist.Pull.CDSMeasurementsConfig = "/run/c8s-launch/cds.json"
	cfg.Allowlist.Base = roleBase(t, pushDigestB, meshRole, []string{"/mesh"})
	cfg.Mesh.Pod = &podMeshPolicy{}
	cfg.Mesh.Roles = cfg.Mesh.Roles[:1]
	cfg.Mesh.ExemptNamespaces = nil
	cfg.Policy.ExemptNamespaces = nil
	cfg.Policy.Sandbox = SandboxEnforce
	cfg.Policy.FatalExisting = true
	cfg.Policy.EnforceExisting = true
	cfg.Policy.BootMarkerPath = "/run/nri-image-policy/registered"
	cfg.Pod = &podConfig{UID: "assigned", Namespace: "tenant", Name: "app", Images: map[string]string{workloadclaims.MeshContainerName: pushDigestB, "app": pushDigestA}}
	return cfg
}

// A signed peer or ingress port the guest ruleset would refuse fails at load,
// not at the first sandbox.
func TestPodRoleRefusesTuplesTheGuestRulesetWouldRefuse(t *testing.T) {
	for _, tc := range []struct {
		name string
		pod  podMeshPolicy
		want string
	}{
		{"zero ingress port", podMeshPolicy{IngressPorts: []uint16{0}}, "mesh.pod.ingress_ports"},
		{"mesh ingress port", podMeshPolicy{IngressPorts: []uint16{uint16(workloadclaims.MeshInboundPort)}}, "mesh.pod.ingress_ports"},
		{"local peer", podMeshPolicy{Peers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:443")}}, "mesh.pod.peers"},
		{"peer without port", podMeshPolicy{Peers: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.9:0")}}, "mesh.pod.peers"},
	} {
		cfg := podRoleConfig(t)
		cfg.Mesh.Pod = &tc.pod
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
	cfg := podRoleConfig(t)
	cfg.Mesh.Pod = &podMeshPolicy{Peers: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.9:443")}, IngressPorts: []uint16{8080}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid tuples refused: %v", err)
	}
}

// The register has no writer besides the plugin's measured launches;
// The journal lives where its readers look.
func TestPodRoleRefusesMeasurePolicies(t *testing.T) {
	cfg := podRoleConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("one writer: %v", err)
	}
	cfg.Allowlist.Pull.MeasurePolicies = true
	if err := cfg.Validate(); !errors.Is(err, ErrPodRoleMeasurePolicies) {
		t.Fatalf("got %v, want ErrPodRoleMeasurePolicies", err)
	}
	cfg.Allowlist.Pull.MeasurePolicies = false
	cfg.WorkloadClaims.SocketDir = "/run/elsewhere"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "measure.rtmr3 requires workload_claims.socket_dir /run/nri-image-policy") {
		t.Fatalf("journal elsewhere than its readers look: %v", err)
	}
}

func TestPodRoleConfigRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*config)
		want   string
	}{
		{"worker", func(c *config) { c.Worker = true }, "not a worker"},
		{"no pod", func(c *config) { c.Pod = nil }, "measure.rtmr3 and the signed pod"},
		{"no pod mesh policy", func(c *config) { c.Mesh.Pod = nil }, "measure.rtmr3 and the signed pod"},
		{"SNP", func(c *config) { c.Platform = "snp" }, "requires TDX"},
		{"audit sandbox", func(c *config) { c.Policy.Sandbox = SandboxAudit }, "requires TDX"},
		{"mesh exemption", func(c *config) { c.Mesh.ExemptNamespaces = []string{"kube-system"} }, "no namespace exemptions"},
		{"router namespace", func(c *config) { c.Pod.Namespace = routerNamespace }, "no namespace exemptions"},
		{"credential port", func(c *config) { c.Mesh.CredentialAttestationPort = 9000 }, "only the mesh role"},
		{"no pod UID", func(c *config) { c.Pod.UID = "" }, "signed pod uid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := podRoleConfig(t)
			tc.change(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidate_PullSourceRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*config)
		want   string
	}{
		{"URL and address file", func(c *config) { c.Allowlist.Pull.CDSAddressFile = "/run/cds-address" }, "cannot be combined"},
		{"zero interval", func(c *config) { c.Allowlist.Pull.Interval = 0 }, "allowlist.pull.interval"},
		{"node IP without socket dir", func(c *config) {
			c.WorkloadClaims.PublishNodeIP = true
			c.WorkloadClaims.SocketDir = ""
		}, "publish_node_ip requires workload_claims.socket_dir"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.change(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// A node that keeps nothing under /etc holds the config beside the binary.
func TestStartupConfigPath(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "nri", "10-nri-image-policy")
	installed := InstalledConfigPath(exe)
	if want := filepath.Join(root, "nri", "conf.d", "image-policy.yaml"); installed != want {
		t.Errorf("InstalledConfigPath = %q, want %q", installed, want)
	}
	if got := startupConfigPath(exe); got != DefaultConfigPath {
		t.Errorf("with no installed config: startupConfigPath = %q, want %q", got, DefaultConfigPath)
	}
	if err := os.MkdirAll(filepath.Dir(installed), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := startupConfigPath(exe); got != installed {
		t.Errorf("startupConfigPath = %q, want the installed %q", got, installed)
	}
}
