package credrelease

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	rbacv1 "k8s.io/api/rbac/v1"
	sigsyaml "sigs.k8s.io/yaml"
)

// The node image bakes each issued identity twice: the unit spells out the
// cert flags, and an RKE2 AddOn binds that group to its ClusterRole. Nothing
// else ties the files to this package, so load them here and check they agree
// with each other and with the binary's defaults (which cmd_test.go pins to
// literals). The operator role is bounded on purpose: the baked guards exist
// to hold against the credential holder, so the role must not reach RBAC,
// admission, the privileged namespaces, or the kubelet.
const (
	nodeImageCredReleaseService = "../../../images/node-guest/c8s/mkosi.extra/etc/systemd/system/cred-release.service"
	nodeImageCredReleaseDropIns = nodeImageCredReleaseService + ".d/*.conf"
	nodeImageCredReleaseRBAC    = "../../../images/node-guest/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/cred-release-rbac.yaml"
	nodeImagePSAReadyScript     = "../../../images/node-guest/c8s/mkosi.extra/usr/local/bin/psa-ready.sh"
	nodeImageLogReaderRBAC      = "../../../images/node-guest/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/log-reader-rbac.yaml"
	nodeImageSync               = "../../../images/node-guest/c8s/mkosi.sync"
)

func TestNodeImageCredentialReleaseConfiguration(t *testing.T) {
	unit, err := os.ReadFile(filepath.Clean(nodeImageCredReleaseService))
	if err != nil {
		t.Fatalf("read node-image credential-release service: %v", err)
	}
	// systemd continues a line only on a bare trailing backslash; one followed
	// by whitespace makes the next line a bogus directive and the unit fails
	// to load. Reject it here rather than letting the truncated ExecStart
	// parse to the binary defaults below.
	if regexp.MustCompile(`\\[ \t]+\n`).Match(unit) {
		t.Fatal("cred-release.service has a backslash followed by whitespace: not a systemd continuation")
	}
	// Join continuation lines, then take the single ExecStart.
	joined := strings.ReplaceAll(string(unit), "\\\n", " ")
	if n := strings.Count(joined, "\nExecStartPre="); n != 1 {
		t.Fatalf("ExecStartPre directive count = %d, want exactly 1", n)
	}
	if !strings.Contains(joined, "\nExecStartPre=/usr/local/bin/psa-ready.sh\n") {
		t.Fatal("cred-release.service must gate startup on /usr/local/bin/psa-ready.sh")
	}
	if n := strings.Count(joined, "\nExecStart="); n != 1 {
		t.Fatalf("ExecStart directive count = %d, want exactly 1", n)
	}
	_, rest, _ := strings.Cut(joined, "\nExecStart=")
	execStart, _, _ := strings.Cut(rest, "\n")
	args := strings.Fields(execStart)
	if len(args) < 2 || args[0] != "/usr/local/bin/c8s" || args[1] != "cred-release" {
		t.Fatalf("ExecStart = %q, want /usr/local/bin/c8s cred-release ...", execStart)
	}
	// The unit spells the identity out (see its comment); a missing flag here
	// would otherwise pass silently on the binary defaults. And the only
	// environment expansion is the platform: anything else would let a
	// drop-in's Environment= rewrite the identity out of sight of this test.
	for _, flag := range []string{"--cert-ttl", "--cert-org", "--cert-cn", "--log-cert-ttl", "--log-cert-org", "--log-cert-cn"} {
		if !slices.Contains(args, flag) {
			t.Errorf("ExecStart does not spell out %s", flag)
		}
	}
	for _, arg := range args {
		if strings.Contains(arg, "$") && arg != "--platform=${CRED_PLATFORM}" {
			t.Errorf("ExecStart argument %q expands the environment", arg)
		}
	}
	// Drop-ins can reset ExecStart or inject environment; mkosi.sync renders
	// one with only Environment=CRED_PLATFORM, so any baked drop-in that
	// touches Exec*/Environment* is an override this test would not see.
	dropIns, err := filepath.Glob(nodeImageCredReleaseDropIns)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range dropIns {
		conf, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.SplitSeq(string(conf), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Exec") || strings.HasPrefix(line, "Environment") {
				t.Errorf("%s overrides the unit: %q", path, line)
			}
		}
	}

	// Parse the baked flags with the real command so the test sees exactly
	// what the binary sees (last-wins duplicates, --flag=value forms, ...).
	flags := NewCmd().Flags()
	if err := flags.Parse(args[2:]); err != nil {
		t.Fatalf("parse baked ExecStart flags: %v", err)
	}
	org, _ := flags.GetString("cert-org")
	cn, _ := flags.GetString("cert-cn")
	ttl, _ := flags.GetDuration("cert-ttl")
	if org != defaultCertOrg || cn != defaultCertCN || ttl != defaultCertTTL {
		t.Errorf("baked identity = O=%s CN=%s ttl=%v, want the binary defaults O=%s CN=%s ttl=%v",
			org, cn, ttl, defaultCertOrg, defaultCertCN, defaultCertTTL)
	}
	logOrg, _ := flags.GetString("log-cert-org")
	logCN, _ := flags.GetString("log-cert-cn")
	logTTL, _ := flags.GetDuration("log-cert-ttl")
	if logOrg != defaultLogCertOrg || logCN != defaultLogCertCN || logTTL != defaultLogCertTTL {
		t.Errorf("baked log-reader identity = O=%s CN=%s ttl=%v, want the binary defaults O=%s CN=%s ttl=%v",
			logOrg, logCN, logTTL, defaultLogCertOrg, defaultLogCertCN, defaultLogCertTTL)
	}
	if logOrg == org || logCN == cn {
		t.Errorf("log-reader identity O=%s CN=%s collides with the operator's O=%s CN=%s", logOrg, logCN, org, cn)
	}
	// system:* groups are apiserver-reserved; system:masters in particular
	// bypasses RBAC and cannot be revoked.
	for _, g := range []string{org, logOrg} {
		if strings.HasPrefix(g, "system:") {
			t.Errorf("baked group %q is an apiserver-reserved group", g)
		}
	}

	operatorRole, binding := readRoleAndBinding(t, nodeImageCredReleaseRBAC)
	gate, err := os.ReadFile(filepath.Clean(nodeImagePSAReadyScript))
	if err != nil {
		t.Fatalf("read node-image PodSecurity readiness gate: %v", err)
	}
	gateInfo, err := os.Stat(filepath.Clean(nodeImagePSAReadyScript))
	if err != nil {
		t.Fatalf("stat node-image PodSecurity readiness gate: %v", err)
	}
	if gateInfo.Mode().Perm()&0o111 == 0 {
		t.Error("psa-ready.sh is not executable")
	}
	// The production gate waits for every guard mkosi.sync stages as a
	// reference copy (GUARDS=), including the two RBAC AddOns, then exercises
	// the real admission chain: PodSecurity as a non-granter, the operator
	// scope as the baked --cert-org group. images/node-guest/tests/psa-ready-test.sh
	// executes this exact script and proves these are behavior, not inert
	// strings; the policies' shapes and expressions are tested in
	// internal/helmchart.
	gateText := string(gate)
	for _, want := range []string{
		"GUARDS_DIR=${GUARDS_DIR:-/usr/lib/confai/guards}",
		"replace --dry-run=server -f \"$file\"",
		"get -f \"$file\"",
		"--as=\"$probe_user\" create --dry-run=server",
		"probe_namespace restricted",
		"probe_namespace privileged",
		"pod-security.kubernetes.io/enforce may not be set below restricted",
		"operator_group=" + org,
		"--as-group=\"$operator_group\"",
		"probe_scope default",
		"probe_scope kube-system",
		"may not write in the privileged namespaces",
	} {
		if !strings.Contains(gateText, want) {
			t.Errorf("psa-ready.sh does not contain required gate %q", want)
		}
	}
	sync, err := os.ReadFile(filepath.Clean(nodeImageSync))
	if err != nil {
		t.Fatalf("read node-image mkosi.sync: %v", err)
	}
	guards := regexp.MustCompile(`(?m)^GUARDS="(.*)"$`).FindStringSubmatch(string(sync))
	if guards == nil {
		t.Fatal("mkosi.sync does not define GUARDS=, the guard AddOns psa-ready.sh waits for")
	}
	for _, rbac := range []string{nodeImageCredReleaseRBAC, nodeImageLogReaderRBAC} {
		if name := strings.TrimSuffix(filepath.Base(rbac), ".yaml"); !slices.Contains(strings.Fields(guards[1]), name) {
			t.Errorf("mkosi.sync GUARDS= does not stage %s, so psa-ready.sh would not wait for its binding before serving", name)
		}
	}
	// The operator is bound to the baked bounded role, never to cluster-admin
	// (which could delete every guard) and never to a role that reaches them.
	wantRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: operatorRole.Name}
	if binding.RoleRef != wantRef || operatorRole.Name == "cluster-admin" || operatorRole.Name == "" {
		t.Errorf("roleRef = %+v, want the bounded ClusterRole %q from the same AddOn", binding.RoleRef, operatorRole.Name)
	}
	wantSubjects := []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: org}}
	if len(binding.Subjects) != 1 || binding.Subjects[0] != wantSubjects[0] {
		t.Errorf("subjects = %+v, want %+v (the baked --cert-org group)", binding.Subjects, wantSubjects)
	}
	if operatorRole.AggregationRule != nil {
		t.Error("operator ClusterRole must not aggregate: its rules must be exactly what this file says")
	}
	checkGuardedRules(t, "operator", operatorRole.Rules, operatorGuard)

	// The log-reader AddOn: exactly a ClusterRole and a ClusterRoleBinding
	// that grants the baked --log-cert-org group that role, and the role
	// reads pods and their logs but nothing that carries secrets or lets the
	// holder run code.
	logRole, logBinding := readRoleAndBinding(t, nodeImageLogReaderRBAC)
	if logBinding.RoleRef != (rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: logRole.Name}) {
		t.Errorf("log-reader roleRef = %+v, want the ClusterRole %q from the same AddOn", logBinding.RoleRef, logRole.Name)
	}
	wantLogSubjects := []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: logOrg}}
	if len(logBinding.Subjects) != 1 || logBinding.Subjects[0] != wantLogSubjects[0] {
		t.Errorf("log-reader subjects = %+v, want %+v (the baked --log-cert-org group)", logBinding.Subjects, wantLogSubjects)
	}
	checkGuardedRules(t, "log-reader", logRole.Rules, logReaderGuard)
	var grantsLogs bool
	for _, rule := range logRole.Rules {
		if slices.Contains(rule.Resources, "pods/log") && slices.Contains(rule.Verbs, "get") && slices.Contains(rule.APIGroups, "") {
			grantsLogs = true
		}
	}
	if !grantsLogs {
		t.Error("log-reader ClusterRole does not grant get on pods/log")
	}

}

// guard is what a cred-release ClusterRole must never grant. Wildcards are
// refused outright: "*" in resources matches every subresource (nodes/proxy
// reaches the kubelet's exec endpoint with no pods/exec admission check), and
// "*" in verbs includes bind, escalate, impersonate and grant.
type guard struct {
	writeVerbs bool                // may any rule carry a write verb
	resources  map[string][]string // apiGroup -> resources refused with any verb
	writeOnly  map[string][]string // apiGroup -> resources refused with a write verb
}

var (
	writeVerbs    = []string{"create", "update", "patch", "delete", "deletecollection"}
	dangerVerbs   = []string{"*", "bind", "escalate", "impersonate", "grant", "approve", "sign"}
	proxyOrExec   = []string{"nodes/proxy", "nodes/log", "nodes/stats", "nodes/metrics", "nodes/spec", "pods/proxy", "services/proxy", "pods/exec", "pods/attach", "pods/portforward", "pods/ephemeralcontainers", "serviceaccounts/token"}
	operatorGuard = guard{
		writeVerbs: true,
		resources: map[string][]string{
			"":                proxyOrExec,
			"confidential.ai": {"podsecurityexemptions"},
		},
		writeOnly: map[string][]string{
			"":                             {"nodes", "nodes/status", "persistentvolumes"},
			"rbac.authorization.k8s.io":    {"clusterroles", "clusterrolebindings"},
			"admissionregistration.k8s.io": {"validatingadmissionpolicies", "validatingadmissionpolicybindings", "validatingwebhookconfigurations", "mutatingwebhookconfigurations", "mutatingadmissionpolicies", "mutatingadmissionpolicybindings"},
			"apiextensions.k8s.io":         {"customresourcedefinitions"},
			"storage.k8s.io":               {"storageclasses", "csidrivers", "csinodes", "volumeattachments"},
			"helm.cattle.io":               {"helmcharts", "helmchartconfigs"},
			"k3s.cattle.io":                {"addons"},
			"apiregistration.k8s.io":       {"apiservices"},
			"certificates.k8s.io":          {"certificatesigningrequests", "certificatesigningrequests/approval", "certificatesigningrequests/status", "signers"},
		},
	}
	logReaderGuard = guard{
		writeVerbs: false,
		resources: map[string][]string{
			"": append([]string{"secrets", "configmaps"}, proxyOrExec...),
		},
	}
)

func checkGuardedRules(t *testing.T, role string, rules []rbacv1.PolicyRule, g guard) {
	t.Helper()
	for _, rule := range rules {
		if slices.Contains(rule.APIGroups, "*") {
			t.Errorf("%s rule %+v spans every API group", role, rule)
		}
		if slices.Contains(rule.Resources, "*") {
			t.Errorf("%s rule %+v spans every resource (and subresource)", role, rule)
		}
		for _, res := range rule.Resources {
			if strings.HasSuffix(res, "/*") {
				t.Errorf("%s rule grants every subresource of %q", role, res)
			}
		}
		if len(rule.NonResourceURLs) != 0 {
			t.Errorf("%s rule %+v grants non-resource URLs", role, rule)
		}
		writes := false
		for _, verb := range rule.Verbs {
			if slices.Contains(dangerVerbs, verb) {
				t.Errorf("%s rule %+v grants verb %q", role, rule, verb)
			}
			if slices.Contains(writeVerbs, verb) {
				writes = true
			}
		}
		if writes && !g.writeVerbs {
			t.Errorf("%s rule %+v grants a write verb", role, rule)
		}
		for _, group := range rule.APIGroups {
			for _, res := range rule.Resources {
				if slices.Contains(g.resources[group], res) {
					t.Errorf("%s rule grants %s/%s", role, group, res)
				}
				if writes && slices.Contains(g.writeOnly[group], res) {
					t.Errorf("%s rule grants a write verb on %s/%s", role, group, res)
				}
			}
		}
	}
}

// readRoleAndBinding decodes an AddOn that holds exactly a ClusterRole then a
// ClusterRoleBinding, strictly.
func readRoleAndBinding(t *testing.T, path string) (rbacv1.ClusterRole, rbacv1.ClusterRoleBinding) {
	t.Helper()
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read node-image RBAC manifest %s: %v", path, err)
	}
	docs := yaml.NewDecoder(bytes.NewReader(body))
	var role rbacv1.ClusterRole
	var binding rbacv1.ClusterRoleBinding
	decodeStrictDoc(t, docs, path, 0, &role)
	decodeStrictDoc(t, docs, path, 1, &binding)
	if err := docs.Decode(new(yaml.Node)); err != io.EOF {
		t.Fatalf("%s holds more than two documents, want a ClusterRole then a ClusterRoleBinding (third decode: %v)", path, err)
	}
	if role.APIVersion != "rbac.authorization.k8s.io/v1" || role.Kind != "ClusterRole" {
		t.Errorf("%s document 0 typeMeta = %s %s, want rbac.authorization.k8s.io/v1 ClusterRole", path, role.APIVersion, role.Kind)
	}
	if binding.APIVersion != "rbac.authorization.k8s.io/v1" || binding.Kind != "ClusterRoleBinding" {
		t.Errorf("%s document 1 typeMeta = %s %s, want rbac.authorization.k8s.io/v1 ClusterRoleBinding", path, binding.APIVersion, binding.Kind)
	}
	return role, binding
}

// decodeStrictDoc reads the next YAML document from docs into out, refusing
// unknown fields.
func decodeStrictDoc(t *testing.T, docs *yaml.Decoder, path string, i int, out any) {
	t.Helper()
	var node yaml.Node
	if err := docs.Decode(&node); err != nil {
		t.Fatalf("decode %s document %d: %v", path, i, err)
	}
	raw, err := yaml.Marshal(&node)
	if err != nil {
		t.Fatal(err)
	}
	if err := sigsyaml.UnmarshalStrict(raw, out); err != nil {
		t.Fatalf("decode %s document %d as %T: %v", path, i, out, err)
	}
}
