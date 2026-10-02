package helmchart

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sigsyaml "sigs.k8s.io/yaml"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// helmFailMessage extracts the user-visible message from a `helm template`
// failure so tests can parse a typed value out of it instead of grepping
// the whole stderr blob.
var helmFailRE = regexp.MustCompile(`execution error at \([^)]+\): (.+?)\n`)

func helmFailMessage(t *testing.T, out string) string {
	t.Helper()
	m := helmFailRE.FindStringSubmatch(out)
	if len(m) < 2 {
		t.Fatalf("no helm fail message in output:\n%s", out)
	}
	return m[1]
}

func assertHelmFailMessage(t *testing.T, out, want string) {
	t.Helper()
	if got := helmFailMessage(t, out); got != want {
		t.Fatalf("helm fail message = %q, want %q\n%s", got, want, out)
	}
}

// preStopBoundFailure captures the structured shape of the daemonset
// preStop fail-checks so tests can assert on typed fields instead of
// substring-matching the rendered error.
type preStopBoundFailure struct {
	Cmp   string // "le" for "≤", "ge" for "≥"
	Bound int
	Got   int
}

var preStopBoundRE = regexp.MustCompile(`iptablesCleanup\.preStopSleepSeconds must be ([≤≥]) (-?\d+).*got (-?\d+)`)

func parsePreStopBoundFailure(t *testing.T, out string) preStopBoundFailure {
	t.Helper()
	msg := helmFailMessage(t, out)
	m := preStopBoundRE.FindStringSubmatch(msg)
	if len(m) != 4 {
		t.Fatalf("preStop bound regex did not match %q", msg)
	}
	cmp := "ge"
	if m[1] == "≤" {
		cmp = "le"
	}
	bound, err := strconv.Atoi(m[2])
	if err != nil {
		t.Fatalf("bound %q is not an int: %v", m[2], err)
	}
	got, err := strconv.Atoi(m[3])
	if err != nil {
		t.Fatalf("got %q is not an int: %v", m[3], err)
	}
	return preStopBoundFailure{Cmp: cmp, Bound: bound, Got: got}
}

// gracePeriodBudgetFailure: the durations the chart says don't leave a
// preStop window.
type gracePeriodBudgetFailure struct {
	GracePeriod string
	Drain       string
}

var gracePeriodBudgetRE = regexp.MustCompile(`terminationGracePeriod \(([^)]+)\) must exceed drainTimeout \(([^)]+)\)`)

func parseGracePeriodBudgetFailure(t *testing.T, out string) gracePeriodBudgetFailure {
	t.Helper()
	msg := helmFailMessage(t, out)
	m := gracePeriodBudgetRE.FindStringSubmatch(msg)
	if len(m) != 3 {
		t.Fatalf("grace-period budget regex did not match %q", msg)
	}
	return gracePeriodBudgetFailure{GracePeriod: m[1], Drain: m[2]}
}

// durationFormatFailure classifies the two distinct rejection paths in the
// duration helper so a future refactor that conflates them flags here.
type durationFormatFailure struct {
	Value  string
	Reason string // "no-unit" | "non-integer"
}

var (
	durationNoUnitRE     = regexp.MustCompile(`duration "([^"]+)" must end with h, m, or s`)
	durationNonIntegerRE = regexp.MustCompile(`duration "([^"]+)" must be a positive integer`)
)

func parseDurationFormatFailure(t *testing.T, out string) durationFormatFailure {
	t.Helper()
	msg := helmFailMessage(t, out)
	if m := durationNoUnitRE.FindStringSubmatch(msg); len(m) == 2 {
		return durationFormatFailure{Value: m[1], Reason: "no-unit"}
	}
	if m := durationNonIntegerRE.FindStringSubmatch(msg); len(m) == 2 {
		return durationFormatFailure{Value: m[1], Reason: "non-integer"}
	}
	t.Fatalf("duration-format regex did not match %q", msg)
	return durationFormatFailure{}
}

// containerArgs returns the args of the named container, searching main and
// init containers. Fails the test if no such container exists.
func containerArgs(t *testing.T, ds *appsv1.DaemonSet, name string) []string {
	t.Helper()
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == name {
			return c.Args
		}
	}
	for _, c := range ds.Spec.Template.Spec.InitContainers {
		if c.Name == name {
			return c.Args
		}
	}
	t.Fatalf("container %q not found in DaemonSet", name)
	return nil
}

// containerArgValue returns (value, true) for `--flag value`, or ("", false)
// if the flag isn't present.
func containerArgValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func TestChartDefaultRendersReplacementStack(t *testing.T) {
	// gke keeps the host-side attestation-api enabled, reachable only via the
	// on-node Unix socket (node disables it and points components at the baked
	// host attestation-api via HOST_IP; that path is covered separately).
	out, err := helmTemplate(t, "--set", "attestationApi.cvmMode=gke")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !renderedManifestHasKind(t, out, "MutatingWebhookConfiguration") {
		t.Fatalf("default chart missing MutatingWebhookConfiguration\n%s", out)
	}
	for _, label := range [][2]string{
		{"app.kubernetes.io/component", "cds"},
		{"app.kubernetes.io/name", "ratls-mesh"},
		{"app.kubernetes.io/name", "nri-image-policy"},
		{"app.kubernetes.io/name", "router"},
	} {
		if !renderedManifestHasLabel(t, out, label[0], label[1]) {
			t.Fatalf("default chart missing a manifest labelled %s: %s", label[0], label[1])
		}
	}
	renderedRouterNginxConfig(t, out).server(t).assertDirective(t, "server_name", "c8s-router.c8s-system.svc")
	cert := routerGetCertContainer(t, out, "c8s-cert")
	assertContainerArgs(t, cert,
		"get-cert",
		"--cds-url=https://c8s-cds.c8s-system.svc:8443",
		"--attestation-api-url=unix:///var/run/nri-image-policy/attestation-api.sock",
		"--san=c8s-router.c8s-system.svc",
		"--out=/tls/cert.pem",
		"--key-out=/tls/key.pem",
		"--renew-interval=1h",
		"--reload-nginx=true",
		"--continue-on-initial-error",
		// The CA watch keeps the served mesh CA tracking the live CDS CA: a
		// CDS restart regenerates the mesh CA in-memory, and without the watch
		// the /.well-known/mesh-ca.pem discovery endpoint serves the dead CA
		// until the next scheduled renewal.
		"--ca-watch-interval=1m",
	)
	if cert.RestartPolicy == nil || *cert.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("c8s-cert restartPolicy = %v, want Always", cert.RestartPolicy)
	}
	// nginx is gated by the c8s-cert-wait init container, not an exec
	// startupProbe on the sidecar.
	if cert.StartupProbe != nil {
		t.Fatalf("c8s-cert must NOT carry a startupProbe; got %+v", cert.StartupProbe)
	}
	wait := routerGetCertContainer(t, out, "c8s-cert-wait")
	if got := strings.Join(wait.Command, " "); !strings.Contains(got, "probe-file") || !strings.Contains(got, "--wait") || !strings.Contains(got, "/tls/cert.pem") {
		t.Fatalf("c8s-cert-wait command = %q, want `/c8s probe-file --wait --timeout=... /tls/cert.pem`", got)
	}
	if got := cert.SecurityContext.RunAsUser; got == nil || *got != 101 {
		t.Fatalf("c8s-cert runAsUser = %v, want 101", got)
	}
	args := renderedOperatorArgs(t, out)
	for _, want := range []string{
		"--get-cert-image=ghcr.io/confidential-dot-ai/c8s-operator:dev",
		"--cds-url=https://c8s-cds.c8s-system.svc:8443",
		"--get-cert-renew-interval=2h",
	} {
		if !slices.Contains(args, want) {
			t.Fatalf("operator args missing %q\n%v", want, args)
		}
	}
}

func TestChartRendersRATLSHostRoutingDefaults(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := findRATLSMeshDaemonSet(t, out)

	sync, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "iptables-sync")
	if !ok {
		t.Fatalf("iptables-sync init container missing; have %v", containerNames(ds.Spec.Template.Spec.InitContainers))
	}
	for _, pair := range [][2]string{
		{"--node-ip", "$(NODE_IP)"},
		{"--resync-period", "30s"},
		{"--watchdog-period", "2s"},
		{"--ipset-maxelem", "262144"},
		{"--ready-file", "/tmp/ratls-iptables-ready"},
		{"--iptables-metrics-file", "/tmp/ratls-iptables-metrics.json"},
		// The release namespace must NOT be excluded: router egress to
		// workload pod IPs (headless-Service dials) needs mesh interception.
		{"--exclude-source-namespaces", "kube-system"},
	} {
		if !argvContainsFlagValue(sync.Command, pair[0], pair[1]) {
			t.Errorf("iptables-sync command missing %s %s; command=%q", pair[0], pair[1], sync.Command)
		}
	}
	if slices.Contains(sync.Command, "--pod-cidrs") {
		t.Errorf("iptables-sync must not require static --pod-cidrs; command=%q", sync.Command)
	}
	// The cw inbound guard is always on; its posture is the passthrough
	// allowlist, defaulting to DNS replies so get-cert can resolve.
	if !slices.Contains(sync.Command, "--cw-inbound-passthrough=udp:53,tcp:53") {
		t.Errorf("iptables-sync command missing --cw-inbound-passthrough=udp:53,tcp:53; command=%q", sync.Command)
	}

	mesh, ok := findContainer(ds.Spec.Template.Spec.Containers, "ratls-mesh")
	if !ok {
		t.Fatalf("ratls-mesh container missing; have %v", containerNames(ds.Spec.Template.Spec.Containers))
	}
	if !argvContainsFlagValue(mesh.Args, "--iptables-metrics-file", "/tmp/ratls-iptables-metrics.json") {
		t.Errorf("ratls-mesh args missing the shared iptables metrics file flag; args=%q", mesh.Args)
	}
	// --platform is the RA-TLS TEE type; an empty value (the old missing
	// default) trips the binary's "--platform is required" check, so the mesh
	// pod never starts. Pin the non-empty default.
	if !argvContainsFlagValue(mesh.Args, "--platform", "sev-snp") {
		t.Errorf("ratls-mesh args must default --platform to sev-snp; args=%q", mesh.Args)
	}
	if hp, ok := containerHostPort(mesh, "inbound"); !ok || hp != 15006 {
		t.Errorf("ratls-mesh inbound port must publish hostPort 15006; got %d (found=%v)", hp, ok)
	}
	for _, banned := range []int32{15001, 15021} {
		if containers := containersExposingHostPort(ds, banned); len(containers) > 0 {
			t.Errorf("hostPort %d must not be exposed; exposed by %v", banned, containers)
		}
	}

	for _, c := range allContainers(ds) {
		for name := range c.Resources.Requests {
			if strings.Contains(string(name), "confidential.ai/tpm") {
				t.Errorf("container %q requests local TPM resource %q by default", c.Name, name)
			}
		}
		for name := range c.Resources.Limits {
			if strings.Contains(string(name), "confidential.ai/tpm") {
				t.Errorf("container %q limits local TPM resource %q by default", c.Name, name)
			}
		}
	}

	// The attestation-api policy must remain; nothing may select the hostNetwork
	// mesh pods. volumed's is absent here because volumed is off by default.
	wantPolicies := []string{
		"c8s-attestation-api",
		"ratls-mesh-tcp-only-egress",
		"c8s-cds-ingress",
		"c8s-operator-ingress",
		"c8s-router-ingress",
	}
	kinds := renderedKinds(t, out)
	if kinds["NetworkPolicy"] != len(wantPolicies) {
		t.Errorf("default render NetworkPolicy count = %d, want %d", kinds["NetworkPolicy"], len(wantPolicies))
	}
	for _, name := range wantPolicies {
		if !renderedManifestHasNamedKind(t, out, "NetworkPolicy", name) {
			t.Errorf("default render is missing NetworkPolicy %q", name)
		}
	}
}

func TestChartCWInboundPassthrough(t *testing.T) {
	// An empty passthrough renders the strict fail-closed posture (no
	// exemptions), and the flag is present-but-empty so the manifest still
	// self-documents that the guard is on.
	out, err := helmTemplate(t, "--set", "ratlsMesh.cwInboundEnforcement.passthrough=[]")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := findRATLSMeshDaemonSet(t, out)
	sync, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "iptables-sync")
	if !ok {
		t.Fatalf("iptables-sync init container missing; have %v", containerNames(ds.Spec.Template.Spec.InitContainers))
	}
	if !slices.Contains(sync.Command, "--cw-inbound-passthrough=") {
		t.Errorf("iptables-sync command missing empty --cw-inbound-passthrough=; command=%q", sync.Command)
	}

	// A custom passthrough list renders in order as proto:port,proto:port.
	out, err = helmTemplate(t,
		"--set", "ratlsMesh.cwInboundEnforcement.passthrough[0].protocol=udp",
		"--set", "ratlsMesh.cwInboundEnforcement.passthrough[0].sourcePort=53",
		"--set", "ratlsMesh.cwInboundEnforcement.passthrough[1].protocol=tcp",
		"--set", "ratlsMesh.cwInboundEnforcement.passthrough[1].sourcePort=8443",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds = findRATLSMeshDaemonSet(t, out)
	sync, _ = findContainer(ds.Spec.Template.Spec.InitContainers, "iptables-sync")
	if !slices.Contains(sync.Command, "--cw-inbound-passthrough=udp:53,tcp:8443") {
		t.Errorf("iptables-sync command missing --cw-inbound-passthrough=udp:53,tcp:8443; command=%q", sync.Command)
	}

	// A wrong-typed value (e.g. --set-string) fails loudly instead of silently
	// rendering strict drop-all, which would reproduce the DNS-resolution
	// outage this guard exists to prevent.
	out, err = helmTemplate(t, "--set-string", "ratlsMesh.cwInboundEnforcement.passthrough=udp:53")
	if err == nil {
		t.Fatalf("helm template succeeded on a string passthrough, want a fail\n%s", out)
	}
	if !strings.Contains(out, "must be a list") {
		t.Errorf("passthrough type error should name the fix; got %s", out)
	}

	// A malformed entry fails at render, not at daemon startup — a rendered
	// "udp:<nil>" would crash-loop the init container. The key prefix is elided
	// to pt for readability.
	const pt = "ratlsMesh.cwInboundEnforcement.passthrough"
	for _, bad := range [][]string{
		{"--set", pt + "[0].protocol=udp"},                                       // missing sourcePort
		{"--set", pt + "[0].protocol=icmp", "--set", pt + "[0].sourcePort=53"},   // bad protocol
		{"--set", pt + "[0].protocol=udp", "--set", pt + "[0].sourcePort=70000"}, // out-of-range port
	} {
		if out, err := helmTemplate(t, bad...); err == nil {
			t.Errorf("helm template succeeded on malformed passthrough entry %v, want a fail\n%s", bad, out)
		}
	}
}

// argvContainsFlagValue reports whether argv has `flag` immediately followed
// by `value`.
func argvContainsFlagValue(argv []string, flag, value string) bool {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) && argv[i+1] == value {
			return true
		}
	}
	return false
}

func namedContainerPort(c corev1.Container, portName string) (corev1.ContainerPort, bool) {
	for _, p := range c.Ports {
		if p.Name == portName {
			return p, true
		}
	}
	return corev1.ContainerPort{}, false
}

func containerHostPort(c corev1.Container, portName string) (int32, bool) {
	p, ok := namedContainerPort(c, portName)
	return p.HostPort, ok
}

func containersExposingHostPort(ds *appsv1.DaemonSet, port int32) []string {
	var hits []string
	for _, c := range allContainers(ds) {
		for _, p := range c.Ports {
			if p.HostPort == port {
				hits = append(hits, c.Name)
				break
			}
		}
	}
	return hits
}

func allContainers(ds *appsv1.DaemonSet) []corev1.Container {
	out := make([]corev1.Container, 0, len(ds.Spec.Template.Spec.InitContainers)+len(ds.Spec.Template.Spec.Containers))
	out = append(out, ds.Spec.Template.Spec.InitContainers...)
	out = append(out, ds.Spec.Template.Spec.Containers...)
	return out
}

// iterateManifests calls fn for each non-nil YAML document in helmOut,
// using yaml.NewDecoder so a "---" inside a block scalar can't fool the
// split. The document is re-marshalled to YAML bytes so fn can pass it
// to sigsyaml.Unmarshal for typed decoding. fn returning true stops
// iteration.
func iterateManifests(t *testing.T, helmOut string, fn func(doc []byte) bool) {
	t.Helper()
	decoder := yaml.NewDecoder(strings.NewReader(helmOut))
	for {
		var raw any
		err := decoder.Decode(&raw)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			t.Fatalf("decode helm output: %v", err)
		}
		if raw == nil {
			continue
		}
		b, err := yaml.Marshal(raw)
		if err != nil {
			t.Fatalf("re-marshal manifest: %v", err)
		}
		if fn(b) {
			return
		}
	}
}

// renderedKinds counts each manifest kind across a helm template output.
func renderedKinds(t *testing.T, helmOut string) map[string]int {
	t.Helper()
	out := map[string]int{}
	iterateManifests(t, helmOut, func(doc []byte) bool {
		var head struct {
			Kind string `json:"kind"`
		}
		if err := sigsyaml.Unmarshal(doc, &head); err == nil && head.Kind != "" {
			out[head.Kind]++
		}
		return false
	})
	return out
}

// Two silent-break risks in a daemonset.yaml refactor:
//  1. iptables-{cleanup,sync} must stay native sidecars (restartPolicy:
//     Always); dropping that demotes them to one-shot init containers and
//     the cleanup preStop never fires, leaking rules across restarts.
//  2. iptables-cleanup must be the FIRST initContainer; native sidecars
//     terminate in reverse-init order, so a swap with iptables-sync stops
//     cleanup before sync loses its chains.
func TestChartRATLSNativeSidecarShape(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := findRATLSMeshDaemonSet(t, out)

	// hostNetwork + dnsPolicy are part of the routing contract: iptables-sync
	// must run in the host netns to see pre-DNAT pod traffic, and the
	// matching dnsPolicy keeps in-cluster service DNS working from that
	// netns. A refactor that templated either to a value and accidentally
	// toggled it via overlay defaults would still match the substring check
	// in TestChartRendersRATLSHostRoutingDefaults; assert against the typed
	// PodSpec so the contract is unambiguous.
	if !ds.Spec.Template.Spec.HostNetwork {
		t.Errorf("ratls-mesh DaemonSet must set hostNetwork: true; got %v", ds.Spec.Template.Spec.HostNetwork)
	}
	if got := ds.Spec.Template.Spec.DNSPolicy; got != corev1.DNSClusterFirstWithHostNet {
		t.Errorf("ratls-mesh DaemonSet must set dnsPolicy: ClusterFirstWithHostNet (paired with hostNetwork); got %q", got)
	}

	init := ds.Spec.Template.Spec.InitContainers
	if len(init) < 2 {
		t.Fatalf("expected at least 2 initContainers (iptables-cleanup, iptables-sync); got %d", len(init))
	}
	if init[0].Name != "iptables-cleanup" {
		t.Fatalf("first init container must be iptables-cleanup so its preStop fires last on shutdown; got %q", init[0].Name)
	}

	for _, name := range []string{"iptables-cleanup", "iptables-sync"} {
		c, ok := findContainer(init, name)
		if !ok {
			t.Fatalf("init container %q not found in %v", name, containerNames(init))
		}
		if c.RestartPolicy == nil || *c.RestartPolicy != corev1.ContainerRestartPolicyAlways {
			t.Errorf("init container %q must declare restartPolicy: Always (native sidecar contract); got %v", name, c.RestartPolicy)
		}
		if !hasCapability(c, "NET_ADMIN") {
			t.Errorf("init container %q must hold NET_ADMIN to manage iptables/ipset; caps=%+v", name, c.SecurityContext)
		}
		// NET_RAW is required for the xt_set match's socket to ip_set on the
		// nf_tables-compat path; without it `iptables -m set` fails with
		// "Can't open socket to ipset" despite NET_ADMIN.
		if !hasCapability(c, "NET_RAW") {
			t.Errorf("init container %q must hold NET_RAW for the iptables xt_set match; caps=%+v", name, c.SecurityContext)
		}
		// The sidecars run as root for iptables/ipset but are bounded by
		// allowPrivilegeEscalation: false and the runtime-default seccomp
		// profile. Both are easy to omit silently in a refactor and turn the
		// containers into a full-root attack surface; pin them.
		sc := c.SecurityContext
		if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
			t.Errorf("init container %q must set allowPrivilegeEscalation: false; got %+v", name, sc)
		}
		if sc == nil || sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
			t.Errorf("init container %q must set seccompProfile.type: RuntimeDefault; got %+v", name, sc.SeccompProfile)
		}
	}

	sync, ok := findContainer(init, "iptables-sync")
	if !ok {
		t.Fatalf("iptables-sync init container missing; initContainers=%v", containerNames(init))
	}
	// HTTP because a locked node image denies every runc exec, so an exec
	// probe would never pass there.
	if sync.StartupProbe == nil || sync.StartupProbe.HTTPGet == nil {
		t.Fatalf("iptables-sync must expose an HTTP startupProbe so the main proxy waits for interception; got %+v", sync.StartupProbe)
	}
	if got := sync.StartupProbe.HTTPGet; got.Path != "/readyz" || got.Host != "127.0.0.1" {
		t.Errorf("iptables-sync startupProbe = %+v, want GET /readyz on node loopback", got)
	}

	// The entire teardown contract hinges on the iptables-cleanup container
	// cleaning up last in the reverse-init-order stop sequence. A future
	// refactor that drops --on-shutdown or renames the subcommand would
	// silently leak iptables rules and ipsets across pod restarts — catch
	// that here instead of in production.
	cleanup := init[0]
	if cleanup.Lifecycle != nil {
		t.Errorf("iptables-cleanup must clean up on SIGTERM, not through a lifecycle hook; got %+v", cleanup.Lifecycle)
	}
	command := strings.Join(cleanup.Command, " ")
	for _, want := range []string{"ratls-mesh iptables-cleanup", "--on-shutdown"} {
		if !strings.Contains(command, want) {
			t.Errorf("iptables-cleanup command %q must contain %q", command, want)
		}
	}
}

// TestChartRATLSKubeVersionPinned guards the chart's Kubernetes base
// against accidental relaxation. Two contracts pin it:
//   - native sidecars (SidecarContainers default-on from 1.29): with the
//     gate off, iptables-cleanup is invalid as a native sidecar, its preStop
//     cannot run, and the host leaks managed chains/ipsets across restarts;
//   - ValidatingAdmissionPolicy v1 (GA from 1.30): the chart ships default-on
//     UID, workload-integrity, and Restricted pod-security policies, so a
//     pre-1.30 apply fails mid-install on unknown kinds anyway — the
//     kubeVersion constraint makes helm fail early and clearly instead.
func TestChartRATLSKubeVersionPinned(t *testing.T) {
	const path = "c8s/Chart.yaml"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var chart struct {
		KubeVersion string `json:"kubeVersion"`
	}
	if err := sigsyaml.Unmarshal(raw, &chart); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	const want = ">=1.30.0-0"
	if chart.KubeVersion != want {
		t.Fatalf("c8s Chart.yaml kubeVersion = %q; want %q (native sidecars need k8s 1.29+, and the default-on ValidatingAdmissionPolicies need v1/GA from 1.30)", chart.KubeVersion, want)
	}
}

// nodeAffinityHasKey reports whether any required nodeAffinity matchExpression
// keys on the given label.
func nodeAffinityHasKey(ds appsv1.DaemonSet, key string) bool {
	aff := ds.Spec.Template.Spec.Affinity
	if aff == nil || aff.NodeAffinity == nil ||
		aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		return false
	}
	for _, term := range aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
		for _, expr := range term.MatchExpressions {
			if expr.Key == key {
				return true
			}
		}
	}
	return false
}

// The chart renders exactly one pull-mode installer DaemonSet, `-worker`, that
// targets every node — there is no CDS/worker partition. The old push archetype
// (a role=cds-pinned `-cds` installer) is gone; this guards against it coming
// back.
func TestChartNriInstallerRendersSinglePullDaemonSet(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-nri-image-policy-cds") {
		t.Error("no cds/push installer must render; only the pull-mode -worker DaemonSet exists")
	}
	worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	if nodeAffinityHasKey(worker, "role") {
		t.Error("worker installer must not key on role; it targets every node")
	}
	if got, want := worker.Spec.Template.Labels["app.kubernetes.io/component"], "nri-installer-worker"; got != want {
		t.Errorf("worker installer pod component label = %q, want %q", got, want)
	}
	// The install script writes ${NODE_IP:?} to the node-ip file the plugin
	// reads, so the env var must sit on the install container itself, not on
	// the rke2-only containerd-prep sibling.
	install, ok := findContainer(worker.Spec.Template.Spec.InitContainers, "install")
	if !ok {
		t.Fatalf("install init container missing; have %v", containerNames(worker.Spec.Template.Spec.InitContainers))
	}
	if !hasNodeIPEnv(install) {
		t.Errorf("install init container missing NODE_IP downward-API env; have %+v", install.Env)
	}
}

// Both admission paths enforce host isolation and Pod security defaults.
// The ephemeral policy otherwise checks only debugger containers, leaving
// unrelated preserved container fields alone.
func TestChartHostSecurityPoliciesSplitPodAndEphemeral(t *testing.T) {
	out, err := helmTemplate(t, "--set", "hostNamespacePolicy.exemptNamespaces={tenant-platform}")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var podPolicy admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, out, "ValidatingAdmissionPolicy", "c8s-deny-host-namespaces", &podPolicy) {
		t.Fatal("ValidatingAdmissionPolicy c8s-deny-host-namespaces not rendered")
	}
	var ephemeralPolicy admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, out, "ValidatingAdmissionPolicy", "c8s-deny-host-namespaces-ephemeral", &ephemeralPolicy) {
		t.Fatal("ValidatingAdmissionPolicy c8s-deny-host-namespaces-ephemeral not rendered")
	}

	resources := func(p admissionregv1.ValidatingAdmissionPolicy) []string {
		var got []string
		for _, rule := range p.Spec.MatchConstraints.ResourceRules {
			got = append(got, rule.Resources...)
		}
		return got
	}
	if got := resources(podPolicy); !slices.Contains(got, "pods") {
		t.Errorf("pod security policy resources = %v, want pods", got)
	} else if slices.Contains(got, "pods/ephemeralcontainers") {
		t.Errorf("pod security policy must not match the separately validated ephemeral subresource: %v", got)
	}
	if got := resources(ephemeralPolicy); !slices.Contains(got, "pods/ephemeralcontainers") {
		t.Errorf("ephemeral security policy resources = %v, want pods/ephemeralcontainers", got)
	} else if slices.Contains(got, "pods") {
		t.Errorf("ephemeral security policy must not match pods: %v", got)
	}

	var hostPortExpr string
	for _, v := range podPolicy.Spec.Validations {
		if strings.Contains(v.Expression, "hostPort") {
			hostPortExpr = v.Expression
		}
	}
	if hostPortExpr == "" {
		t.Fatal("no hostPort validation in c8s-deny-host-namespaces: a tenant pod with hostPort 1019 impersonates the admission inventory")
	}
	for _, want := range []string{"spec.containers", "spec.initContainers", "spec.ephemeralContainers"} {
		if !strings.Contains(hostPortExpr, want) {
			t.Errorf("hostPort validation does not cover %s; expression=%q", want, hostPortExpr)
		}
	}
	for _, v := range ephemeralPolicy.Spec.Validations {
		// Host isolation stays a full-Pod invariant on subresource updates.
		if slices.ContainsFunc([]string{"hostNetwork", "hostPID", "hostIPC", "hostPort", "hostPath", "sysctls"}, func(field string) bool {
			return strings.Contains(v.Expression, field)
		}) {
			continue
		}
		if !strings.Contains(v.Expression, "object.spec.ephemeralContainers") {
			t.Errorf("ephemeral security expression does not inspect debuggers: %s", v.Expression)
		}
		for _, preservedField := range []string{"object.spec.containers", "object.spec.initContainers", "object.spec.volumes"} {
			if strings.Contains(v.Expression, preservedField) {
				t.Errorf("ephemeral security expression revalidates unrelated preserved field %s: %s", preservedField, v.Expression)
			}
		}
	}

	for _, policy := range []admissionregv1.ValidatingAdmissionPolicy{podPolicy, ephemeralPolicy} {
		selector := policy.Spec.MatchConstraints.NamespaceSelector
		if selector == nil {
			t.Errorf("%s has no namespaceSelector", policy.Name)
			continue
		}
		var excluded []string
		for _, requirement := range selector.MatchExpressions {
			if requirement.Key == "kubernetes.io/metadata.name" &&
				requirement.Operator == metav1.LabelSelectorOpNotIn {
				excluded = append(excluded, requirement.Values...)
			}
		}
		for _, want := range []string{"c8s-system", "kube-system", "local-path-storage", "tenant-platform"} {
			if !slices.Contains(excluded, want) {
				t.Errorf("%s namespace exclusions = %v, missing %q", policy.Name, excluded, want)
			}
		}
	}

	for _, name := range []string{"c8s-deny-host-namespaces", "c8s-deny-host-namespaces-ephemeral"} {
		var binding admissionregv1.ValidatingAdmissionPolicyBinding
		if !findDoc(t, out, "ValidatingAdmissionPolicyBinding", name, &binding) {
			t.Errorf("ValidatingAdmissionPolicyBinding %s not rendered", name)
			continue
		}
		if binding.Spec.PolicyName != name {
			t.Errorf("%s binding policyName = %q, want %q", name, binding.Spec.PolicyName, name)
		}
		if len(binding.Spec.ValidationActions) != 1 ||
			binding.Spec.ValidationActions[0] != admissionregv1.Deny {
			t.Errorf("%s binding actions = %v, want [Deny]", name, binding.Spec.ValidationActions)
		}
	}
}

// The UID admission policy must cover spec.ephemeralContainers (value check)
// and the pods/ephemeralcontainers subresource (match) so a debug exec can't
// run as the proxy UID and escape the mesh.
// The pods/ephemeralcontainers subresource has a different object shape
// (spec.ephemeralContainers only) than a pod. The UID policy is therefore
// split: the pod policy validates pod/container/init shapes, and a separate
// policy validates the ephemeral subresource so a kubectl debug is not
// denied by pod-only expressions failing their type-check.
func TestChartUIDAdmissionPolicySplitsPodAndEphemeral(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var podPolicy admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, out, "ValidatingAdmissionPolicy", "deny-ratls-mesh-uid", &podPolicy) {
		t.Fatal("missing deny-ratls-mesh-uid ValidatingAdmissionPolicy")
	}
	var ephemeralPolicy admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, out, "ValidatingAdmissionPolicy", "deny-ratls-mesh-uid-ephemeral", &ephemeralPolicy) {
		t.Fatal("missing deny-ratls-mesh-uid-ephemeral ValidatingAdmissionPolicy")
	}

	resources := func(p admissionregv1.ValidatingAdmissionPolicy) []string {
		var outResources []string
		for _, r := range p.Spec.MatchConstraints.ResourceRules {
			outResources = append(outResources, r.Resources...)
		}
		return outResources
	}
	if !slices.Contains(resources(podPolicy), "pods") {
		t.Error("pod policy does not match pods")
	}
	if slices.Contains(resources(podPolicy), "pods/ephemeralcontainers") {
		t.Error("pod policy must not match pods/ephemeralcontainers (different object shape)")
	}
	if !slices.Contains(resources(ephemeralPolicy), "pods/ephemeralcontainers") {
		t.Error("ephemeral policy does not match pods/ephemeralcontainers")
	}

	// The ephemeral policy's expressions must reference only the subresource
	// shape (spec.ephemeralContainers), not pod-only fields.
	for _, v := range ephemeralPolicy.Spec.Validations {
		if strings.Contains(v.Expression, "spec.containers") {
			t.Errorf("ephemeral policy expression references pod-only spec.containers: %s", v.Expression)
		}
		if !strings.Contains(v.Expression, "spec.ephemeralContainers") {
			t.Errorf("ephemeral policy expression does not reference spec.ephemeralContainers: %s", v.Expression)
		}
	}
}

// tcpEgressPolicy is default-on and must render a policy even when the
// operator opts out of the per-namespace list ([] falls back to the release
// namespace). The rendered policy must allow mesh-protected TCP egress plus
// DNS/53 to kube-system and deny everything else by default.
func TestChartTCPEgressPolicyDefaultOnRendersNoNamespaces(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var np networkingv1.NetworkPolicy
	if !findDoc(t, out, "NetworkPolicy", "ratls-mesh-tcp-only-egress", &np) {
		t.Fatal("default render missing ratls-mesh-tcp-only-egress NetworkPolicy")
	}
	if !slices.Contains(np.Spec.PolicyTypes, networkingv1.PolicyTypeEgress) {
		t.Errorf("policyTypes = %v, want Egress (default-deny)", np.Spec.PolicyTypes)
	}
	// podSelector: {} (empty label selector) selects every pod in the
	// namespace — that's the "applies to all non-excluded pods" posture.
	if len(np.Spec.PodSelector.MatchLabels) != 0 || len(np.Spec.PodSelector.MatchExpressions) != 0 {
		t.Errorf("podSelector = %v, want empty (select all pods)", np.Spec.PodSelector)
	}
	// First egress rule allows TCP egress (mesh-protected); second allows
	// DNS UDP/53 to kube-system. Anything else is denied by default.
	if len(np.Spec.Egress) != 2 {
		t.Fatalf("egress rules = %d, want 2 (TCP + DNS to kube-system)", len(np.Spec.Egress))
	}
	if np.Spec.Egress[0].Ports == nil || len(np.Spec.Egress[0].Ports) != 1 || np.Spec.Egress[0].Ports[0].Protocol == nil || *np.Spec.Egress[0].Ports[0].Protocol != corev1.ProtocolTCP {
		t.Errorf("first egress rule must allow TCP egress; got %+v", np.Spec.Egress[0])
	}

	// Default values in values.yaml must be enabled:true / namespaces:[].
	const valuesPath = "c8s/values.yaml"
	raw, err := os.ReadFile(valuesPath)
	if err != nil {
		t.Fatalf("read %s: %v", valuesPath, err)
	}
	var vals struct {
		RatlsMesh struct {
			TCPEgressPolicy struct {
				Enabled    bool     `yaml:"enabled"`
				Namespaces []string `yaml:"namespaces"`
			} `yaml:"tcpEgressPolicy"`
		} `yaml:"ratlsMesh"`
	}
	if err := sigsyaml.Unmarshal(raw, &vals); err != nil {
		t.Fatalf("decode values.yaml: %v", err)
	}
	if !vals.RatlsMesh.TCPEgressPolicy.Enabled {
		t.Error("tcpEgressPolicy must default to enabled:true")
	}
	if len(vals.RatlsMesh.TCPEgressPolicy.Namespaces) != 0 {
		t.Errorf("tcpEgressPolicy must default to namespaces:[] (got %v)", vals.RatlsMesh.TCPEgressPolicy.Namespaces)
	}
}

// The claims socket directory reaches CW pods as an NRI mount, not a pod-spec
// volume, so the deny-host-namespaces VAP denies hostPath outright: any
// carve-out would let a tenant reach the node filesystem.
func TestChartHostNamespacePolicyDeniesAllHostPath(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var vap admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, out, "ValidatingAdmissionPolicy", "c8s-deny-host-namespaces", &vap) {
		t.Fatal("ValidatingAdmissionPolicy c8s-deny-host-namespaces not rendered")
	}
	var hostPathExprs []string
	for _, v := range vap.Spec.Validations {
		if strings.Contains(v.Expression, "hostPath") {
			hostPathExprs = append(hostPathExprs, v.Expression)
		}
	}
	if len(hostPathExprs) == 0 {
		t.Fatal("no hostPath validation in c8s-deny-host-namespaces")
	}
	// Absence, not presence: a leftover carve-out would pass a "some hostPath
	// deny renders" check.
	for _, v := range vap.Spec.Validations {
		for _, stale := range []string{"/var/run/nri-image-policy", "readOnly", "hostPath.type"} {
			if strings.Contains(v.Expression, stale) {
				t.Errorf("validation still carves out the claims dir (%q); expression=%q", stale, v.Expression)
			}
		}
	}
}

// hasNodeIPEnv reports whether the container carries a NODE_IP env var sourced
// from the status.hostIP downward-API field — the sandbox-digests callback
// address the installer writes down for the host-process plugin.
func hasNodeIPEnv(c corev1.Container) bool {
	for _, e := range c.Env {
		if e.Name == "NODE_IP" && e.ValueFrom != nil && e.ValueFrom.FieldRef != nil &&
			e.ValueFrom.FieldRef.FieldPath == "status.hostIP" {
			return true
		}
	}
	return false
}

// Single-node (empty cds.node.selector) renders the installer identically to
// the default (covered by TestChartNriInstallerRendersSinglePullDaemonSet);
// what's unique here is the CDS Deployment carrying no nodeSelector so it lands
// on the lone node.
func TestChartCDSDeploymentHasNoNodeSelectorUnderEmptySelector(t *testing.T) {
	out, err := helmTemplate(t, "--set", "cds.node.selector=null")
	if err != nil {
		t.Fatalf("helm template --set cds.node.selector=null: %v\n%s", err, out)
	}
	cdsDep := renderedDeployment(t, out, "c8s-cds")
	if len(cdsDep.Spec.Template.Spec.NodeSelector) != 0 {
		t.Errorf("cds Deployment must have no nodeSelector under single-node; got %v", cdsDep.Spec.Template.Spec.NodeSelector)
	}
}

func findRATLSMeshDaemonSet(t *testing.T, helmOut string) *appsv1.DaemonSet {
	t.Helper()
	var ds *appsv1.DaemonSet
	iterateManifests(t, helmOut, func(doc []byte) bool {
		var head struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		if err := sigsyaml.Unmarshal(doc, &head); err != nil ||
			head.Kind != "DaemonSet" ||
			!strings.Contains(head.Metadata.Name, "ratls-mesh") {
			return false
		}
		var decoded appsv1.DaemonSet
		if err := sigsyaml.Unmarshal(doc, &decoded); err != nil {
			t.Fatalf("decode ratls-mesh DaemonSet: %v\n%s", err, doc)
		}
		ds = &decoded
		return true
	})
	if ds == nil {
		t.Fatalf("ratls-mesh DaemonSet not found in helm template output\n%s", helmOut)
	}
	return ds
}

// findContainer mirrors findEnv in internal/webhook/pod_mutator_test.go:
// return (value, ok) so callers decide how to report the miss.
func findContainer(containers []corev1.Container, name string) (corev1.Container, bool) {
	for _, c := range containers {
		if c.Name == name {
			return c, true
		}
	}
	return corev1.Container{}, false
}

func containerNames(containers []corev1.Container) []string {
	names := make([]string, 0, len(containers))
	for _, c := range containers {
		names = append(names, c.Name)
	}
	return names
}

// routerGetCertContainer returns the named router get-cert init container
// (c8s-cert), failing if absent.
func routerGetCertContainer(t *testing.T, manifest, name string) corev1.Container {
	t.Helper()
	init := renderedDeploymentInitContainers(t, manifest, "c8s-router")
	c, ok := findContainer(init, name)
	if !ok {
		t.Fatalf("router init container %q missing; have %v", name, containerNames(init))
	}
	return c
}

// assertContainerArgs fails unless every wanted arg is present on the container.
func assertContainerArgs(t *testing.T, c corev1.Container, want ...string) {
	t.Helper()
	for _, w := range want {
		assertContainerHasArg(t, c.Name, c.Args, w)
	}
}

func hasCapability(c corev1.Container, want corev1.Capability) bool {
	if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
		return false
	}
	return slices.Contains(c.SecurityContext.Capabilities.Add, want)
}

// PrometheusRule's types live in a separate go module (prometheus-operator)
// the chart does not otherwise depend on; decoding into a local typed shim
// is enough to assert the rule contract without pulling that dep in just
// for tests.
type prometheusRule struct {
	Spec struct {
		Groups []struct {
			Name  string `json:"name"`
			Rules []struct {
				Alert       string            `json:"alert"`
				Expr        string            `json:"expr"`
				For         string            `json:"for"`
				Labels      map[string]string `json:"labels"`
				Annotations map[string]string `json:"annotations"`
			} `json:"rules"`
		} `json:"groups"`
	} `json:"spec"`
}

func findRATLSMeshPrometheusRule(t *testing.T, helmOut string) prometheusRule {
	t.Helper()
	var found prometheusRule
	var ok bool
	iterateManifests(t, helmOut, func(doc []byte) bool {
		var head struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		if err := sigsyaml.Unmarshal(doc, &head); err != nil ||
			head.Kind != "PrometheusRule" ||
			!strings.Contains(head.Metadata.Name, "ratls-mesh") {
			return false
		}
		var rule prometheusRule
		if err := sigsyaml.Unmarshal(doc, &rule); err != nil {
			t.Fatalf("decode ratls-mesh PrometheusRule: %v\n%s", err, doc)
		}
		found = rule
		ok = true
		return true
	})
	if !ok {
		t.Fatalf("ratls-mesh PrometheusRule not found in helm template output\n%s", helmOut)
	}
	return found
}

// TestChartRATLSRoutingAlerts pins routing-path alerts that fire on signals
// downstream consumers should not have to reconstruct by hand: a wedged
// iptables-sync sidecar (its in-process counters stop publishing), unavailable
// local CIDR route cross-checking, and direct dials to :15001 outside the
// REDIRECT path. Drop any alert and a refactor of
// prometheus-rules.yaml could silently lose the corresponding production
// signal.
func TestChartRATLSRoutingAlerts(t *testing.T) {
	out, err := helmTemplate(t, "--set", "ratlsMesh.prometheusRules.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	rule := findRATLSMeshPrometheusRule(t, out)

	want := map[string]string{
		"RATLSMeshIptablesSyncWedged":             "ratls_mesh_iptables_metrics_file_updated_at_seconds",
		"RATLSMeshLocalCIDRRouteCheckUnavailable": "ratls_mesh_resolver_local_cidrs == 0",
		"RATLSMeshOutboundDirectDial":             `reason="host_addr"`,
		"RATLSMeshIptablesIPSetOverflow":          "ratls_mesh_iptables_ipset_overflow_total",
		"RATLSMeshJumpPositionViolations":         "ratls_mesh_iptables_jump_position_violations_total",
	}
	got := make(map[string]string)
	for _, g := range rule.Spec.Groups {
		for _, r := range g.Rules {
			if _, ok := want[r.Alert]; ok {
				got[r.Alert] = r.Expr
			}
		}
	}
	for alert, exprSubstr := range want {
		expr, ok := got[alert]
		if !ok {
			t.Errorf("alert %q missing from rendered PrometheusRule", alert)
			continue
		}
		if !strings.Contains(expr, exprSubstr) {
			t.Errorf("alert %q expr does not reference %q: got %q", alert, exprSubstr, expr)
		}
	}
}

// terminationGracePeriod minus drainTimeout (both Go-style durations) is the
// budget left for the iptables-cleanup preStop sleep. A higher value is
// silently truncated at runtime by SIGKILL, leaking managed chains/ipsets
// across the pod restart. The chart fails the install instead of letting
// that misconfig ship. The bound is derived, not hardcoded, so changes to
// either underlying value reshape it automatically.
func TestChartRejectsExcessivePreStopSleep(t *testing.T) {
	out, err := helmTemplate(t, "--set", "ratlsMesh.iptablesCleanup.preStopSleepSeconds=30")
	if err == nil {
		t.Fatalf("helm template succeeded, want preStopSleepSeconds upper-bound failure\n%s", out)
	}
	failure := parsePreStopBoundFailure(t, out)
	if want := (preStopBoundFailure{Cmp: "le", Bound: 15, Got: 30}); failure != want {
		t.Fatalf("preStop upper-bound failure = %+v, want %+v", failure, want)
	}
}

func TestChartRejectsNegativePreStopSleep(t *testing.T) {
	out, err := helmTemplate(t, "--set", "ratlsMesh.iptablesCleanup.preStopSleepSeconds=-1")
	if err == nil {
		t.Fatalf("helm template succeeded, want preStopSleepSeconds lower-bound failure\n%s", out)
	}
	failure := parsePreStopBoundFailure(t, out)
	if want := (preStopBoundFailure{Cmp: "ge", Bound: 0, Got: -1}); failure != want {
		t.Fatalf("preStop lower-bound failure = %+v, want %+v", failure, want)
	}
}

// TestChartRejectsOperatorKeysPath pins the path-vs-content guard: a
// cds.operatorKeys value that is a filesystem path (or any non-PEM string)
// must fail the render with an instructive message, not ship a ConfigMap CDS
// will refuse at startup.
func TestChartRejectsOperatorKeysPath(t *testing.T) {
	out, err := helmTemplate(t, "--set", "cds.operatorKeys=/home/user/public.pem")
	if err == nil {
		t.Fatalf("helm template succeeded, want operatorKeys content-guard failure\n%s", out)
	}
	assertHelmFailMessage(t, out, "cds.operatorKeys must be the PEM content of the operator public-key bundle, not a file path — use `c8s install --operator-keys <file>`, `c8s render-values --operator-keys <file>`, or helm --set-file cds.operatorKeys=<file>")
}

func TestChartRendersOperatorKeysPEM(t *testing.T) {
	pemText := "-----BEGIN PUBLIC KEY-----\nMFkwfakefakefake\n-----END PUBLIC KEY-----\n"
	path := filepath.Join(t.TempDir(), "operator.pub")
	if err := os.WriteFile(path, []byte(pemText), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	out, err := helmTemplate(t, "--set-file", "cds.operatorKeys="+path)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cm := renderedConfigMap(t, out, "c8s-cds-operator-keys")
	if got := cm.Data["keys.pem"]; got != pemText {
		t.Fatalf("operator-keys ConfigMap keys.pem = %q, want the PEM content %q", got, pemText)
	}
}

func TestChartAcceptsPreStopSleepAtBoundary(t *testing.T) {
	out, err := helmTemplate(t, "--set", "ratlsMesh.iptablesCleanup.preStopSleepSeconds=15")
	if err != nil {
		t.Fatalf("helm template at boundary should succeed: %v\n%s", err, out)
	}
	ds := findRATLSMeshDaemonSet(t, out)
	cleanup, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "iptables-cleanup")
	if !ok {
		t.Fatalf("iptables-cleanup init container missing")
	}
	command := strings.Join(cleanup.Command, " ")
	if !strings.Contains(command, "--settle-delay=15s") {
		t.Fatalf("iptables-cleanup did not render the boundary settle delay: %q", command)
	}
}

// Tuning terminationGracePeriod or drainTimeout must reshape the preStop
// bound automatically — otherwise the bound goes stale silently once an
// operator changes either knob. Exercising mixed unit forms (h, m, s) also
// pins that the durationSeconds helper handles each correctly.
func TestChartPreStopBoundFollowsGracePeriodAndDrain(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "ratlsMesh.terminationGracePeriod=2m",
		"--set-string", "ratlsMesh.drainTimeout=60s",
		"--set", "ratlsMesh.iptablesCleanup.preStopSleepSeconds=45",
	)
	if err != nil {
		t.Fatalf("helm template at (tgp=2m, drain=60s, sleep=45) should succeed: %v\n%s", err, out)
	}
	ds := findRATLSMeshDaemonSet(t, out)
	if ds.Spec.Template.Spec.TerminationGracePeriodSeconds == nil {
		t.Fatalf("DaemonSet.terminationGracePeriodSeconds is nil")
	}
	if got := *ds.Spec.Template.Spec.TerminationGracePeriodSeconds; got != 120 {
		t.Errorf("terminationGracePeriodSeconds = %d, want 120 (from 2m)", got)
	}
	args := containerArgs(t, ds, "ratls-mesh")
	if got, ok := containerArgValue(args, "--drain-timeout"); !ok || got != "60s" {
		t.Errorf("--drain-timeout = (%q, %v), want (\"60s\", true)", got, ok)
	}

	// Same knobs, sleep one above the derived bound — must fail.
	out, err = helmTemplate(t,
		"--set-string", "ratlsMesh.terminationGracePeriod=2m",
		"--set-string", "ratlsMesh.drainTimeout=60s",
		"--set", "ratlsMesh.iptablesCleanup.preStopSleepSeconds=61",
	)
	if err == nil {
		t.Fatalf("helm template succeeded above derived bound, want failure\n%s", out)
	}
	failure := parsePreStopBoundFailure(t, out)
	if want := (preStopBoundFailure{Cmp: "le", Bound: 60, Got: 61}); failure != want {
		t.Fatalf("derived-bound failure = %+v, want %+v", failure, want)
	}
}

// drainTimeout ≥ terminationGracePeriod leaves zero preStop budget — even a
// 0-second sleep can race shutdown. Fail rather than render a useless
// DaemonSet.
func TestChartRejectsZeroPreStopBudget(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "ratlsMesh.terminationGracePeriod=30s",
		"--set-string", "ratlsMesh.drainTimeout=30s",
	)
	if err == nil {
		t.Fatalf("helm template succeeded with zero preStop budget, want failure\n%s", out)
	}
	failure := parseGracePeriodBudgetFailure(t, out)
	if want := (gracePeriodBudgetFailure{GracePeriod: "30s", Drain: "30s"}); failure != want {
		t.Fatalf("zero-budget failure = %+v, want %+v", failure, want)
	}
}

// Reject duration formats the helper intentionally doesn't support so a
// typo doesn't silently degrade the bound arithmetic via sprig's lenient
// int parsing (which would otherwise read "1m30s" as 1 second).
func TestChartRejectsCompoundDurations(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "ratlsMesh.drainTimeout=1m30s",
	)
	if err == nil {
		t.Fatalf("helm template succeeded for compound duration, want failure\n%s", out)
	}
	failure := parseDurationFormatFailure(t, out)
	if want := (durationFormatFailure{Value: "1m30s", Reason: "non-integer"}); failure != want {
		t.Fatalf("compound-duration failure = %+v, want %+v", failure, want)
	}
}

// Pin the suffix-only rejection separately so a future refactor of the
// helper can't remove the unit check without flagging in tests.
func TestChartRejectsUnitlessDuration(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "ratlsMesh.drainTimeout=30",
	)
	if err == nil {
		t.Fatalf("helm template succeeded for unitless duration, want failure\n%s", out)
	}
	failure := parseDurationFormatFailure(t, out)
	if want := (durationFormatFailure{Value: "30", Reason: "no-unit"}); failure != want {
		t.Fatalf("unitless-duration failure = %+v, want %+v", failure, want)
	}
}

func TestChartRendersRATLSCustomOutboundPortConsistently(t *testing.T) {
	out, err := helmTemplate(t, "--set", "ratlsMesh.ports.outbound=16001")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := findRATLSMeshDaemonSet(t, out)
	sync, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "iptables-sync")
	if !ok {
		t.Fatalf("iptables-sync init container missing; have %v", containerNames(ds.Spec.Template.Spec.InitContainers))
	}
	if !argvContainsFlagValue(sync.Command, "--outbound-port", "16001") {
		t.Fatalf("iptables-sync missing --outbound-port 16001; command=%q", sync.Command)
	}
	meshArgs := containerArgs(t, ds, "ratls-mesh")
	if got, ok := containerArgValue(meshArgs, "--outbound-port"); !ok || got != "16001" {
		t.Fatalf("ratls-mesh --outbound-port = (%q, %v), want (\"16001\", true)", got, ok)
	}
	for _, c := range allContainers(ds) {
		if argvContainsFlagValue(c.Command, "--outbound-port", "15001") || argvContainsFlagValue(c.Args, "--outbound-port", "15001") {
			t.Fatalf("container %q rendered the default outbound port despite override", c.Name)
		}
	}
}

func TestChartCanDisableStatusMirror(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertContainerHasArg(t, "operator", renderedOperatorArgs(t, out), "--status-mirror-enabled=true")

	out, err = helmTemplate(t, "--set", "statusMirror.enabled=false")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertContainerHasArg(t, "operator", renderedOperatorArgs(t, out), "--status-mirror-enabled=false")
}

func TestChartWebhookInjectsWorkloadsAndExcludesSystemNamespaces(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// router now self-renders get-cert, so the platform-pods rule that only
	// existed to inject it is gone: one workload webhook remains.
	names := renderedMutatingWebhookNames(t, out)
	if !slices.Equal(names, []string{"pods.c8s.confidential.ai"}) {
		t.Fatalf("webhook names = %v, want only the workload rule", names)
	}

	generalWebhook := renderedMutatingWebhook(t, out, "pods.c8s.confidential.ai")
	excludedNamespaces := selectorExpressionValues(generalWebhook.NamespaceSelector, "kubernetes.io/metadata.name", metav1.LabelSelectorOpNotIn)
	for _, want := range []string{"c8s-system", "kube-system", "kube-public", "kube-node-lease"} {
		if !slices.Contains(excludedNamespaces, want) {
			t.Fatalf("general webhook namespaceSelector missing excluded namespace %q: %v", want, excludedNamespaces)
		}
	}
}

func TestChartWebhookExtraExcludedFlowsToWebhookAndSweep(t *testing.T) {
	out, err := helmTemplate(t, "--set", "webhook.extraExcluded={tenant-a,tenant-b}")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// extraExcluded must reach both the webhook namespaceSelector (CREATE-time
	// exclusion) and the operator's reinject sweep (--exclude-namespaces), or
	// the two disagree on which namespaces are out of scope.
	generalWebhook := renderedMutatingWebhook(t, out, "pods.c8s.confidential.ai")
	excluded := selectorExpressionValues(generalWebhook.NamespaceSelector, "kubernetes.io/metadata.name", metav1.LabelSelectorOpNotIn)
	args := renderedOperatorArgs(t, out)
	for _, ns := range []string{"tenant-a", "tenant-b"} {
		if !slices.Contains(excluded, ns) {
			t.Fatalf("webhook namespaceSelector missing extraExcluded %q: %v", ns, excluded)
		}
		if !slices.Contains(args, "--exclude-namespaces="+ns) {
			t.Fatalf("operator args missing --exclude-namespaces=%s\n%v", ns, args)
		}
	}
}

// TestChartWebhookOptsOutOfAKSAdmissionsEnforcer proves the AKS workaround:
// with attestationApi.cvmMode=aks (what `c8s install --cvm-mode aks` sets) the
// pod-injector MutatingWebhookConfiguration carries
// admissions.enforcer/disabled=true, so AKS's admissionsenforcer controller
// stops rewriting the webhook namespaceSelector and conflicting with helm
// re-applies. The default (node) must NOT carry it — the annotation is
// pure AKS plumbing and shouldn't appear on other platforms. A user-set
// webhook.annotations value flows through alongside it.
func TestChartWebhookOptsOutOfAKSAdmissionsEnforcer(t *testing.T) {
	const annotation = "admissions.enforcer/disabled"

	// Default (node): no AKS opt-out annotation.
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var def admissionregv1.MutatingWebhookConfiguration
	if !findDoc(t, out, "MutatingWebhookConfiguration", "c8s-pod-injector", &def) {
		t.Fatalf("default chart missing MutatingWebhookConfiguration c8s-pod-injector\n%s", out)
	}
	if _, ok := def.Annotations[annotation]; ok {
		t.Errorf("default (node) webhook must not carry %s; got %v", annotation, def.Annotations)
	}

	// aks: opt-out annotation present and "true".
	out, err = helmTemplate(t, "--set-string", "attestationApi.cvmMode=aks")
	if err != nil {
		t.Fatalf("helm template --set attestationApi.cvmMode=aks: %v\n%s", err, out)
	}
	var aks admissionregv1.MutatingWebhookConfiguration
	if !findDoc(t, out, "MutatingWebhookConfiguration", "c8s-pod-injector", &aks) {
		t.Fatalf("aks chart missing MutatingWebhookConfiguration c8s-pod-injector\n%s", out)
	}
	if got := aks.Annotations[annotation]; got != "true" {
		t.Errorf("aks webhook %s = %q, want \"true\"; annotations=%v", annotation, got, aks.Annotations)
	}

	// A user-supplied annotation coexists with the automatic AKS opt-out.
	out, err = helmTemplate(t,
		"--set-string", "attestationApi.cvmMode=aks",
		"--set-string", "webhook.annotations.team=platform",
	)
	if err != nil {
		t.Fatalf("helm template with extra webhook annotation: %v\n%s", err, out)
	}
	var both admissionregv1.MutatingWebhookConfiguration
	if !findDoc(t, out, "MutatingWebhookConfiguration", "c8s-pod-injector", &both) {
		t.Fatalf("override chart missing MutatingWebhookConfiguration c8s-pod-injector\n%s", out)
	}
	if got := both.Annotations["team"]; got != "platform" {
		t.Errorf("user webhook.annotations.team = %q, want \"platform\"; annotations=%v", got, both.Annotations)
	}
	if got := both.Annotations[annotation]; got != "true" {
		t.Errorf("AKS opt-out must still apply alongside user annotations: %s = %q, want \"true\"", annotation, got)
	}
}

func TestChartManagedRATLSServiceTargetPortsMatchContainerPorts(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	for _, tc := range []struct {
		service    string
		deployment string
		container  string
		want       string
	}{
		{service: "c8s-cds", deployment: "c8s-cds", container: "cds", want: "https"},
	} {
		svc := renderedService(t, out, tc.service)
		if len(svc.Spec.Ports) != 1 {
			t.Fatalf("Service %s ports = %d, want 1", tc.service, len(svc.Spec.Ports))
		}
		if got := svc.Spec.Ports[0].TargetPort.String(); got != tc.want {
			t.Fatalf("Service %s targetPort = %q, want %q", tc.service, got, tc.want)
		}

		container := renderedDeploymentContainer(t, out, tc.deployment, tc.container)
		if _, ok := containerHostPort(container, tc.want); !ok {
			t.Fatalf("Deployment %s container %s missing port named %q; ports=%v", tc.deployment, tc.container, tc.want, container.Ports)
		}
	}
}

// TestChartCDSPinnedToCDSNode proves the CDS Deployment is pinned to the
// cds.node.selector node and tolerates that node's dedicated taint. CDS is a
// singleton trust root reached over a node-local NodePort and (with
// persistence) an RWO volume, so it must land on a known node — independent of
// image policy. Pinning without tolerating the dedicated taint leaves CDS
// Pending, so both must hold.
func TestChartCDSPinnedToCDSNode(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	spec := renderedDeployment(t, out, "c8s-cds").Spec.Template.Spec
	if got := spec.NodeSelector["role"]; got != "cds" {
		t.Errorf("CDS nodeSelector[role] = %q, want %q (CDS must pin to a known node)", got, "cds")
	}
	if !tolerates(spec.Tolerations, "dedicated", "cds") {
		t.Errorf("CDS does not tolerate the dedicated=cds taint; it would stay Pending on a dedicated node: %v", spec.Tolerations)
	}
}

// Both secret path bounds are chart-settable, up to a quota one below the
// ceiling — the largest the guard admits.
func TestChartCDSSecretsPathQuotaFlagsThrough(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  []string
		want []string
	}{
		{"default", nil, []string{"--secrets-max-paths=1024", "--secrets-max-paths-per-workload=64"}},
		{
			"sized",
			[]string{"--set", "cds.secretsMaxPaths=256", "--set", "cds.secretsMaxPathsPerWorkload=8"},
			[]string{"--secrets-max-paths=256", "--secrets-max-paths-per-workload=8"},
		},
		{
			"quota one below the ceiling",
			[]string{"--set", "cds.secretsMaxPaths=256", "--set", "cds.secretsMaxPathsPerWorkload=255"},
			[]string{"--secrets-max-paths=256", "--secrets-max-paths-per-workload=255"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.set...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
			for _, want := range tc.want {
				assertContainerHasArg(t, "cds", args, want)
			}
		})
	}
}

// The pair CDS refuses to start on is refused at template time instead.
func TestChartCDSSecretsQuotaAboveTheCeilingFailsRendering(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  []string
		want string
	}{
		{"at the ceiling", []string{"--set", "cds.secretsMaxPaths=64"}, "kind=cds_secrets_path_budget"},
		{"above the ceiling", []string{"--set", "cds.secretsMaxPaths=32"}, "kind=cds_secrets_path_budget"},
		{"raised quota, default ceiling", []string{"--set", "cds.secretsMaxPathsPerWorkload=1024"}, "kind=cds_secrets_path_budget"},
		{"zero ceiling", []string{"--set", "cds.secretsMaxPaths=0"}, "cds.secretsMaxPaths must be a positive integer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.set...)
			if err == nil {
				t.Fatalf("a quota at or above the ceiling rendered:\n%s", out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("render failed without %q: %v\n%s", tc.want, err, out)
			}
		})
	}
}

func tolerates(tols []corev1.Toleration, key, value string) bool {
	for _, t := range tols {
		if t.Key == key && t.Value == value {
			return true
		}
	}
	return false
}

// TestChartOperatorDialsTrustRootOverHTTPS proves the operator injects get-cert
// with --cds-url over https://, not http://. A regression to http:// would
// silently turn off the bootstrap-channel MITM defence (H1).
func TestChartOperatorDialsTrustRootOverHTTPS(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	const wantURL = "https://c8s-cds.c8s-system.svc:8443"

	operatorArgs := renderedOperatorArgs(t, out)
	assertContainerHasArg(t, "operator", operatorArgs, "--cds-url="+wantURL)
	assertContainerNoArgPrefix(t, "operator", operatorArgs, "--cds-url=http://")
}

// TestChartRatlsMeshCDSMeasurementsFlagsThrough confirms the single
// cds.measurements reaches the daemonset's --cds-measurements flag — without
// this the RA-TLS handshake accepts any measurement and the H1 defence
// collapses to "trust the cluster network". ratls-mesh reads the parent's
// cds.measurements directly, so there is no mirror to drift.
func TestChartRatlsMeshCDSMeasurementsFlagsThrough(t *testing.T) {
	const measurement = "abc1230000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff"
	out, err := helmTemplate(t,
		"--set", "cds.measurements[0]="+measurement,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDaemonSetContainer(t, out, "c8s-ratls-mesh", "ratls-mesh").Args
	i := slices.Index(args, "--cds-measurements")
	if i < 0 || i+1 >= len(args) {
		t.Fatalf("ratls-mesh container missing --cds-measurements <value>\nargs: %v", args)
	}
	if got := args[i+1]; got != measurement {
		t.Fatalf("--cds-measurements = %q, want %q", got, measurement)
	}
}

func TestChartNRIImagePolicyUsesPullMode(t *testing.T) {
	const measurement = "abc1230000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff"
	out, err := helmTemplate(t,
		"--set", "cds.measurements[0]="+measurement,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	workerCfg := renderedNRIBootConfig(t, out, "c8s-nri-image-policy-worker")
	if got, want := workerCfg.Allowlist.Pull.URL, "https://127.0.0.1:30808"; got != want {
		t.Fatalf("worker pull URL = %q, want %q", got, want)
	}
	if got, want := workerCfg.Allowlist.Pull.Interval, "5s"; got != want {
		t.Fatalf("worker pull interval = %q, want %q", got, want)
	}
	if got, want := workerCfg.Allowlist.Pull.AttestationApiURL, "unix:///var/run/nri-image-policy/attestation-api.sock"; got != want {
		t.Fatalf("runtime attestation-api URL = %q, want %q", got, want)
	}
	if want := []string{measurement}; !slices.Equal(workerCfg.Allowlist.Pull.CDSMeasurements, want) {
		t.Fatalf("worker CDS measurements = %v, want %v", workerCfg.Allowlist.Pull.CDSMeasurements, want)
	}
	// Pull-only: the boot config never carries a push block.
	if workerCfg.Allowlist.Push.PersistPath != "" {
		t.Fatalf("worker boot config has push persist path %q, want empty", workerCfg.Allowlist.Push.PersistPath)
	}
}

// The default attestation-api shape publishes nothing routable: no Service at
// all, the API bound to pod loopback, a default-deny NetworkPolicy on the
// DaemonSet pods, and the attest-proxy sidecar serving the on-node Unix
// socket every consumer dials.
func TestChartAttestationApiDefaultsToNodeLocalSocket(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "Service", "c8s-attestation-api") {
		t.Fatalf("default render must not create an attestation-api Service (evidence generation is node-local only)\n%s", out)
	}
	assertNoLegacyAttestationStrings(t, out)

	var np networkingv1.NetworkPolicy
	if !findDoc(t, out, "NetworkPolicy", "c8s-attestation-api", &np) {
		t.Fatalf("default render missing the attestation-api default-deny NetworkPolicy\n%s", out)
	}
	if len(np.Spec.Ingress) != 0 {
		t.Fatalf("default NetworkPolicy must deny all ingress; got rules %+v", np.Spec.Ingress)
	}
	if !slices.Contains(np.Spec.PolicyTypes, networkingv1.PolicyTypeIngress) {
		t.Fatalf("NetworkPolicy policyTypes = %v, want Ingress", np.Spec.PolicyTypes)
	}

	if renderedManifestHasNamedKind(t, out, "Secret", "c8s-attestation-api") {
		t.Fatalf("attestation-api config must render as a ConfigMap, not a Secret\n%s", out)
	}
	cfg := renderedConfigMap(t, out, "c8s-attestation-api").Data["config.toml"]
	if !strings.Contains(cfg, `bind = "127.0.0.1:8400"`) {
		t.Fatalf("default config must bind pod loopback; got:\n%s", cfg)
	}
	if strings.Contains(cfg, "[auth]") {
		t.Fatalf("config must not render [auth] (nothing routable to protect); got:\n%s", cfg)
	}

	ds := renderedDaemonSet(t, out, "c8s-attestation-api")
	proxy := renderedDaemonSetContainer(t, out, "c8s-attestation-api", "attest-proxy")
	assertContainerArgs(t, proxy,
		"attest-proxy",
		"--socket=/var/run/nri-image-policy/attestation-api.sock",
		"--upstream=http://127.0.0.1:8400",
	)
	assertContainerNoArgPrefix(t, "attest-proxy", proxy.Args, "--api-key-file")
	// The proxy publishes into the socket-dir hostPath, and both it and the
	// API read their config from the ConfigMap — dropping either renders
	// fine and only fails at runtime.
	assertPodVolume(t, &ds.Spec.Template.Spec, "socket-dir", func(v corev1.Volume) bool {
		return v.HostPath != nil && v.HostPath.Path == "/var/run/nri-image-policy"
	})
	assertPodVolume(t, &ds.Spec.Template.Spec, "config", func(v corev1.Volume) bool {
		return v.ConfigMap != nil && v.ConfigMap.Name == "c8s-attestation-api"
	})
	assertContainerMount(t, proxy, "socket-dir", "/var/run/nri-image-policy")
	// HTTP (a locked node image denies every runc exec), against
	// the proxy's own health listener: the API's loopback bind is not
	// kubelet-dialable, and this is the evidence path's only liveness signal.
	for name, probe := range map[string]*corev1.Probe{"readiness": proxy.ReadinessProbe, "liveness": proxy.LivenessProbe} {
		if probe == nil || probe.HTTPGet == nil {
			t.Fatalf("attest-proxy must carry an HTTP %s probe; got %+v", name, probe)
		}
		if probe.HTTPGet.Path != "/healthz" || probe.HTTPGet.Port.StrVal != "health" {
			t.Fatalf("attest-proxy %s probe = %+v, want GET /healthz on the health port", name, probe.HTTPGet)
		}
		// Kubelet's 1s default probe timeout would flap the healthcheck's 3s
		// internal budget.
		if probe.TimeoutSeconds != 5 {
			t.Fatalf("attest-proxy %s probe timeoutSeconds = %d, want 5", name, probe.TimeoutSeconds)
		}
	}
	if _, ok := findContainerPort(proxy, "health"); !ok {
		t.Fatalf("attest-proxy must name its health port; got %+v", proxy.Ports)
	}
	// uid 0 owns the socket (clients reject a foreign owner) and gid 65532 is
	// the socket's group — the chgrp works by membership, all caps dropped.
	sc := proxy.SecurityContext
	if sc == nil || sc.RunAsUser == nil || *sc.RunAsUser != 0 || sc.RunAsGroup == nil || *sc.RunAsGroup != 65532 {
		t.Fatalf("attest-proxy must run as uid 0 / gid 65532 (socket owner and group); got %+v", sc)
	}
	if sc.Capabilities == nil || !slices.Contains(sc.Capabilities.Drop, corev1.Capability("ALL")) {
		t.Fatalf("attest-proxy must drop all capabilities; got %+v", sc.Capabilities)
	}
	if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		t.Fatalf("attest-proxy must mount its root filesystem read-only; got %+v", sc.ReadOnlyRootFilesystem)
	}
	// An httpGet probe would never pass against the loopback bind, so the
	// proxy's exec probe is the only health signal.
	api := renderedDaemonSetContainer(t, out, "c8s-attestation-api", "attestation-api")
	if api.ReadinessProbe != nil || api.LivenessProbe != nil {
		t.Fatalf("attestation-api container must not carry kubelet probes against its loopback bind; got %+v / %+v", api.ReadinessProbe, api.LivenessProbe)
	}
}

// assertNoLegacyAttestationStrings keeps the routable shapes the hardening
// removed out of every render: the old NodePort, a wildcard bind, and the
// deleted Service's DNS name.
func assertNoLegacyAttestationStrings(t *testing.T, manifest string) {
	t.Helper()
	for _, legacy := range []string{"30840", "0.0.0.0", "c8s-attestation-api.c8s-system.svc"} {
		if strings.Contains(manifest, legacy) {
			t.Fatalf("render must not contain legacy routable-attestation string %q", legacy)
		}
	}
}

func assertPodVolume(t *testing.T, spec *corev1.PodSpec, name string, ok func(corev1.Volume) bool) {
	t.Helper()
	for _, v := range spec.Volumes {
		if v.Name == name {
			if !ok(v) {
				t.Fatalf("volume %q has the wrong source: %+v", name, v.VolumeSource)
			}
			return
		}
	}
	t.Fatalf("pod spec missing volume %q; volumes %+v", name, spec.Volumes)
}

func assertContainerMount(t *testing.T, c corev1.Container, name, mountPath string) {
	t.Helper()
	for _, m := range c.VolumeMounts {
		if m.Name == name && m.MountPath == mountPath {
			return
		}
	}
	t.Fatalf("container %s missing mount of volume %q at %q; mounts %+v", c.Name, name, mountPath, c.VolumeMounts)
}

// The host NRI plugin is a host process: it reaches the attestation-api over
// the node-local Unix socket, never the pod network.
func TestChartAttestationApiSocketWiresNRI(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedNRIBootConfig(t, out, "c8s-nri-image-policy-worker")
	if got, want := cfg.Allowlist.Pull.AttestationApiURL, "unix:///var/run/nri-image-policy/attestation-api.sock"; got != want {
		t.Fatalf("runtime attestation-api URL = %q, want %q", got, want)
	}
}

// The require_host_image_policy guard exempts cvmMode=bare-metal: the node image bakes
// its own fail-closed nri-image-policy, so nri off there is not an unenforced
// cluster. The served seed under this shape is covered by
// TestChartServesAllowlistSeedInBareMetalMode.
func TestChartAllowsImagePolicyOffInBareMetalMode(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "attestationApi.cvmMode=bare-metal",
		"--set", "nriImagePolicy.enabled=false",
	)
	if err != nil {
		t.Fatalf("helm template rejected cvmMode=bare-metal with nri off, want success (the node image bakes the plugin)\n%s", out)
	}
}

func TestChartRejectsPlaintextNRIAllowlist(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "nriImagePolicy.cds.url=http://c8s-cds.c8s-system.svc:8443",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want plaintext NRI allowlist failure\n%s", out)
	}
	assertHelmFailMessage(t, out, `nriImagePolicy.cds.url must start with https:// when nriImagePolicy.enabled=true (got "http://c8s-cds.c8s-system.svc:8443"): the host plugin must fetch the allowlist over RA-TLS`)
}

// parseValidationErrorKind extracts kind=<id> from helm's stderr when the
// chart's `fail` message starts with `VALIDATION_ERROR kind=<id>:`. Returns
// empty string if the marker is absent.
func parseValidationErrorKind(helmOutput string) string {
	re := regexp.MustCompile(`VALIDATION_ERROR kind=([a-z0-9_]+)`)
	m := re.FindStringSubmatch(helmOutput)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

func assertContainerHasArg(t *testing.T, container string, args []string, want string) {
	t.Helper()
	if !slices.Contains(args, want) {
		t.Fatalf("%s container missing arg %q\nargs: %v", container, want, args)
	}
}

func assertContainerNoArgPrefix(t *testing.T, container string, args []string, prefix string) {
	t.Helper()
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			t.Fatalf("%s container has unexpected arg with prefix %q: %q\nargs: %v", container, prefix, arg, args)
		}
	}
}

func assertContainerHasArgPrefix(t *testing.T, container string, args []string, prefix string) {
	t.Helper()
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			return
		}
	}
	t.Fatalf("%s container missing arg with prefix %q\nargs: %v", container, prefix, args)
}

// renderedManifestHasLabel reports whether any rendered doc carries the label,
// on its own metadata or its pod template.
func renderedManifestHasLabel(t *testing.T, manifest, key, value string) bool {
	t.Helper()
	found := false
	iterateManifests(t, manifest, func(doc []byte) bool {
		var obj struct {
			Metadata struct {
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec struct {
				Template struct {
					Metadata struct {
						Labels map[string]string `json:"labels"`
					} `json:"metadata"`
				} `json:"template"`
			} `json:"spec"`
		}
		if err := sigsyaml.Unmarshal(doc, &obj); err != nil {
			return false
		}
		if obj.Metadata.Labels[key] == value || obj.Spec.Template.Metadata.Labels[key] == value {
			found = true
			return true
		}
		return false
	})
	return found
}

// renderedWorkload is a pod-bearing manifest (Deployment, DaemonSet,
// StatefulSet, Job) with its decoded pod spec.
type renderedWorkload struct {
	kind, name string
	spec       corev1.PodSpec
}

func renderedPodSpecs(t *testing.T, manifest string) []renderedWorkload {
	t.Helper()
	var out []renderedWorkload
	iterateManifests(t, manifest, func(doc []byte) bool {
		var obj struct {
			docMeta
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := sigsyaml.Unmarshal(doc, &obj); err != nil {
			return false
		}
		switch obj.Kind {
		case "Deployment", "DaemonSet", "StatefulSet", "Job":
			out = append(out, renderedWorkload{obj.Kind, obj.Metadata.Name, obj.Spec.Template.Spec})
		}
		return false
	})
	return out
}

// findKey returns a dotted path to the first occurrence of key anywhere in a
// decoded YAML tree, or "" if absent.
func findKey(node any, key string) string {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			if k == key {
				return k
			}
			if p := findKey(child, key); p != "" {
				return k + "." + p
			}
		}
	case []any:
		for i, child := range v {
			if p := findKey(child, key); p != "" {
				return fmt.Sprintf("[%d].%s", i, p)
			}
		}
	}
	return ""
}

// The renewal interval the operator hands every injected sidecar must be
// strictly below the shortest TTL CDS issues. cds.namedCertTTL is that TTL — a
// named leaf's — and nothing backdates NotBefore, so an interval at or above it
// would only fire once the installed leaf had already expired. get-cert paces
// off the leaf's own NotAfter as a backstop, but the chart's own defaults must
// not need it.
func TestChartGetCertRenewIntervalIsBelowNamedCertTTL(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	renew := durationArg(t, renderedOperatorArgs(t, out), "--get-cert-renew-interval=")
	named := durationArg(t, renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args, "--named-cert-ttl=")
	certTTL := durationArg(t, renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args, "--cert-ttl=")

	if renew >= named {
		t.Fatalf("webhook.getCert.renewInterval %v >= cds.namedCertTTL %v: an injected sidecar would renew at or after its leaf expired", renew, named)
	}
	if renew >= certTTL {
		t.Fatalf("webhook.getCert.renewInterval %v >= cds.certTTL %v", renew, certTTL)
	}
}

// durationArg extracts and parses the value of the first arg carrying prefix.
func durationArg(t *testing.T, args []string, prefix string) time.Duration {
	t.Helper()
	for _, a := range args {
		if raw, ok := strings.CutPrefix(a, prefix); ok {
			d, err := time.ParseDuration(raw)
			if err != nil {
				t.Fatalf("parse %s%s: %v", prefix, raw, err)
			}
			return d
		}
	}
	t.Fatalf("args missing %s\n%v", prefix, args)
	return 0
}

func TestChartWebhookRendersSecurityKnobs(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "webhook.certVolume.fsGroup=4242",
		"--set-string", "webhook.getCert.renewInterval=3h",
		"--set", "webhook.getCert.runAsUser=0",
		"--set", "webhook.getCert.runAsGroup=0",
		"--set", "webhook.getCert.runAsNonRoot=false",
		"--set", "ratlsMesh.enabled=false",
		"--set", "router.enabled=false",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !renderedManifestHasKind(t, out, "MutatingWebhookConfiguration") {
		t.Fatalf("render missing MutatingWebhookConfiguration\n%s", out)
	}
	args := renderedOperatorArgs(t, out)
	for _, want := range []string{
		"--cds-url=https://c8s-cds.c8s-system.svc:8443",
		"--cert-fs-group=4242",
		"--get-cert-renew-interval=3h",
		"--get-cert-run-as-user=0",
		"--get-cert-run-as-group=0",
		"--get-cert-run-as-non-root=false",
	} {
		if !slices.Contains(args, want) {
			t.Fatalf("operator args missing %q\n%v", want, args)
		}
	}
}

// A -f values file decodes ints as float64; helm renders float64 >= 1e6 as
// scientific notation (7000000 -> 7e+06), which is invalid in a numeric
// securityContext field and a type error in CEL. c8s.int must keep these plain
// integers. This drives the bug's actual path (a -f file, value >= 1e6), which
// --set does not reproduce.
func TestChartIntValuesFromValuesFileRenderPlain(t *testing.T) {
	dir := t.TempDir()
	vals := filepath.Join(dir, "vals.yaml")
	if err := os.WriteFile(vals, []byte(
		"ratlsMesh:\n  uid: 7000000\n"+
			"router:\n  nginx:\n    runAsUser: 7000000\n    runAsGroup: 7000000\n"+
			"webhook:\n  certVolume:\n    fsGroup: 1500000\n  getCert:\n    runAsUser: 2000000000\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := helmTemplate(t, "-f", vals)
	if err != nil {
		t.Fatalf("helm template -f: %v\n%s", err, out)
	}
	// Each affected field is asserted through its decoded typed value; a
	// scientific-notation render (7e+06) fails the int decode loudly.
	args := renderedOperatorArgs(t, out)
	assertContainerHasArg(t, "operator", args, "--cert-fs-group=1500000")
	assertContainerHasArg(t, "operator", args, "--get-cert-run-as-user=2000000000")
	nginx := renderedDeploymentContainer(t, out, "c8s-router", "nginx")
	if got := nginx.SecurityContext.RunAsUser; got == nil || *got != 7000000 {
		t.Errorf("nginx runAsUser = %v, want 7000000", got)
	}
	if got := nginx.SecurityContext.RunAsGroup; got == nil || *got != 7000000 {
		t.Errorf("nginx runAsGroup = %v, want 7000000", got)
	}
	mesh := renderedDaemonSetContainer(t, out, "c8s-ratls-mesh", "ratls-mesh")
	if got := mesh.SecurityContext.RunAsUser; got == nil || *got != 7000000 {
		t.Errorf("ratls-mesh runAsUser = %v, want 7000000", got)
	}
	// The CEL admission policy, where int != double would be an uninstallable
	// compile error.
	var policy admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, out, "ValidatingAdmissionPolicy", "deny-ratls-mesh-uid", &policy) {
		t.Fatalf("missing deny-ratls-mesh-uid ValidatingAdmissionPolicy\n%s", out)
	}
	if !slices.ContainsFunc(policy.Spec.Validations, func(v admissionregv1.Validation) bool {
		return strings.Contains(v.Expression, "runAsUser != 7000000")
	}) {
		t.Errorf("uid policy expression missing the plain-integer comparison: %+v", policy.Spec.Validations)
	}
}

// c8s.int must fail the render on a non-integer rather than silently coercing to
// 0 (sprig int64's fail-open behavior — 0 is root). Guards against a malformed
// hand-written -f.
func TestChartIntValueRejectsNonInteger(t *testing.T) {
	dir := t.TempDir()
	vals := filepath.Join(dir, "vals.yaml")
	if err := os.WriteFile(vals, []byte("webhook:\n  getCert:\n    runAsUser: notanumber\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := helmTemplate(t, "-f", vals)
	if err == nil {
		t.Fatalf("expected render to fail on a non-integer runAsUser, got success:\n%s", out)
	}
	if !strings.Contains(out, "expected an integer") {
		t.Errorf("want 'expected an integer' error, got: %s", out)
	}
}

// TestChartAttestationApiPrivileged proves every cvmMode renders privileged:
// true. A hostPath device mount does not add a device-cgroup rule, so open() on
// the TEE device (/dev/sev-guest, /dev/tpm0) is EPERM from an unprivileged
// container regardless of SYS_RAWIO (cgroup v2 eBPF device controller); aks
// additionally gates the vTPM below the capability layer. TODO: revert to
// least-privilege once SNP attest goes through the TSM configfs report
// interface.
func TestChartAttestationApiPrivileged(t *testing.T) {
	for _, tc := range []struct {
		mode string
		// node is the chart default, so render it via the no-arg path to
		// also guard that a plain install is privileged.
		useDefault bool
		// aks renders the privilege axis only — it must NOT also carry the
		// least-privilege capabilities map (the modes are either/or, not merged).
		noCapabilities bool
	}{
		{mode: "bare-metal", useDefault: true},
		{mode: "gke"},
		{mode: "aks", noCapabilities: true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			var args []string
			if !tc.useDefault {
				args = []string{"--set", "attestationApi.cvmMode=" + tc.mode}
			}
			out, err := helmTemplate(t, args...)
			if err != nil {
				t.Fatalf("helm template (cvmMode=%s): %v\n%s", tc.mode, err, out)
			}
			c := renderedDaemonSetContainer(t, out, "c8s-attestation-api", "attestation-api")
			sc := c.SecurityContext
			if sc == nil || sc.Privileged == nil || !*sc.Privileged {
				t.Errorf("%s must be privileged for device access; got %+v", tc.mode, sc)
			}
			if tc.noCapabilities && sc != nil && sc.Capabilities != nil {
				t.Errorf("%s must not carry the least-privilege capabilities map; got %+v", tc.mode, sc.Capabilities)
			}
		})
	}
}

// TestChartAttestationApiInvalidCvmMode proves an unrecognized cvmMode fails
// the render loudly rather than silently falling through to least-privilege
// (which would fail closed at runtime on an AKS CVM).
func TestChartAttestationApiInvalidCvmMode(t *testing.T) {
	for _, mode := range []string{"bogus", "baremetal", "pod"} {
		t.Run(mode, func(t *testing.T) {
			out, err := helmTemplate(t, "--set-string", "attestationApi.cvmMode="+mode)
			if err == nil {
				t.Fatalf("expected render to fail on invalid cvmMode; got success\n%s", out)
			}
			assertHelmFailMessage(t, out, fmt.Sprintf(`attestationApi.cvmMode must be one of bare-metal, gke, aks (got %q)`, mode))
		})
	}
}

// hasHostIPEnv reports whether the container carries a HOST_IP env var sourced
// from the status.hostIP downward-API field — the substitution source for the
// $(HOST_IP) placeholder in the bare-metal-mode attestation-api URL.
func hasHostIPEnv(c corev1.Container) bool {
	for _, e := range c.Env {
		if e.Name == "HOST_IP" && e.ValueFrom != nil && e.ValueFrom.FieldRef != nil &&
			e.ValueFrom.FieldRef.FieldPath == "status.hostIP" {
			return true
		}
	}
	return false
}

// TestChartBareMetalModeAttestationApiURLUsesHostIP proves cvmMode=bare-metal points the
// pod-netns components (cds, router's cert sidecar, ratls-mesh) at the
// node-baked host attestation-api via the $(HOST_IP) downward-API env var, since
// there is no in-cluster Service and pods cannot reach host loopback. The
// operator is the exception: it forwards its --attestation-api-url verbatim into
// the tenant get-cert sidecars it injects, so the placeholder must stay
// UNEXPANDED there — the operator container deliberately omits HOST_IP so each
// tenant pod expands it against its own node.
// KNOWN-GAP (ATTEST-ORACLE, bare-metal mode): the http://$(HOST_IP):8400 wiring
// this test pins reaches the node image's baked attestation-api, which still
// binds 0.0.0.0:8400 with no auth — the oracle shape this branch removes
// everywhere the chart controls. Closing bare-metal mode needs the
// confidential-os-builder companion (loopback bind + baked attest-proxy
// systemd unit + image-policy socket URL), tracked cross-repo; when it
// lands, the chart's bare-metal-mode branch and this test flip to the socket shape
// together.
func TestChartBareMetalModeAttestationApiURLUsesHostIP(t *testing.T) {
	const hostIPURL = "--attestation-api-url=http://$(HOST_IP):8400"
	// The exact shape `c8s install --cvm-mode=bare-metal` produces: the node image
	// bakes attestation-api and nri-image-policy, so both chart components
	// are off and consumers dial the baked host service via $(HOST_IP).
	out, err := helmTemplate(t,
		"--set-string", "attestationApi.cvmMode=bare-metal",
		"--set", "attestationApi.enabled=false",
		"--set", "nriImagePolicy.enabled=false",
		"--set", "router.attest.enabled=true",
	)
	if err != nil {
		t.Fatalf("helm template (cvmMode=bare-metal): %v\n%s", err, out)
	}

	// No chart-managed evidence source renders in this shape at all.
	if renderedManifestHasNamedKind(t, out, "Service", "c8s-attestation-api") ||
		renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-attestation-api") {
		t.Fatalf("cvmMode=bare-metal install shape renders no attestation-api Service or DaemonSet\n%s", out)
	}

	// cds: pod-netns, dials the host attestation-api via $(HOST_IP).
	cds := renderedDeploymentContainer(t, out, "c8s-cds", "cds")
	assertContainerArgs(t, cds, hostIPURL)
	if !hasHostIPEnv(cds) {
		t.Errorf("cds container missing HOST_IP downward-API env; have %+v", cds.Env)
	}

	// router c8s-cert sidecar (via c8s.getCertContainers).
	cert := routerGetCertContainer(t, out, "c8s-cert")
	assertContainerArgs(t, cert, hostIPURL)
	if !hasHostIPEnv(cert) {
		t.Errorf("router c8s-cert missing HOST_IP downward-API env; have %+v", cert.Env)
	}

	// router cds-attest sidecar (rendered under router.attest.enabled).
	attest := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	assertContainerArgs(t, attest, hostIPURL)
	if !hasHostIPEnv(attest) {
		t.Errorf("router cds-attest missing HOST_IP downward-API env; have %+v", attest.Env)
	}

	// router allowlist proxy: pod-netns, uses the same verifier endpoint for
	// the RA-TLS hop to CDS.
	allowlistProxy := renderedDeploymentContainer(t, out, "c8s-router", "allowlist-proxy")
	assertContainerArgs(t, allowlistProxy, hostIPURL)
	if !hasHostIPEnv(allowlistProxy) {
		t.Errorf("router allowlist-proxy missing HOST_IP downward-API env; have %+v", allowlistProxy.Env)
	}

	// ratls-mesh: hostNetwork, so $(HOST_IP) is its own node IP. Two-arg form.
	mesh := renderedDaemonSetContainer(t, out, "c8s-ratls-mesh", "ratls-mesh")
	if !slices.Contains(mesh.Args, "http://$(HOST_IP):8400") {
		t.Errorf("ratls-mesh missing http://$(HOST_IP):8400 arg; have %v", mesh.Args)
	}
	if !hasHostIPEnv(mesh) {
		t.Errorf("ratls-mesh missing HOST_IP downward-API env; have %+v", mesh.Env)
	}

	// operator: forwards the string verbatim; the placeholder must NOT be
	// expanded here, so the container must NOT define HOST_IP.
	if !slices.Contains(renderedOperatorArgs(t, out), hostIPURL) {
		t.Errorf("operator missing verbatim %q\n%v", hostIPURL, renderedOperatorArgs(t, out))
	}
	op := renderedDeploymentContainer(t, out, "c8s-operator", "operator")
	if hasHostIPEnv(op) {
		t.Errorf("operator MUST NOT define HOST_IP (it forwards $(HOST_IP) verbatim to tenant sidecars); env %+v", op.Env)
	}
}

// TestChartNonBareMetalModeUsesAttestationSocket proves the bare-metal-mode wiring does
// not leak into the other cvmModes: gke/aks dial the on-node Unix socket
// and render no HOST_IP env anywhere. The consumers that must carry both the
// socket URL and the socket-directory mount are asserted per shape.
func TestChartNonBareMetalModeUsesAttestationSocket(t *testing.T) {
	const socketURL = "--attestation-api-url=unix:///var/run/nri-image-policy/attestation-api.sock"
	for _, mode := range []string{"gke", "aks"} {
		t.Run(mode, func(t *testing.T) {
			out, err := helmTemplate(t, "--set-string", "attestationApi.cvmMode="+mode, "--set", "router.attest.enabled=true")
			if err != nil {
				t.Fatalf("helm template (cvmMode=%s): %v\n%s", mode, err, out)
			}
			// The acceptance criteria are per-mode: no routable path to
			// evidence generation, and the default-deny NetworkPolicy on the
			// DaemonSet.
			if renderedManifestHasNamedKind(t, out, "Service", "c8s-attestation-api") {
				t.Fatalf("cvmMode=%s renders no attestation-api Service (evidence generation is node-local only)\n%s", mode, out)
			}
			assertNoLegacyAttestationStrings(t, out)
			var np networkingv1.NetworkPolicy
			if !findDoc(t, out, "NetworkPolicy", "c8s-attestation-api", &np) || len(np.Spec.Ingress) != 0 {
				t.Fatalf("cvmMode=%s renders the attestation-api default-deny NetworkPolicy; got %+v", mode, np.Spec.Ingress)
			}
			cds := renderedDeploymentContainer(t, out, "c8s-cds", "cds")
			assertContainerArgs(t, cds, socketURL)
			// Every consumer of the socket URL must also mount the socket
			// directory (read-only), at the host path so the URL is verbatim.
			assertHasSocketMount := func(c corev1.Container) {
				t.Helper()
				for _, m := range c.VolumeMounts {
					if m.Name == "attestation-api-socket" && m.MountPath == "/var/run/nri-image-policy" && m.ReadOnly {
						return
					}
				}
				t.Errorf("container %s carries the socket URL but no attestation-api-socket mount; mounts %+v", c.Name, c.VolumeMounts)
			}
			assertHasSocketMount(cds)
			mesh := renderedDaemonSetContainer(t, out, "c8s-ratls-mesh", "ratls-mesh")
			if !slices.Contains(mesh.Args, "unix:///var/run/nri-image-policy/attestation-api.sock") {
				t.Errorf("ratls-mesh missing the socket URL arg; have %v", mesh.Args)
			}
			assertHasSocketMount(mesh)
			if sc := renderedDaemonSet(t, out, "c8s-ratls-mesh").Spec.Template.Spec.SecurityContext; sc == nil || !slices.Contains(sc.SupplementalGroups, int64(65532)) {
				t.Errorf("ratls-mesh pod must carry supplementalGroups [65532] to connect to the socket; got %+v", sc)
			}
			assertHasSocketMount(routerGetCertContainer(t, out, "c8s-cert"))
			assertHasSocketMount(renderedDeploymentContainer(t, out, "c8s-router", "cds-attest"))
			assertHasSocketMount(renderedDeploymentContainer(t, out, "c8s-router", "allowlist-proxy"))
			for _, w := range renderedPodSpecs(t, out) {
				for _, c := range append(append([]corev1.Container{}, w.spec.InitContainers...), w.spec.Containers...) {
					for _, e := range c.Env {
						if e.Name == "HOST_IP" {
							t.Errorf("cvmMode=%s must not render any HOST_IP env; %s %s container %s carries it", mode, w.kind, w.name, c.Name)
						}
					}
				}
			}
		})
	}
}

func TestChartRendersManagedClusterKnobs(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "serviceAccount.imagePullSecrets[0].name=ghcr-secret",
		"--set", "attestationApi.cvmMode=aks",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var sa corev1.ServiceAccount
	if !findDoc(t, out, "ServiceAccount", "c8s-operator", &sa) {
		t.Fatalf("render missing ServiceAccount c8s-operator\n%s", out)
	}
	if !hasPullSecret(sa.ImagePullSecrets, "ghcr-secret") {
		t.Fatalf("operator ServiceAccount missing chart-wide pull secret ghcr-secret: %v", sa.ImagePullSecrets)
	}
	// aks → privileged attestation-api with a read-only root filesystem.
	sc := renderedDaemonSetContainer(t, out, "c8s-attestation-api", "attestation-api").SecurityContext
	if sc == nil || sc.Privileged == nil || !*sc.Privileged {
		t.Fatalf("attestation-api must be privileged under aks; got %+v", sc)
	}
	if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		t.Fatalf("attestation-api must set readOnlyRootFilesystem: true; got %+v", sc)
	}
}

// TestChartGlobalImagePullSecrets proves the chart-wide imagePullSecrets feeds
// every component, and a per-component value overrides it for that component.
func TestChartGlobalImagePullSecrets(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "imagePullSecrets[0].name=ghcr-pull",
		"--set", "router.imagePullSecrets[0].name=lb-special",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// The global reaches a non-overriding component (ratls-mesh).
	rm := renderedDaemonSet(t, out, "c8s-ratls-mesh")
	if !hasPullSecret(rm.Spec.Template.Spec.ImagePullSecrets, "ghcr-pull") {
		t.Errorf("ratls-mesh missing global pull secret: %v", rm.Spec.Template.Spec.ImagePullSecrets)
	}
	// router's own value overrides the global.
	lb := renderedDeployment(t, out, "c8s-router")
	if hasPullSecret(lb.Spec.Template.Spec.ImagePullSecrets, "ghcr-pull") || !hasPullSecret(lb.Spec.Template.Spec.ImagePullSecrets, "lb-special") {
		t.Errorf("router should use its override, not the global: %v", lb.Spec.Template.Spec.ImagePullSecrets)
	}
}

func hasPullSecret(refs []corev1.LocalObjectReference, name string) bool {
	for _, r := range refs {
		if r.Name == name {
			return true
		}
	}
	return false
}

func TestChartRendersRouterPublicTLSAndDiscovery(t *testing.T) {
	out, err := helmTemplate(t, noUpstreamArgs(
		"--set-string", "router.publicTLS.mode=webpki",
		"--set-string", "router.publicTLS.secretName=router-public-tls",
		"--set-string", "router.publicTLS.mountPath=/edge-tls",
		"--set-string", "router.publicTLS.certKey=public.crt",
		"--set-string", "router.publicTLS.keyKey=public.key",
		"--set", "router.discovery.enabled=true",
		"--set-string", "router.upstream.address=my-backend.other-ns.svc:8443",
		"--set", "router.upstream.protocol=https",
		"--set", "router.upstream.tls.verify=true",
		"--set-string", "router.upstream.tls.serverName=my-backend.other-ns.svc.cluster.local",
	)...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	server := cfg.server(t)
	server.assertDirective(t, "ssl_certificate", "/edge-tls/public.crt")
	server.assertDirective(t, "ssl_certificate_key", "/edge-tls/public.key")
	ciphers := server.directives["ssl_ciphers"]
	if len(ciphers) != 1 || len(ciphers[0]) != 1 ||
		!slices.Contains(strings.Split(ciphers[0][0], ":"), "ECDHE-RSA-AES128-GCM-SHA256") {
		t.Fatalf("ssl_ciphers missing ECDHE-RSA-AES128-GCM-SHA256; got %v", ciphers)
	}
	cfg.location(t, "exact", "/v1/discovery").assertDirective(t, "alias", "/discovery/discovery.json")
	cfg.location(t, "exact", "/.well-known/cds-cert.pem").assertDirective(t, "alias", "/tls/cert.pem")
	cfg.location(t, "exact", "/.well-known/mesh-ca.pem").assertDirective(t, "alias", "/tls/ca.pem")
	defaultRoute := cfg.location(t, "prefix", "/")
	defaultRoute.assertDirective(t, "proxy_ssl_certificate", "/tls/cert.pem")
	defaultRoute.assertDirective(t, "proxy_ssl_certificate_key", "/tls/key.pem")
	defaultRoute.assertDirective(t, "proxy_ssl_name", "my-backend.other-ns.svc.cluster.local")
	defaultRoute.assertDirective(t, "proxy_ssl_verify", "on")
	defaultRoute.assertDirective(t, "proxy_ssl_trusted_certificate", "/tls/cert.pem")
	defaultRoute.assertDirective(t, "proxy_pass", "https://catch_all")
	cfg.upstream(t, "catch_all").assertServer(t, "my-backend.other-ns.svc:8443")

	spec := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
	if _, ok := podVolume(spec, "tls-certs"); !ok {
		t.Fatalf("router missing tls-certs volume; volumes=%v", spec.Volumes)
	}
	pub, ok := podVolume(spec, "public-tls")
	if !ok || pub.Secret == nil || pub.Secret.SecretName != "router-public-tls" {
		t.Fatalf("router public-tls volume must source Secret router-public-tls; got %+v", pub)
	}
	wantItems := []corev1.KeyToPath{
		{Key: "public.crt", Path: "public.crt"},
		{Key: "public.key", Path: "public.key"},
	}
	if !reflect.DeepEqual(pub.Secret.Items, wantItems) {
		t.Fatalf("public-tls secret items = %v, want %v", pub.Secret.Items, wantItems)
	}
	if _, ok := podVolume(spec, "discovery"); !ok {
		t.Fatalf("router missing discovery volume; volumes=%v", spec.Volumes)
	}
	nginx := renderedDeploymentContainer(t, out, "c8s-router", "nginx")
	if m, ok := containerVolumeMount(nginx, "public-tls"); !ok || m.MountPath != "/edge-tls" {
		t.Fatalf("nginx public-tls mount = (%+v, %v), want mountPath /edge-tls", m, ok)
	}
	cert := routerGetCertContainer(t, out, "c8s-cert")
	assertContainerArgs(t, cert,
		"--discovery-out=/discovery/discovery.json",
		"--discovery-cds-cert-url=/.well-known/cds-cert.pem",
		"--discovery-public-tls-mode=webpki",
		"--discovery-mesh-ca-url=/.well-known/mesh-ca.pem",
		"--reload-watch=/edge-tls/public.crt",
		"--reload-watch=/edge-tls/public.key",
	)
	// A WebPKI-secret front door is attest-pq-only: its host-visible serving
	// key cannot support attest-lb's transport binding.
	attest := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	assertContainerArgs(t, attest, "--front-door-mode=webpki")
	deployment := renderedDeployment(t, out, "c8s-router")
	if got := deployment.Spec.Template.Spec.ShareProcessNamespace; got == nil || !*got {
		t.Fatalf("router shareProcessNamespace = %v, want true", got)
	}
}

// The locked node image's measured runtime wrapper denies every runc exec,
// and CRI routes exec probes and lifecycle exec hooks through exactly that
// call (internal/cmds/c8srunc). A c8s-owned exec probe would therefore never
// pass on such a node — the component would sit in CrashLoop or never go
// Ready — so the chart must render none.
func TestChartRendersNoExecProbes(t *testing.T) {
	// Every rendering that adds pod templates of its own: the default stack,
	// the acme front door, and the volumed/GPU opt-ins.
	renderings := map[string][]string{
		"default": nil,
		"acme": {
			"--set-string", "router.publicTLS.mode=acme",
			"--set", "router.san={lb.example.com}",
			"--set-string", "router.acme.email=ops@example.com",
		},
		"volumed": {"--set", "volumed.enabled=true", "--set", "volumed.image.tag=dev"},
	}
	for name, args := range renderings {
		t.Run(name, func(t *testing.T) {
			out, err := helmTemplate(t, args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			for _, found := range execProbesByTemplate(t, out) {
				t.Errorf("%s renders %s, which a locked node image denies; use an HTTP, TCP or gRPC probe, or SIGTERM handling", found.source, found.what)
			}
		})
	}
}

// execProbe is one exec probe or lifecycle exec hook, with the chart template
// that rendered it.
type execProbe struct {
	source string
	what   string
}

// execProbesByTemplate walks every rendered manifest for exec probes and
// lifecycle exec hooks. The walk is structural rather than typed so it covers
// every workload kind, including pod templates nested in a CronJob.
func execProbesByTemplate(t *testing.T, helmOut string) []execProbe {
	t.Helper()
	var found []execProbe
	for _, doc := range strings.Split(helmOut, "\n---\n") {
		source := manifestSource(doc)
		var obj any
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			t.Fatalf("decode manifest from %s: %v", source, err)
		}
		for _, what := range findExecHooks(obj) {
			found = append(found, execProbe{source: source, what: what})
		}
	}
	return found
}

var manifestSourceRE = regexp.MustCompile(`(?m)^# Source: (\S+)`)

func manifestSource(doc string) string {
	if m := manifestSourceRE.FindStringSubmatch(doc); m != nil {
		return m[1]
	}
	return "<unknown template>"
}

// findExecHooks returns a description of every probe or lifecycle handler in
// the decoded manifest that spawns a process.
func findExecHooks(node any) []string {
	var found []string
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			switch key {
			case "livenessProbe", "readinessProbe", "startupProbe":
				if handler, ok := child.(map[string]any); ok && handler["exec"] != nil {
					found = append(found, key+" with an exec handler")
				}
			case "lifecycle":
				if handlers, ok := child.(map[string]any); ok {
					for _, hook := range []string{"postStart", "preStop"} {
						if h, ok := handlers[hook].(map[string]any); ok && h["exec"] != nil {
							found = append(found, "a lifecycle "+hook+" exec hook")
						}
					}
				}
			}
			found = append(found, findExecHooks(child)...)
		}
	case []any:
		for _, child := range v {
			found = append(found, findExecHooks(child)...)
		}
	}
	return found
}

// TestChartRouterACMEMode pins the acme front door: the `c8s acme` native
// sidecar issues one multi-SAN leaf for the sanList into a Memory emptyDir it
// alone writes, nginx and cds-attest read it, the :80 server proxies HTTP-01
// to the sidecar's loopback challenge port and 301s everything else, and the
// mode string rides the attested surfaces (--front-door-mode,
// --discovery-public-tls-mode).
func TestChartRouterACMEMode(t *testing.T) {
	acmeArgs := []string{
		"--set-string", "router.publicTLS.mode=acme",
		"--set", "router.san={lb.example.com,api.lb.example.com}",
		"--set-string", "router.acme.email=ops@example.com",
		"--set-string", "router.acme.directoryURL=https://acme-staging-v02.api.letsencrypt.org/directory",
	}
	out, err := helmTemplate(t, acmeArgs...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	acme := routerGetCertContainer(t, out, "acme")
	if len(acme.Args) == 0 || acme.Args[0] != "acme" {
		t.Fatalf("acme sidecar args must start with the acme subcommand, got %v", acme.Args)
	}
	assertContainerArgs(t, acme,
		"--domains=lb.example.com,api.lb.example.com",
		"--acme-email=ops@example.com",
		"--acme-directory-url=https://acme-staging-v02.api.letsencrypt.org/directory",
		"--challenge-port=8402",
		"--cert-dir=/etc/c8s-acme-tls",
	)
	if acme.RestartPolicy == nil || *acme.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("acme must be a native sidecar (restartPolicy Always), got %v", acme.RestartPolicy)
	}
	// SIGHUP-ing nginx across the shared PID namespace needs the nginx uid.
	if got := acme.SecurityContext.RunAsUser; got == nil || *got != 101 {
		t.Fatalf("acme runAsUser = %v, want the nginx uid 101", got)
	}
	if m, ok := containerVolumeMount(acme, "acme-tls"); !ok || m.MountPath != "/etc/c8s-acme-tls" || m.ReadOnly {
		t.Fatalf("acme must mount acme-tls read-write at /etc/c8s-acme-tls, got (%+v, %v)", m, ok)
	}

	spec := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
	vol, ok := podVolume(spec, "acme-tls")
	if !ok || vol.EmptyDir == nil || vol.EmptyDir.Medium != corev1.StorageMediumMemory {
		t.Fatalf("acme-tls must be a Memory-medium emptyDir, got %+v", vol)
	}

	nginx := renderedDeploymentContainer(t, out, "c8s-router", "nginx")
	if m, ok := containerVolumeMount(nginx, "acme-tls"); !ok || !m.ReadOnly {
		t.Fatalf("nginx must mount acme-tls read-only, got (%+v, %v)", m, ok)
	}
	httpPort, ok := findContainerPort(nginx, "http")
	if !ok || httpPort.ContainerPort != 8080 || httpPort.HostPort != 80 {
		t.Fatalf("nginx http port = (%+v, %v), want containerPort 8080 hostPort 80", httpPort, ok)
	}

	attest := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	assertContainerArgs(t, attest,
		"--front-door-mode=acme",
		"--serving-cert-file=/etc/c8s-acme-tls/cert.pem",
	)
	if m, ok := containerVolumeMount(attest, "acme-tls"); !ok || !m.ReadOnly {
		t.Fatalf("cds-attest must mount acme-tls read-only, got (%+v, %v)", m, ok)
	}

	cert := routerGetCertContainer(t, out, "c8s-cert")
	assertContainerArgs(t, cert, "--discovery-public-tls-mode=acme")
	// The acme sidecar SIGHUPs nginx itself; get-cert watches nothing extra.
	for _, a := range cert.Args {
		if strings.HasPrefix(a, "--reload-watch=") {
			t.Fatalf("get-cert must not watch the acme certs, got %v", cert.Args)
		}
	}

	cfg := renderedRouterNginxConfig(t, out)
	if len(cfg.servers) != 2 {
		t.Fatalf("nginx config has %d server blocks, want the :443 and :80 pair", len(cfg.servers))
	}
	cfg.servers[0].assertDirective(t, "ssl_certificate", "/etc/c8s-acme-tls/cert.pem")
	cfg.servers[0].assertDirective(t, "ssl_certificate_key", "/etc/c8s-acme-tls/key.pem")
	cfg.servers[1].assertDirective(t, "listen", "8080")
	cfg.location(t, "prefix", "/.well-known/acme-challenge/").
		assertDirective(t, "proxy_pass", "http://127.0.0.1:8402")
	// The :80 server renders last, so its catch-all is the "/" the parser
	// keeps: everything but the challenge upgrades.
	cfg.location(t, "prefix", "/").assertDirective(t, "return", "301", "https://$host$request_uri")

	// The Service and the ingress policy must open the :80 path the
	// validators arrive on.
	svc := renderedService(t, out, "c8s-router")
	var httpSvcPort *corev1.ServicePort
	for i, p := range svc.Spec.Ports {
		if p.Name == "http" {
			httpSvcPort = &svc.Spec.Ports[i]
		}
	}
	if httpSvcPort == nil || httpSvcPort.Port != 80 || httpSvcPort.TargetPort.StrVal != "http" {
		t.Fatalf("router Service must expose port 80 -> http, got %+v", svc.Spec.Ports)
	}
	var np networkingv1.NetworkPolicy
	if !findDoc(t, out, "NetworkPolicy", "c8s-router-ingress", &np) {
		t.Fatal("render is missing the router ingress policy")
	}
	var npPorts []int32
	for _, rule := range np.Spec.Ingress {
		for _, p := range rule.Ports {
			npPorts = append(npPorts, int32(p.Port.IntValue()))
		}
	}
	if !slices.Contains(npPorts, int32(8080)) {
		t.Fatalf("router ingress policy must admit the http port 8080, got %v", npPorts)
	}

	// hostPort follows the existing gating: disabling it drops both binds.
	// A reachable front door must remain, so the LB Service takes over.
	out, err = helmTemplate(t, append([]string{
		"--set", "router.hostPort.enabled=false",
		"--set", "router.service.type=LoadBalancer",
	}, acmeArgs...)...)
	if err != nil {
		t.Fatalf("helm template (hostPort off): %v\n%s", err, out)
	}
	nginx = renderedDeploymentContainer(t, out, "c8s-router", "nginx")
	httpPort, ok = findContainerPort(nginx, "http")
	if !ok || httpPort.HostPort != 0 {
		t.Fatalf("hostPort.enabled=false must not bind the node's :80, got (%+v, %v)", httpPort, ok)
	}
}

// findContainerPort returns the named container port.
func findContainerPort(c corev1.Container, name string) (corev1.ContainerPort, bool) {
	for _, p := range c.Ports {
		if p.Name == name {
			return p, true
		}
	}
	return corev1.ContainerPort{}, false
}

// TestChartRouterPublicTLSModeGuards pins the fail-closed mode/values
// invariants: each rejected shape would silently serve the wrong credential
// or an ACME order that can never complete.
func TestChartRouterPublicTLSModeGuards(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "webpki without the Secret",
			args: []string{"--set-string", "router.publicTLS.mode=webpki"},
			want: "router.publicTLS.mode=webpki requires router.publicTLS.secretName",
		},
		{
			// The pre-mode values shape (secretName alone implied webpki)
			// must not silently fall back to serving the mesh leaf.
			name: "secret without webpki mode",
			args: []string{"--set-string", "router.publicTLS.secretName=edge"},
			want: `router.publicTLS.secretName is set but router.publicTLS.mode is "cds"; set mode=webpki to serve the Secret, or clear secretName`,
		},
		{
			name: "acme with a Secret",
			args: []string{"--set-string", "router.publicTLS.mode=acme", "--set-string", "router.publicTLS.secretName=edge"},
			want: `router.publicTLS.secretName is set but router.publicTLS.mode is "acme"; set mode=webpki to serve the Secret, or clear secretName`,
		},
		{
			name: "unknown mode",
			args: []string{"--set-string", "router.publicTLS.mode=webpki-tee"},
			want: "router.publicTLS.mode must be cds, webpki, or acme, got: webpki-tee",
		},
		{
			// The ACME account and serving keys live in pod memory; outside a
			// TEE the host reads them.
			name: "acme without a confidential runtime",
			args: []string{"--set-string", "router.publicTLS.mode=acme", "--set", "attestationApi.cvmMode=gke"},
			want: "VALIDATION_ERROR kind=router_acme_runtime: router.publicTLS.mode=acme requires a confidential runtime (attestationApi.cvmMode=bare-metal) so the ACME account and serving keys are TEE-held",
		},
		{
			name: "acme with a wildcard san",
			args: []string{"--set-string", "router.publicTLS.mode=acme", "--set", "router.san={*.example.com}"},
			want: `router.publicTLS.mode=acme cannot issue for wildcard san "*.example.com": HTTP-01 forbids wildcards`,
		},
		{
			// No hostPort and no LB/NodePort Service: the CA could never
			// reach the challenge.
			name: "acme without a reachable front door",
			args: []string{"--set-string", "router.publicTLS.mode=acme", "--set", "router.hostPort.enabled=false"},
			want: "VALIDATION_ERROR kind=router_acme_front_door: router.publicTLS.mode=acme needs an internet-reachable front door for the HTTP-01 challenge: set router.service.type=LoadBalancer (any LB implementation: cloud controller, MetalLB, kube-vip, ...) or router.hostPort.enabled=true",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err == nil {
				t.Fatalf("render succeeded, want a fail\n%s", out)
			}
			assertHelmFailMessage(t, out, tc.want)
		})
	}
}

// assertRouterReadyzProbe pins the readiness gate's routing invariant: the probe
// goes through nginx over HTTPS on the named `https` port, since the sidecar's
// own port is loopback-only. Nginx exact-matches /readyz onto the sidecar.
func assertRouterReadyzProbe(t *testing.T, out string) {
	t.Helper()
	rp := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest").ReadinessProbe
	if rp == nil || rp.HTTPGet == nil {
		t.Fatalf("expectedWorkload must wire an httpGet /readyz probe, got %+v", rp)
	}
	if rp.HTTPGet.Path != "/readyz" || rp.HTTPGet.Port.StrVal != "https" || rp.HTTPGet.Scheme != corev1.URISchemeHTTPS {
		t.Fatalf("readiness probe must be HTTPS /readyz on the nginx port, got %+v", rp.HTTPGet)
	}
	renderedRouterNginxConfig(t, out).location(t, "exact", "/readyz").
		assertDirective(t, "proxy_pass", "http://127.0.0.1:8800")
}

// TestChartRouterAttestFrontDoorModeAndReadinessGate pins the endpoint-split
// wiring: a default (mesh-issued serving leaf) front door runs cds-attest in
// cds front-door mode with no readiness gate, and router.attest.expectedWorkload
// wires the /readyz matched-workload gate — probed through nginx, because the
// sidecar stays on loopback in every shape.
func TestChartRouterAttestFrontDoorModeAndReadinessGate(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	attest := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	assertContainerArgs(t, attest, "--front-door-mode=cds", "--host=127.0.0.1")
	if attest.ReadinessProbe != nil {
		t.Fatalf("no expectedWorkload: cds-attest must keep today's probe-less shape, got %+v", attest.ReadinessProbe)
	}

	// Readiness can only gate ingress that flows through the Service, so the
	// gate requires the node port off (see TestChartRouterReadinessGateGuards).
	out, err = helmTemplate(t, "--set-string", "router.attest.expectedWorkload=infer", "--set", "router.hostPort.enabled=false")
	if err != nil {
		t.Fatalf("helm template with expectedWorkload: %v\n%s", err, out)
	}
	attest = renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	// The sidecar's single listener also carries the attestation, handshake and
	// tunnel routes; the gate must never move it off loopback.
	assertContainerArgs(t, attest, "--front-door-mode=cds", "--expected-workload=infer", "--host=127.0.0.1")
	assertRouterReadyzProbe(t, out)

	// The gate is satisfiable only if get-cert can earn the stamp: the
	// claims flow must be wired on the same condition. Node-CVM shape:
	// --workload-claims, the inventory socket mounted read-only at the
	// compiled path, and the socket's supplemental group on the pod.
	cert, ok := findContainer(renderedDeploymentInitContainers(t, out, "c8s-router"), "c8s-cert")
	if !ok {
		t.Fatal("c8s-cert init container missing")
	}
	assertContainerArgs(t, cert, "--workload-claims")
	var mount *corev1.VolumeMount
	for i, m := range cert.VolumeMounts {
		if m.Name == "workload-claims" {
			mount = &cert.VolumeMounts[i]
		}
	}
	if mount == nil || mount.MountPath != "/run/c8s/workload-claims" || !mount.ReadOnly {
		t.Fatalf("get-cert must mount the inventory socket read-only at the compiled path, got %+v", cert.VolumeMounts)
	}
	dep := renderedDeployment(t, out, "c8s-router")
	sc := dep.Spec.Template.Spec.SecurityContext
	if sc == nil || len(sc.SupplementalGroups) != 1 || sc.SupplementalGroups[0] != 65532 {
		t.Fatalf("pod must carry the inventory socket's supplemental group 65532, got %+v", sc)
	}
	var vol *corev1.Volume
	for i, v := range dep.Spec.Template.Spec.Volumes {
		if v.Name == "workload-claims" {
			vol = &dep.Spec.Template.Spec.Volumes[i]
		}
	}
	if vol == nil || vol.HostPath == nil || vol.HostPath.Path != "/var/run/nri-image-policy" {
		t.Fatalf("workload-claims hostPath volume missing or wrong, got %+v", dep.Spec.Template.Spec.Volumes)
	}

}

// TestChartRouterReadinessGateGuards pins the render-time guards around the
// readiness gate. Each rejected shape is one where the gate silently gates
// nothing, or where the front door it protects is unreachable to begin with.
func TestChartRouterReadinessGateGuards(t *testing.T) {
	gate := []string{"--set-string", "router.attest.expectedWorkload=infer"}
	noHostPort := []string{"--set", "router.hostPort.enabled=false"}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			// Readiness withdraws Service endpoints; the node port is
			// published by CNI portmap at sandbox creation and keeps serving.
			name: "hostPort defeats the gate",
			args: gate,
			want: "router.attest.expectedWorkload cannot gate ingress while router.hostPort.enabled=true: the node port is published by CNI portmap regardless of pod readiness. Set router.hostPort.enabled=false and route through the Service, or clear expectedWorkload",
		},
		{
			// Without the sidecar there is no /readyz to gate on, yet the
			// claims wiring the gate pulls in would still render.
			name: "gate without the sidecar it gates",
			args: append(append([]string{}, gate...), append(noHostPort, "--set", "router.attest.enabled=false")...),
			want: "router.attest.expectedWorkload gates the cds-attest sidecar's /readyz endpoint: set router.attest.enabled=true or clear expectedWorkload",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err == nil {
				t.Fatalf("render succeeded, want a fail\n%s", out)
			}
			assertHelmFailMessage(t, out, tc.want)
		})
	}
}

// TestChartRouterServiceType pins that the Service type is exactly what the
// operator sets: default ClusterIP, explicit LoadBalancer/NodePort honored.
// Public exposure is an explicit type=LoadBalancer, not inferred.
func TestChartRouterServiceType(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		wantType   corev1.ServiceType
		wantPolicy corev1.ServiceExternalTrafficPolicy
	}{
		{name: "default is ClusterIP", wantType: corev1.ServiceTypeClusterIP},
		{name: "explicit LoadBalancer", args: []string{"--set", "router.service.type=LoadBalancer"}, wantType: corev1.ServiceTypeLoadBalancer, wantPolicy: corev1.ServiceExternalTrafficPolicyLocal},
		{name: "explicit NodePort", args: []string{"--set", "router.service.type=NodePort"}, wantType: corev1.ServiceTypeNodePort, wantPolicy: corev1.ServiceExternalTrafficPolicyLocal},
		// The attestation sidecar keys its limiter on the same public peer
		// address, so it holds the policy on its own.
		{name: "LoadBalancer without allowlist route", args: []string{"--set", "router.service.type=LoadBalancer", "--set", "router.allowlist.enabled=false"}, wantType: corev1.ServiceTypeLoadBalancer, wantPolicy: corev1.ServiceExternalTrafficPolicyLocal},
		// With neither, nothing keys on the source address, so the default
		// must not regress reachability through nodes that do not run the
		// router pod.
		{name: "LoadBalancer with neither limiter", args: []string{"--set", "router.service.type=LoadBalancer", "--set", "router.allowlist.enabled=false", "--set", "router.attest.enabled=false"}, wantType: corev1.ServiceTypeLoadBalancer, wantPolicy: corev1.ServiceExternalTrafficPolicyCluster},
		{name: "explicit policy override wins", args: []string{"--set", "router.service.type=NodePort", "--set", "router.service.externalTrafficPolicy=Cluster"}, wantType: corev1.ServiceTypeNodePort, wantPolicy: corev1.ServiceExternalTrafficPolicyCluster},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			svc := renderedService(t, out, "c8s-router")
			if svc.Spec.Type != tc.wantType {
				t.Fatalf("service type = %q, want %q", svc.Spec.Type, tc.wantType)
			}
			if svc.Spec.ExternalTrafficPolicy != tc.wantPolicy {
				t.Fatalf("externalTrafficPolicy = %q, want %q", svc.Spec.ExternalTrafficPolicy, tc.wantPolicy)
			}
		})
	}
}

func TestChartRouterServiceRejectsInvalidTrafficPolicy(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "router.service.type=LoadBalancer",
		"--set-string", "router.service.externalTrafficPolicy=bogus",
	)
	if err == nil {
		t.Fatalf("expected render to fail on invalid externalTrafficPolicy; got success\n%s", out)
	}
	assertHelmFailMessage(t, out, "router.service.externalTrafficPolicy must be Local or Cluster, got: bogus")
}

// With no adopted workload the upstream address is empty; the sidecar must
// render without any --upstream* flag (its echo backend takes over) instead
// of a scheme-only "--upstream=http://" that crash-loops the container.
func TestChartRouterAttestSidecarNoUpstream(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "router.attest.enabled=true",
		"--set-string", "router.upstream.address=",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	sidecar := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	for _, arg := range sidecar.Args {
		if strings.HasPrefix(arg, "--upstream") {
			t.Fatalf("cds-attest must omit %q when no upstream address is set: %v", arg, sidecar.Args)
		}
	}
}

func TestChartRendersRouterAttestSidecar(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "router.attest.enabled=true",
		"--set", "router.attest.port=8800",
		"--set-string", "router.attest.generation=milan",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	// The cds-attest sidecar runs the operator multi-mode image with the
	// cds-attest subcommand, bound to loopback for nginx to proxy to.
	deployment := renderedDeployment(t, out, "c8s-router")
	sidecar := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	if len(sidecar.Args) == 0 || sidecar.Args[0] != "cds-attest" {
		t.Fatalf("cds-attest args = %v, want first arg 'cds-attest'", sidecar.Args)
	}
	assertContainerArgs(t, sidecar,
		"--host=127.0.0.1",
		"--port=8800",
		"--generation=milan",
		"--mesh-identity-cert-file=/tls/cert.pem",
		"--mesh-identity-key-file=/tls/key.pem",
		"--mesh-identity-ca-file=/tls/ca.pem",
		// The baseline mesh-wrapped upstream is a plain-HTTP workload upstream;
		// the mTLS args render only for an https upstream.
		"--upstream=http://c8s-infer.c8s-system.svc.cluster.local:8000",
	)
	assertContainerHasArgPrefix(t, "cds-attest", sidecar.Args, "--attestation-api-url=unix:///var/run/nri-image-policy/attestation-api.sock")
	for _, banned := range []string{"--upstream-ca", "--upstream-cert", "--upstream-key", "--upstream-server-name"} {
		assertContainerNoArgPrefix(t, "cds-attest", sidecar.Args, banned)
	}
	// The sidecar must not mount the mesh-CA for the default cert.pem trust path.
	if _, ok := containerVolumeMount(sidecar, "mesh-ca"); ok {
		t.Fatalf("cds-attest should not mount mesh-ca with the default /tls/cert.pem trust; mounts=%v", sidecar.VolumeMounts)
	}
	if got := len(deployment.Spec.Template.Spec.Containers); got != 3 {
		t.Fatalf("router should have nginx + cds-attest + allowlist-proxy, got %d containers", got)
	}

	// nginx reverse-proxies the dynamic well-known prefix to the sidecar.
	renderedRouterNginxConfig(t, out).
		location(t, "prefix", "/.well-known/c8s/").
		assertDirective(t, "proxy_pass", "http://127.0.0.1:8800")
	renderedRouterNginxConfig(t, out).
		location(t, "prefix", "/.well-known/c8s/").
		assertDirective(t, "proxy_set_header", "X-Real-IP", "$remote_addr")
	renderedRouterNginxConfig(t, out).
		location(t, "exact", "/readyz").
		assertDirective(t, "proxy_set_header", "X-Real-IP", "$remote_addr")

	// An https upstream: the sidecar presents the CDS client cert and
	// verifies the upstream against the CA chain get-cert writes to
	// /tls/cert.pem, mirroring the nginx proxy_ssl_* config.
	httpsOut, err := helmTemplate(t, noUpstreamArgs(
		"--set", "router.attest.enabled=true",
		"--set-string", "router.upstream.address=my-backend.other-ns.svc:8443",
		"--set", "router.upstream.protocol=https",
	)...)
	if err != nil {
		t.Fatalf("helm template (https upstream): %v\n%s", err, httpsOut)
	}
	httpsSidecar := renderedDeploymentContainer(t, httpsOut, "c8s-router", "cds-attest")
	assertContainerArgs(t, httpsSidecar,
		"--upstream=https://my-backend.other-ns.svc:8443",
		"--upstream-ca=/tls/cert.pem",
		"--upstream-cert=/tls/cert.pem",
		"--upstream-key=/tls/key.pem",
		"--upstream-server-name=my-backend.other-ns.svc",
	)

	// Default on: the sidecar and its well-known proxy render without any
	// attest override.
	defOut, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template (defaults): %v\n%s", err, defOut)
	}
	wellKnown := nginxLocationKey{match: "prefix", path: "/.well-known/c8s/"}
	defContainers := renderedDeployment(t, defOut, "c8s-router").Spec.Template.Spec.Containers
	if _, ok := findContainer(defContainers, "cds-attest"); !ok {
		t.Fatal("cds-attest sidecar should render by default (router.attest.enabled defaults true)")
	}
	if _, ok := renderedRouterNginxConfig(t, defOut).locations[wellKnown]; !ok {
		t.Fatal("well-known proxy location should render by default (router.attest.enabled defaults true)")
	}

	// Explicit opt-out: no sidecar, no well-known proxy.
	offOut, err := helmTemplate(t, "--set", "router.attest.enabled=false")
	if err != nil {
		t.Fatalf("helm template (attest disabled): %v\n%s", err, offOut)
	}
	offContainers := renderedDeployment(t, offOut, "c8s-router").Spec.Template.Spec.Containers
	if _, ok := findContainer(offContainers, "cds-attest"); ok {
		t.Fatal("cds-attest sidecar should not render when router.attest.enabled=false")
	}
	if _, ok := renderedRouterNginxConfig(t, offOut).locations[wellKnown]; ok {
		t.Fatal("well-known proxy location should not render when router.attest.enabled=false")
	}
}

func TestRouterCertProvisioningValuesDriveGetCertContainers(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "router.certProvisioning.renewInterval=30m",
		"--set-string", "router.certProvisioning.caWatchInterval=2m",
		"--set", "router.certProvisioning.verbose=true",
		"--set", "router.nginx.runAsUser=201",
		"--set", "router.nginx.runAsGroup=202",
		"--set", "router.nginx.runAsNonRoot=false",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cert := routerGetCertContainer(t, out, "c8s-cert")
	assertContainerArgs(t, cert, "--verbose", "--renew-interval=30m", "--ca-watch-interval=2m")
	if got := cert.SecurityContext.RunAsUser; got == nil || *got != 201 {
		t.Fatalf("c8s-cert runAsUser = %v, want 201", got)
	}
	if got := cert.SecurityContext.RunAsGroup; got == nil || *got != 202 {
		t.Fatalf("c8s-cert runAsGroup = %v, want 202", got)
	}
	if got := cert.SecurityContext.RunAsNonRoot; got == nil || *got {
		t.Fatalf("c8s-cert runAsNonRoot = %v, want false", got)
	}
	deployment := renderedDeployment(t, out, "c8s-router")
	if got := deployment.Spec.Template.Spec.SecurityContext.FSGroup; got == nil || *got != 202 {
		t.Fatalf("router fsGroup = %v, want 202", got)
	}
	nginx := renderedDeploymentContainer(t, out, "c8s-router", "nginx")
	if got := nginx.SecurityContext.RunAsUser; got == nil || *got != 201 {
		t.Fatalf("nginx runAsUser = %v, want 201", got)
	}
	if got := nginx.SecurityContext.RunAsGroup; got == nil || *got != 202 {
		t.Fatalf("nginx runAsGroup = %v, want 202", got)
	}
	if got := nginx.SecurityContext.RunAsNonRoot; got == nil || *got {
		t.Fatalf("nginx runAsNonRoot = %v, want false", got)
	}
}

// TestChartDefaultRouterUpstreamIsWorkloadDirect pins the default front-door
// path: router proxies straight to the workload over plain HTTP at the app
// layer (the node mesh wraps pod-IP hops in attested mTLS), with no
// proxy_ssl_* directives on the default route. The upstream is dialed via a
// variable with a resolver so nginx re-resolves per DNS TTL: a headless
// Service (an adopted workload) returns pod IPs that change on pod churn, and
// a static upstream block would pin the startup-time IPs and 502 until the
// next config reload.
func TestChartRouterMeshWrappedUpstreamIsWorkloadDirect(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	cfg.http.assertDirective(t, "resolver", "kube-dns.kube-system.svc.cluster.local")
	defaultRoute := cfg.location(t, "prefix", "/")
	// The baseline mesh-wrapped upstream is the operator-managed headless
	// Service, so the pod-IP hop is mesh-wrapped.
	defaultRoute.assertDirective(t, "set", "$backend_addr", "c8s-infer.c8s-system.svc.cluster.local:8000")
	defaultRoute.assertDirective(t, "proxy_pass", "http://$backend_addr")
	if len(cfg.upstreams) != 0 {
		t.Fatalf("catch-all upstream must be a variable dial, not a static upstream block (it would pin headless pod IPs at startup); got %v", cfg.upstreams)
	}
	cfg.assertNoDirectivePrefix(t, "proxy_ssl_")
}

// A manual upstream is dialed through a static upstream block, so nginx
// resolves it once at startup instead of per request. Per-request resolution
// asks cluster DNS -- plaintext UDP the mesh does not intercept -- where to
// send every request, so a forged answer retargets the hop mid-session; a
// loose tls.serverName or a wildcard SAN pattern leaves nothing to catch it.
// Only the mesh-wrapped headless shape keeps the variable dial, because its
// pod IPs churn; the resolver is rendered for that shape alone.
func TestChartRouterManualUpstreamResolvesAtStartup(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "router.upstream.address=my-backend.other-ns.svc:8443",
		"--set", "router.upstream.protocol=https",
		"--set", "router.upstream.tls.verify=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	cfg.upstream(t, "catch_all").assertServer(t, "my-backend.other-ns.svc:8443")
	route := cfg.location(t, "prefix", "/")
	route.assertDirective(t, "proxy_pass", "https://catch_all")
	route.assertNoDirective(t, "set")
	cfg.http.assertNoDirective(t, "resolver")
}

// nginx exits at startup on a resolver name that does not resolve, and RKE2
// names its CoreDNS Service rke2-coredns-rke2-coredns — the kube-dns default
// crash-loops router on every RKE2 cluster. The resolver therefore derives
// from the distro values (which every RKE2 install already sets for the
// containerd layout); an explicit router.nginx.resolver still wins.
func TestChartRouterResolverDerivesFromDistro(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "rke2 via nriImagePolicy.distro",
			args: []string{"--set-string", "nriImagePolicy.distro=rke2"},
			want: "rke2-coredns-rke2-coredns.kube-system.svc.cluster.local",
		},
		{
			name: "explicit resolver wins over distro",
			args: []string{
				"--set-string", "nriImagePolicy.distro=rke2",
				"--set-string", "router.nginx.resolver=my-dns.dns-ns.svc.cluster.local",
			},
			want: "my-dns.dns-ns.svc.cluster.local",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			cfg := renderedRouterNginxConfig(t, out)
			if cfg.http == nil {
				t.Fatal("nginx config missing http block")
			}
			cfg.http.assertDirective(t, "resolver", tc.want)
		})
	}
}

func TestRouterVerifyDerivesProxySSLNameFromUpstream(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set-string", "upstream.address=my-backend.other-ns.svc.cluster.local:443",
		"--set", "upstream.protocol=https",
		"--set", "upstream.tls.verify=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	defaultRoute := cfg.location(t, "prefix", "/")
	defaultRoute.assertDirective(t, "proxy_ssl_name", "my-backend.other-ns.svc.cluster.local")
}

func TestRouterCORSAllowsSessionHeaderByDefault(t *testing.T) {
	// Browser clients send X-C8s-Session on the /tunnel request, so the default
	// CORS allow-headers must include it or the over-encrypted channel breaks
	// cross-origin.
	out, err := helmTemplateRouter(t,
		"--set", "cors.enabled=true",
		"--set", "cors.allowOrigins={https://example.github.io}",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	conf := renderedRouterNginxConf(t, out)
	if !strings.Contains(conf, "X-C8s-Session") {
		t.Fatalf("CORS Access-Control-Allow-Headers missing X-C8s-Session:\n%s", conf)
	}
}

// protocolCORSLocations are the c8s protocol-owned nginx locations that serve
// wide-open CORS by default: their responses are self-authenticating or
// public by design, and browser verifiers on any origin must be able to
// reach them.
var protocolCORSLocations = []struct{ match, path string }{
	{"exact", "/allowlist"},
	{"prefix", "/allowlist/"},
	{"exact", "/v1/discovery"},
	{"exact", "/.well-known/cds-cert.pem"},
	{"exact", "/.well-known/mesh-ca.pem"},
	{"prefix", "/.well-known/c8s/"},
}

func TestRouterProtocolEndpointsCORSByDefault(t *testing.T) {
	// With no CORS configuration at all, the protocol-owned endpoints must be
	// callable from a browser on any origin — that is the whole point of
	// in-browser attestation — while workload locations stay untouched.
	out, err := helmTemplateRouter(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	for _, loc := range protocolCORSLocations {
		block := cfg.location(t, loc.match, loc.path)
		block.assertDirective(t, "add_header", "Access-Control-Allow-Origin", `"*"`, "always")
	}
	// The workload catch-all inherits nothing from the protocol default.
	cfg.location(t, "prefix", "/").assertNoDirective(t, "add_header")
	// The built-in policy is self-contained: none of the global CORS
	// http-level maps are rendered.
	if _, ok := cfg.maps[nginxMapKey{source: "$http_origin", target: "$cors_origin"}]; ok {
		t.Fatal("global CORS maps rendered without router.cors.enabled")
	}
}

func TestRouterProtocolEndpointsCORSOptOut(t *testing.T) {
	out, err := helmTemplateRouter(t, "--set", "cors.protocolEndpoints=false")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	conf := renderedRouterNginxConf(t, out)
	if strings.Contains(conf, "Access-Control") {
		t.Fatalf("CORS directives rendered with cors.protocolEndpoints=false:\n%s", conf)
	}
}

func TestRouterGlobalCORSCoversProtocolEndpoints(t *testing.T) {
	// An enabled global CORS block is an explicit operator policy; it covers
	// the protocol endpoints too (as it always has), and the built-in
	// wide-open block steps aside rather than double-emitting headers.
	out, err := helmTemplateRouter(t,
		"--set", "cors.enabled=true",
		"--set", "cors.allowOrigins={https://example.github.io}",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	for _, loc := range protocolCORSLocations {
		block := cfg.location(t, loc.match, loc.path)
		block.assertDirective(t, "add_header", "Access-Control-Allow-Origin", "$cors_out_origin", "always")
	}
	if conf := renderedRouterNginxConf(t, out); strings.Contains(conf, `Access-Control-Allow-Origin  "*"`) ||
		strings.Contains(conf, `Access-Control-Allow-Origin "*"`) {
		t.Fatalf("wide-open protocol CORS rendered alongside an enabled global block:\n%s", conf)
	}
}

func TestRouterRejectsStringProtocolEndpoints(t *testing.T) {
	out, err := helmTemplateRouter(t, "--set-string", "cors.protocolEndpoints=false")
	if err == nil {
		t.Fatal("helm template succeeded with string cors.protocolEndpoints, want error")
	}
	if !strings.Contains(out, "router.cors.protocolEndpoints must be a boolean") {
		t.Fatalf("unexpected error output:\n%s", out)
	}
}

func TestRouterExposesAllowlistThroughCDSByDefault(t *testing.T) {
	out, err := helmTemplateRouter(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	if cfg.http == nil {
		t.Fatal("nginx config missing http block")
	}
	cfg.http.assertDirective(t, "limit_req_zone", "$allowlist_write_rate_key", "zone=allowlist_write_per_client:10m", "rate=1r/s")
	cfg.http.assertDirective(t, "limit_req_zone", "$allowlist_write_total_key", "zone=allowlist_write_total:1m", "rate=8r/s")
	cfg.http.assertDirective(t, "limit_req_zone", "$allowlist_read_rate_key", "zone=allowlist_read_per_client:10m", "rate=20r/s")
	rateMap := cfg.mapBlock(t, "$request_method", "$allowlist_write_rate_key")
	rateMap.assertDirective(t, "default", "$binary_remote_addr")
	rateMap.assertDirective(t, "GET", `""`)
	rateMap.assertDirective(t, "HEAD", `""`)
	rateMap.assertDirective(t, "OPTIONS", `""`)
	// The total key chains off the write key: exempt methods stay exempt, any
	// counted method collapses onto the single "all" bucket.
	totalMap := cfg.mapBlock(t, "$allowlist_write_rate_key", "$allowlist_write_total_key")
	totalMap.assertDirective(t, `""`, `""`)
	totalMap.assertDirective(t, "default", `"all"`)
	readMap := cfg.mapBlock(t, "$request_method", "$allowlist_read_rate_key")
	readMap.assertDirective(t, "default", `""`)
	readMap.assertDirective(t, "GET", "$binary_remote_addr")
	readMap.assertDirective(t, "HEAD", "$binary_remote_addr")

	for _, route := range []struct {
		match string
		path  string
	}{
		{match: "exact", path: "/allowlist"},
		{match: "prefix", path: "/allowlist/"},
	} {
		location := cfg.location(t, route.match, route.path)
		location.assertDirective(t, "proxy_pass", "http://127.0.0.1:8801$request_uri")
		location.assertDirective(t, "proxy_set_header", "Host", "$host")
		location.assertDirective(t, "proxy_set_header", "Authorization", "$http_authorization")
		location.assertDirective(t, "limit_req", "zone=allowlist_write_per_client", "burst=5", "nodelay")
		location.assertDirective(t, "limit_req", "zone=allowlist_write_total", "burst=15", "nodelay")
		location.assertDirective(t, "limit_req", "zone=allowlist_read_per_client", "burst=40", "nodelay")
		location.assertDirective(t, "limit_req_status", "429")
		location.assertNoDirective(t, "proxy_ssl_verify")
	}

	proxy := renderedDeploymentContainer(t, out, "c8s-router", "allowlist-proxy")
	for _, want := range []string{
		"allowlist-proxy",
		"--host=127.0.0.1",
		"--port=8801",
		"--cds-url=https://c8s-cds.c8s-system.svc:8443",
		"--attestation-api-url=unix:///var/run/nri-image-policy/attestation-api.sock",
	} {
		assertContainerHasArg(t, "allowlist-proxy", proxy.Args, want)
	}
	// No TLS or operator key material: the only mount is the read-only
	// attestation socket directory.
	for _, m := range proxy.VolumeMounts {
		if m.Name != "attestation-api-socket" || !m.ReadOnly {
			t.Fatalf("allowlist-proxy must not receive TLS or operator private keys: mounts=%v", proxy.VolumeMounts)
		}
	}
}

func TestRouterAllowlistRateLimitsAreConfigurable(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set", "allowlist.rateLimit.requestsPerSecond=2",
		"--set", "allowlist.rateLimit.burst=7",
		"--set", "allowlist.rateLimit.totalRequestsPerSecond=9",
		"--set", "allowlist.rateLimit.totalBurst=19",
		"--set", "allowlist.readRateLimit.requestsPerSecond=50",
		"--set", "allowlist.readRateLimit.burst=100",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	if cfg.http == nil {
		t.Fatal("nginx config missing http block")
	}
	cfg.http.assertDirective(t, "limit_req_zone", "$allowlist_write_rate_key", "zone=allowlist_write_per_client:10m", "rate=2r/s")
	cfg.http.assertDirective(t, "limit_req_zone", "$allowlist_write_total_key", "zone=allowlist_write_total:1m", "rate=9r/s")
	cfg.http.assertDirective(t, "limit_req_zone", "$allowlist_read_rate_key", "zone=allowlist_read_per_client:10m", "rate=50r/s")
	for _, key := range []nginxLocationKey{
		{match: "exact", path: "/allowlist"},
		{match: "prefix", path: "/allowlist/"},
	} {
		location := cfg.location(t, key.match, key.path)
		location.assertDirective(t, "limit_req", "zone=allowlist_write_per_client", "burst=7", "nodelay")
		location.assertDirective(t, "limit_req", "zone=allowlist_write_total", "burst=19", "nodelay")
		location.assertDirective(t, "limit_req", "zone=allowlist_read_per_client", "burst=100", "nodelay")
	}
}

func TestRouterAllowlistProxyPinsCDSMeasurements(t *testing.T) {
	measurement := strings.Repeat("ab", ratls.SNPMeasurementSize)
	out, err := helmTemplate(t,
		"--set-string", "cds.measurements[0]="+measurement,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	proxy := renderedDeploymentContainer(t, out, "c8s-router", "allowlist-proxy")
	assertContainerHasArg(t, "allowlist-proxy", proxy.Args, "--cds-measurements="+measurement)
}

func TestRouterBuiltInAllowlistRouteCanBeDisabled(t *testing.T) {
	out, err := helmTemplateRouter(t, "--set", "allowlist.enabled=false")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	for _, key := range []nginxLocationKey{
		{match: "exact", path: "/allowlist"},
		{match: "prefix", path: "/allowlist/"},
	} {
		if _, ok := cfg.locations[key]; ok {
			t.Fatalf("nginx config contains disabled built-in allowlist location %#v", key)
		}
	}
	if _, ok := cfg.maps[nginxMapKey{source: "$request_method", target: "$allowlist_write_rate_key"}]; ok {
		t.Fatal("disabled built-in allowlist route still renders its rate-limit map")
	}
	cfg.http.assertNoDirective(t, "limit_req_zone")
	deployment := renderedDeployment(t, out, "c8s-router")
	if _, ok := findContainer(deployment.Spec.Template.Spec.Containers, "allowlist-proxy"); ok {
		t.Fatal("disabled built-in allowlist route still renders allowlist-proxy")
	}
}

func TestRouterExplicitAllowlistRouteOverridesBuiltInRoute(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set-string", "routes[0].path=/allowlist",
		"--set-string", "routes[0].match=exact",
		"--set-string", "routes[0].backend.address=custom-cds.example:8443",
		"--set-string", "routes[0].backend.protocol=https",
		"--set", "routes[0].backend.tls.verify=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	cfg.location(t, "exact", "/allowlist").assertDirective(t, "proxy_pass", "https://route_0")
	if _, ok := cfg.locations[nginxLocationKey{match: "prefix", path: "/allowlist/"}]; ok {
		t.Fatal("built-in /allowlist/ route rendered alongside explicit allowlist route")
	}
	if _, ok := cfg.maps[nginxMapKey{source: "$request_method", target: "$allowlist_write_rate_key"}]; ok {
		t.Fatal("explicit allowlist route still renders the built-in rate-limit map")
	}
	cfg.http.assertNoDirective(t, "limit_req_zone")
	deployment := renderedDeployment(t, out, "c8s-router")
	if _, ok := findContainer(deployment.Spec.Template.Spec.Containers, "allowlist-proxy"); ok {
		t.Fatal("explicit allowlist route still renders the built-in allowlist-proxy")
	}
}

func TestRouterAdditionalRoutesConfigureNginxLocations(t *testing.T) {
	// Route backends must be secured (https + verify); the location/upstream
	// wiring under test is protocol-independent.
	out, err := helmTemplateRouter(t,
		"--set-string", "routes[0].path=/allowlist",
		"--set-string", "routes[0].match=exact",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc:8080",
		"--set-string", "routes[0].backend.protocol=https",
		"--set", "routes[0].backend.tls.verify=true",
		"--set-string", "routes[1].path=/tenant/",
		"--set-string", "routes[1].backend.address=tenant-router.c8s-system.svc:8080",
		"--set-string", "routes[1].backend.protocol=https",
		"--set", "routes[1].backend.tls.verify=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)

	for _, tt := range []struct {
		name     string
		match    string
		path     string
		proxyURL string
	}{
		{
			name:     "exact",
			match:    "exact",
			path:     "/allowlist",
			proxyURL: "https://route_0",
		},
		{
			name:     "default-prefix",
			match:    "prefix",
			path:     "/tenant/",
			proxyURL: "https://route_1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			route := cfg.location(t, tt.match, tt.path)
			route.assertDirective(t, "proxy_pass", tt.proxyURL)
		})
	}

	defaultRoute := cfg.location(t, "prefix", "/")
	defaultRoute.assertDirective(t, "proxy_pass", "https://catch_all")
	cfg.upstream(t, "catch_all").assertServer(t, "vllm:8000")
	cfg.upstream(t, "route_0").assertServer(t, "cds.c8s-system.svc:8080")
	cfg.upstream(t, "route_1").assertServer(t, "tenant-router.c8s-system.svc:8080")
}

// A route backend forwards X-Forwarded-Proto to the origin regardless of the
// backend protocol; the backend must be secured (https + verify), so a client
// cert is presented but no proxy_ssl client cert is required for that header.
func TestRouterRouteForwardsProto(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set-string", "routes[0].path=/tenant/",
		"--set-string", "routes[0].backend.address=tenant-router.c8s-system.svc:8080",
		"--set-string", "routes[0].backend.protocol=https",
		"--set", "routes[0].backend.tls.verify=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	cfg.upstream(t, "route_0").assertServer(t, "tenant-router.c8s-system.svc:8080")
	route := cfg.location(t, "prefix", "/tenant/")
	route.assertDirective(t, "proxy_pass", "https://route_0")
	route.assertDirective(t, "proxy_set_header", "X-Forwarded-Proto", "$scheme")
}

func TestRouterTypedHTTPSRouteConfiguresProxyTLS(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set-string", "routes[0].path=/allowlist",
		"--set-string", "routes[0].match=exact",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc.cluster.local:8080",
		"--set-string", "routes[0].backend.protocol=https",
		"--set", "routes[0].backend.tls.verify=true",
		"--set-string", "routes[0].backend.tls.serverName=cds.c8s-system.svc.cluster.local",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	cfg.upstream(t, "route_0").assertServer(t, "cds.c8s-system.svc.cluster.local:8080")
	route := cfg.location(t, "exact", "/allowlist")
	route.assertDirective(t, "proxy_ssl_server_name", "on")
	route.assertDirective(t, "proxy_ssl_name", "cds.c8s-system.svc.cluster.local")
	route.assertDirective(t, "proxy_ssl_verify", "on")
	route.assertDirective(t, "proxy_ssl_verify_depth", "2")
	route.assertDirective(t, "proxy_ssl_trusted_certificate", "/tls/ca.pem")
	route.assertDirective(t, "proxy_pass", "https://route_0")
	route.assertNoDirective(t, "proxy_ssl_certificate")
	route.assertNoDirective(t, "proxy_ssl_certificate_key")
}

func TestRouterTypedHTTPSRouteCanUseCDSClientCert(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set-string", "routes[0].path=/allowlist",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc.cluster.local:8080",
		"--set-string", "routes[0].backend.protocol=https",
		"--set", "routes[0].backend.tls.useCDSClientCert=true",
		"--set", "routes[0].backend.tls.verify=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	route := cfg.location(t, "prefix", "/allowlist")
	route.assertDirective(t, "proxy_ssl_certificate", "/tls/cert.pem")
	route.assertDirective(t, "proxy_ssl_certificate_key", "/tls/key.pem")
	route.assertDirective(t, "proxy_ssl_name", "cds.c8s-system.svc.cluster.local")
	route.assertDirective(t, "proxy_pass", "https://route_0")
}

func TestRouterTypedHTTPSRouteCustomTrustedCAPathDoesNotMountMeshCA(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set-string", "routes[0].path=/allowlist",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc.cluster.local:8080",
		"--set-string", "routes[0].backend.protocol=https",
		"--set", "routes[0].backend.tls.verify=true",
		"--set-string", "routes[0].backend.tls.trustedCAPath=/etc/ssl/certs/ca-certificates.crt",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	route := cfg.location(t, "prefix", "/allowlist")
	route.assertDirective(t, "proxy_ssl_trusted_certificate", "/etc/ssl/certs/ca-certificates.crt")
	assertNoRouterMeshCAVolume(t, out)
}

func renderedRouterNginxConf(t *testing.T, manifest string) string {
	t.Helper()
	cm := renderedConfigMap(t, manifest, "c8s-router-nginx")
	conf, ok := cm.Data["nginx.conf"]
	if !ok || conf == "" {
		t.Fatalf("router nginx ConfigMap missing nginx.conf\n%s", manifest)
	}
	return conf
}

type nginxConfig struct {
	upstreams map[string]*nginxBlock
	maps      map[nginxMapKey]*nginxBlock
	locations map[nginxLocationKey]*nginxBlock
	http      *nginxBlock
	servers   []*nginxBlock
	all       []*nginxBlock
}

type nginxMapKey struct {
	source string
	target string
}

type nginxLocationKey struct {
	match string
	path  string
}

type nginxBlock struct {
	directives map[string][][]string
}

func renderedRouterNginxConfig(t *testing.T, manifest string) nginxConfig {
	t.Helper()
	return parseNginxConfig(t, renderedRouterNginxConf(t, manifest))
}

func parseNginxConfig(t *testing.T, conf string) nginxConfig {
	t.Helper()
	cfg := nginxConfig{
		upstreams: make(map[string]*nginxBlock),
		maps:      make(map[nginxMapKey]*nginxBlock),
		locations: make(map[nginxLocationKey]*nginxBlock),
	}

	var stack []*nginxBlock
	for line := range strings.SplitSeq(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if before, ok := strings.CutSuffix(trimmed, "{"); ok {
			fields := strings.Fields(strings.TrimSpace(before))
			block := &nginxBlock{directives: make(map[string][][]string)}
			cfg.all = append(cfg.all, block)
			if len(fields) == 1 && fields[0] == "http" {
				cfg.http = block
			}
			if len(fields) == 1 && fields[0] == "server" {
				cfg.servers = append(cfg.servers, block)
			}
			if len(fields) == 2 && fields[0] == "upstream" {
				cfg.upstreams[fields[1]] = block
			}
			if len(fields) == 3 && fields[0] == "map" {
				cfg.maps[nginxMapKey{source: fields[1], target: fields[2]}] = block
			}
			if len(fields) >= 2 && fields[0] == "location" {
				key := nginxLocationKey{match: "prefix", path: fields[1]}
				if len(fields) == 3 && fields[1] == "=" {
					key = nginxLocationKey{match: "exact", path: fields[2]}
				}
				cfg.locations[key] = block
			}
			stack = append(stack, block)
			continue
		}
		if trimmed == "}" {
			if len(stack) == 0 {
				t.Fatalf("nginx config has unmatched closing brace")
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if len(stack) == 0 || !strings.HasSuffix(trimmed, ";") {
			continue
		}
		fields := strings.Fields(strings.TrimSuffix(trimmed, ";"))
		if len(fields) == 0 {
			continue
		}
		current := stack[len(stack)-1]
		current.directives[fields[0]] = append(current.directives[fields[0]], fields[1:])
	}
	if len(stack) != 0 {
		t.Fatalf("nginx config has %d unclosed block(s)", len(stack))
	}
	return cfg
}

func (cfg nginxConfig) upstream(t *testing.T, name string) *nginxBlock {
	t.Helper()
	upstream, ok := cfg.upstreams[name]
	if !ok {
		t.Fatalf("nginx config missing upstream %q; got %v", name, cfg.upstreams)
	}
	return upstream
}

func (cfg nginxConfig) location(t *testing.T, match, path string) *nginxBlock {
	t.Helper()
	key := nginxLocationKey{match: match, path: path}
	location, ok := cfg.locations[key]
	if !ok {
		t.Fatalf("nginx config missing location %#v; got %v", key, cfg.locations)
	}
	return location
}

func (cfg nginxConfig) server(t *testing.T) *nginxBlock {
	t.Helper()
	if len(cfg.servers) != 1 {
		t.Fatalf("nginx config has %d server blocks, want 1", len(cfg.servers))
	}
	return cfg.servers[0]
}

// assertNoDirectivePrefix fails if any block in the config carries a directive
// whose name starts with prefix.
func (cfg nginxConfig) assertNoDirectivePrefix(t *testing.T, prefix string) {
	t.Helper()
	for _, block := range cfg.all {
		for name, args := range block.directives {
			if strings.HasPrefix(name, prefix) {
				t.Fatalf("nginx directive %s %v present, want no %s* directives", name, args, prefix)
			}
		}
	}
}

func (cfg nginxConfig) mapBlock(t *testing.T, source, target string) *nginxBlock {
	t.Helper()
	key := nginxMapKey{source: source, target: target}
	block, ok := cfg.maps[key]
	if !ok {
		t.Fatalf("nginx config missing map %#v; got %v", key, cfg.maps)
	}
	return block
}

func (block *nginxBlock) assertServer(t *testing.T, server string) {
	t.Helper()
	block.assertDirective(t, "server", server)
}

func (block *nginxBlock) assertDirective(t *testing.T, name string, args ...string) {
	t.Helper()
	for _, got := range block.directives[name] {
		if slices.Equal(got, args) {
			return
		}
	}
	t.Fatalf("nginx directive %q args %v not found; got %v", name, args, block.directives[name])
}

func (block *nginxBlock) assertNoDirective(t *testing.T, name string) {
	t.Helper()
	if got := block.directives[name]; len(got) > 0 {
		t.Fatalf("nginx directive %q = %v, want absent", name, got)
	}
}

func assertNoRouterMeshCAVolume(t *testing.T, manifest string) {
	t.Helper()
	dep := renderedDeployment(t, manifest, "c8s-router")
	for _, volume := range dep.Spec.Template.Spec.Volumes {
		if volume.Name == "mesh-ca" {
			t.Fatalf("Deployment/router has mesh-ca volume, want absent: %#v", volume)
		}
	}
}

func TestRouterRejectsUnsafeProxyTLS(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "allowlist-enabled-not-bool",
			args: []string{
				"--set-string", "allowlist.enabled=false",
			},
			want: "router.allowlist.enabled must be a boolean; do not set it via --set-string, got: false",
		},
		{
			name: "allowlist-proxy-port-out-of-range",
			args: []string{
				"--set", "allowlist.proxyPort=0",
			},
			want: "router.allowlist.proxyPort must be between 1 and 65535, got: 0",
		},
		{
			name: "allowlist-proxy-port-collides-with-attestation",
			args: []string{
				"--set", "allowlist.proxyPort=8800",
			},
			want: "router.allowlist.proxyPort must differ from router.attest.port, got: 8800",
		},
		{
			name: "allowlist-proxy-port-collides-with-nginx",
			args: []string{
				"--set", "allowlist.proxyPort=8443",
			},
			want: "router.allowlist.proxyPort must differ from router.nginx.httpsPort, got: 8443",
		},
		{
			name: "allowlist-write-rate-not-positive",
			args: []string{
				"--set", "allowlist.rateLimit.requestsPerSecond=0",
			},
			want: "router.allowlist.rateLimit.requestsPerSecond must be a positive integer, got: 0",
		},
		{
			name: "allowlist-write-rate-exceeds-total",
			args: []string{
				"--set", "allowlist.rateLimit.requestsPerSecond=9",
			},
			want: "VALIDATION_ERROR kind=router_allowlist_rate_budget: router.allowlist.rateLimit.requestsPerSecond must not exceed rateLimit.totalRequestsPerSecond (8), got: 9",
		},
		{
			name: "allowlist-write-burst-not-positive",
			args: []string{
				"--set", "allowlist.rateLimit.burst=0",
			},
			want: "router.allowlist.rateLimit.burst must be a positive integer, got: 0",
		},
		{
			name: "allowlist-write-burst-exceeds-total",
			args: []string{
				"--set", "allowlist.rateLimit.burst=16",
			},
			want: "VALIDATION_ERROR kind=router_allowlist_rate_budget: router.allowlist.rateLimit.burst must not exceed rateLimit.totalBurst (15), got: 16",
		},
		{
			name: "allowlist-write-total-rate-consumes-cds-capacity",
			args: []string{
				"--set", "allowlist.rateLimit.totalRequestsPerSecond=10",
			},
			want: "VALIDATION_ERROR kind=router_allowlist_rate_budget: router.allowlist.rateLimit.totalRequestsPerSecond must be less than cds.rateLimit (10), got: 10",
		},
		{
			name: "allowlist-write-total-burst-consumes-cds-capacity",
			args: []string{
				"--set", "allowlist.rateLimit.totalBurst=20",
			},
			want: "VALIDATION_ERROR kind=router_allowlist_rate_budget: router.allowlist.rateLimit.totalBurst must be less than cds.rateBurst (20), got: 20",
		},
		{
			name: "allowlist-read-rate-not-positive",
			args: []string{
				"--set", "allowlist.readRateLimit.requestsPerSecond=0",
			},
			want: "router.allowlist.readRateLimit.requestsPerSecond must be a positive integer, got: 0",
		},
		{
			name: "allowlist-read-burst-not-positive",
			args: []string{
				"--set", "allowlist.readRateLimit.burst=0",
			},
			want: "router.allowlist.readRateLimit.burst must be a positive integer, got: 0",
		},
		{
			name: "route-verifyDepth-injection",
			args: []string{
				"--set-string", "routes[0].path=/x",
				"--set-string", "routes[0].backend.address=svc:8080",
				"--set-string", "routes[0].backend.protocol=https",
				"--set", "routes[0].backend.tls.verify=true",
				"--set-string", "routes[0].backend.tls.verifyDepth=9; return 444",
			},
			want: "router.routes[0].backend.tls.verifyDepth must be a non-negative integer, got: 9; return 444",
		},
		{
			name: "route-tls-on-http-backend",
			args: []string{
				"--set-string", "routes[0].path=/x",
				"--set-string", "routes[0].backend.address=svc:8080",
				"--set", "routes[0].backend.tls.verify=true",
			},
			want: "router.routes[0].backend.tls.verify and useCDSClientCert require backend.protocol: https",
		},
		{
			name: "route-verify-not-bool",
			args: []string{
				"--set-string", "routes[0].path=/x",
				"--set-string", "routes[0].backend.address=svc:8080",
				"--set-string", "routes[0].backend.protocol=https",
				"--set-string", "routes[0].backend.tls.verify=false",
			},
			want: "router.routes[0].backend.tls.verify must be a boolean; do not set it via --set-string, got: false",
		},
		{
			name: "route-address-with-hash",
			args: []string{
				"--set-string", "routes[0].path=/x",
				"--set-string", "routes[0].backend.address=svc:8080#x",
			},
			want: "router.routes[0].backend.address must be a host:port address without scheme, whitespace, semicolons, braces, slashes, or '#', got: svc:8080#x",
		},
		{
			name: "route-serverName-with-slash",
			args: []string{
				"--set-string", "routes[0].path=/x",
				"--set-string", "routes[0].backend.address=svc:8080",
				"--set-string", "routes[0].backend.protocol=https",
				"--set-string", "routes[0].backend.tls.serverName=a/b",
			},
			want: "router.routes[0].backend.tls.serverName must not contain whitespace, semicolons, braces, slashes, or '#', got: a/b",
		},
		{
			name: "upstream-serverName-injection",
			args: []string{
				"--set", "upstream.protocol=https",
				"--set", "upstream.tls.verify=true",
				"--set-string", "upstream.tls.serverName=evil; return 444",
			},
			want: "router.upstream.tls.serverName must not contain whitespace, semicolons, braces, slashes, or '#', got: evil; return 444",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, err := helmTemplateRouter(t, tt.args...)
			if err == nil {
				t.Fatalf("helm template succeeded, want %q\n%s", tt.want, out)
			}
			assertHelmFailMessage(t, out, tt.want)
		})
	}
}

// TestRouterVerifyDepthZeroPreserved guards against the sprig `default` footgun
// where an int 0 is treated as empty: an explicit verifyDepth: 0 (verify leaf
// only) must reach nginx as 0, not be silently bumped to the default 2.
func TestRouterVerifyDepthZeroPreserved(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set", "upstream.protocol=https",
		"--set", "upstream.tls.verify=true",
		"--set", "upstream.tls.verifyDepth=0",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	cfg.location(t, "prefix", "/").assertDirective(t, "proxy_ssl_verify_depth", "0")
}

// TestRouterMultiRouteVerifiedRouteUsesMeshCABundle pins that a verified HTTPS
// route using the default (mesh) CA resolves its trusted cert to the mesh CA
// bundle the get-cert sidecar writes alongside the leaf, even when an earlier
// route does not need it.
func TestRouterMultiRouteVerifiedRouteUsesMeshCABundle(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set-string", "routes[0].path=/a",
		"--set-string", "routes[0].backend.address=svc-a:8080",
		"--set-string", "routes[0].backend.protocol=https",
		"--set", "routes[0].backend.tls.verify=true",
		"--set-string", "routes[0].backend.tls.trustedCAPath=/tls/other.pem",
		"--set-string", "routes[1].path=/b",
		"--set-string", "routes[1].backend.address=svc-b:8080",
		"--set-string", "routes[1].backend.protocol=https",
		"--set", "routes[1].backend.tls.verify=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	route := cfg.location(t, "prefix", "/b")
	route.assertDirective(t, "proxy_ssl_verify", "on")
	route.assertDirective(t, "proxy_ssl_trusted_certificate", "/tls/ca.pem")
}

// TestRouterRejectsUnsecuredRoute pins the per-route secured-backend guard,
// mirroring the catch-all upstream: a route backend must be https with
// tls.verify=true (app-TLS). A plaintext http backend, or https without verify,
// fails the render; there is no plaintext-to-unattested acknowledgment.
func TestRouterRejectsUnsecuredRoute(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		kind string
	}{
		{
			name: "http-route",
			args: []string{
				"--set-string", "routes[0].path=/x",
				"--set-string", "routes[0].backend.address=svc:8080",
			},
			kind: "router_unsecured_route",
		},
		{
			name: "unverified-https-route",
			args: []string{
				"--set-string", "routes[0].path=/x",
				"--set-string", "routes[0].backend.address=svc:8080",
				"--set-string", "routes[0].backend.protocol=https",
			},
			kind: "router_unsecured_route",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, err := helmTemplateRouter(t, tt.args...)
			if err == nil {
				t.Fatalf("helm template succeeded, want %s failure\n%s", tt.kind, out)
			}
			if got := parseValidationErrorKind(out); got != tt.kind {
				t.Fatalf("validation kind = %q, want %q\n%s", got, tt.kind, out)
			}
		})
	}
}

func TestRouterRejectsInvalidRouteMatch(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set-string", "routes[0].path=/allowlist",
		"--set-string", "routes[0].match=regex",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc:8080",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want invalid route match failure\n%s", out)
	}
	assertHelmFailMessage(t, out, "router.routes[0].match must be 'exact' or 'prefix', got: regex")
}

func TestRouterRejectsMissingRouteFields(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "path",
			args: []string{
				"--set-string", "routes[0].backend.address=cds.c8s-system.svc:8080",
			},
			want: "router.routes[0].path is required",
		},
		{
			name: "backend",
			args: []string{
				"--set-string", "routes[0].path=/allowlist",
			},
			want: "router.routes[0].backend is required",
		},
		{
			name: "backend-address",
			args: []string{
				"--set-string", "routes[0].path=/allowlist",
				"--set-string", "routes[0].backend.protocol=https",
			},
			want: "router.routes[0].backend.address is required",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, err := helmTemplateRouter(t, tt.args...)
			if err == nil {
				t.Fatalf("helm template succeeded, want missing route field failure\n%s", out)
			}
			assertHelmFailMessage(t, out, tt.want)
		})
	}
}

func TestRouterRejectsRouteUpstream(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set-string", "routes[0].path=/allowlist",
		"--set-string", "routes[0].upstream=http://cds.c8s-system.svc:8080",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want unsupported route upstream failure\n%s", out)
	}
	assertHelmFailMessage(t, out, "router.routes[0].upstream is not supported; set backend.address and backend.protocol instead")
}

func TestRouterRejectsInvalidTypedRouteProtocol(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set-string", "routes[0].path=/allowlist",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc:8080",
		"--set-string", "routes[0].backend.protocol=grpc",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want invalid typed route protocol failure\n%s", out)
	}
	assertHelmFailMessage(t, out, "router.routes[0].backend.protocol must be 'http' or 'https', got: grpc")
}

func TestRouterRejectsUnsafeRoutePath(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set-string", "routes[0].path=/bad;return",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc:8080",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want unsafe route path failure\n%s", out)
	}
	assertHelmFailMessage(t, out, "router.routes[0].path must start with '/' and contain only URI path characters safe for nginx locations, got: /bad;return")
}

func TestRouterCustomTrustedCAPathDoesNotMountMeshCA(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set", "upstream.protocol=https",
		"--set", "upstream.tls.verify=true",
		"--set-string", "upstream.tls.trustedCAPath=/etc/ssl/certs/ca-certificates.crt",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	defaultRoute := cfg.location(t, "prefix", "/")
	defaultRoute.assertDirective(t, "proxy_ssl_trusted_certificate", "/etc/ssl/certs/ca-certificates.crt")
	assertNoRouterMeshCAVolume(t, out)
}

// TestRouterExplicitTrustedCAPathRendersVerbatim pins that an operator-supplied
// trustedCAPath is emitted verbatim in proxy_ssl_trusted_certificate. The chart
// no longer mounts any volume for it: providing the file at that path is the
// operator's responsibility.
func TestRouterExplicitTrustedCAPathRendersVerbatim(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set", "upstream.protocol=https",
		"--set", "upstream.tls.verify=true",
		"--set-string", "upstream.tls.trustedCAPath=/mesh-ca/ca.pem",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	defaultRoute := cfg.location(t, "prefix", "/")
	defaultRoute.assertDirective(t, "proxy_ssl_trusted_certificate", "/mesh-ca/ca.pem")
}

func TestRouterDiscoveryRequiresAdvertisedMeshCA(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set", "discovery.enabled=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	meshCA := cfg.location(t, "exact", "/.well-known/mesh-ca.pem")
	meshCA.assertDirective(t, "alias", "/tls/ca.pem")
	assertContainerArgs(t, routerGetCertContainer(t, out, "c8s-cert"),
		"--ca-out=/tls/ca.pem",
		"--discovery-mesh-ca-url=/.well-known/mesh-ca.pem")
}

// TestRouterGetCertWritesMeshCABundle pins the mechanism that replaced the
// c8s-cds-mesh-ca ConfigMap mount: the c8s-cert sidecar writes the mesh CA
// bundle to /tls/ca.pem (the tls-certs volume that already holds the leaf).
func TestRouterGetCertWritesMeshCABundle(t *testing.T) {
	out, err := helmTemplateRouter(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertContainerArgs(t, routerGetCertContainer(t, out, "c8s-cert"),
		"--ca-out=/tls/ca.pem")
}

func TestRouterDiscoveryReportsCDSModeWithoutPublicTLSSecret(t *testing.T) {
	out, err := helmTemplateRouter(t,
		"--set", "discovery.enabled=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertContainerArgs(t, routerGetCertContainer(t, out, "c8s-cert"),
		"--discovery-public-tls-mode=cds")
}

func TestRouterRollsOnNginxConfigChange(t *testing.T) {
	defaultOut, err := helmTemplateRouter(t)
	if err != nil {
		t.Fatalf("helm template default config: %v\n%s", err, defaultOut)
	}
	defaultChecksum := renderedDeployment(t, defaultOut, "c8s-router").Spec.Template.Annotations["checksum/nginx-config"]
	if defaultChecksum == "" {
		t.Fatalf("default checksum/nginx-config is empty\n%s", defaultOut)
	}

	changedOut, err := helmTemplateRouter(t,
		"--set-string", "upstream.address=other-upstream:8080",
	)
	if err != nil {
		t.Fatalf("helm template changed config: %v\n%s", err, changedOut)
	}
	changedChecksum := renderedDeployment(t, changedOut, "c8s-router").Spec.Template.Annotations["checksum/nginx-config"]
	if changedChecksum == defaultChecksum {
		t.Fatalf("checksum/nginx-config did not change after changing upstream: %s", defaultChecksum)
	}
}

func TestChartOperatorRBACIsScoped(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// Decode the ClusterRole and assert the verbs exactly so a broadened
	// grant fails. The event recorder needs events, but only create/patch
	// (recorder aggregation), never read or delete across the cluster.
	var role rbacv1.ClusterRole
	if !findDoc(t, out, "ClusterRole", "c8s-operator", &role) {
		t.Fatalf("render missing ClusterRole c8s-operator\n%s", out)
	}
	for _, tc := range []struct {
		apiGroup, resource string
		verbs              []string
	}{
		{"confidential.ai", "confidentialworkloads", []string{"get", "list", "watch"}},
		{"confidential.ai", "confidentialworkloads/status", []string{"get", "update", "patch"}},
		{"", "pods", []string{"get", "list", "watch", "delete"}},
		{"coordination.k8s.io", "leases", []string{"get", "list", "watch", "create", "update", "patch", "delete"}},
		{"admissionregistration.k8s.io", "mutatingwebhookconfigurations", []string{"get", "update", "patch"}},
	} {
		if got := operatorVerbsFor(role, tc.apiGroup, tc.resource); !slices.Equal(got, tc.verbs) {
			t.Fatalf("operator %s verbs = %v, want %v", tc.resource, got, tc.verbs)
		}
	}
	if got := operatorVerbsFor(role, "", "events"); !slices.Equal(got, []string{"create", "patch"}) {
		t.Fatalf("operator events verbs = %v, want [create patch]", got)
	}
	// The workload-service reconciler reads workloads (never mutates them)
	// and owns the headless Services it provisions in workload namespaces.
	for _, resource := range []string{"deployments", "statefulsets", "daemonsets"} {
		if got := operatorVerbsFor(role, "apps", resource); !slices.Equal(got, []string{"get", "list", "watch"}) {
			t.Fatalf("operator %s verbs = %v, want read-only [get list watch]", resource, got)
		}
	}
	if got := operatorVerbsFor(role, "", "services"); !slices.Equal(got, []string{"get", "list", "watch", "create", "update", "delete"}) {
		t.Fatalf("operator services verbs = %v", got)
	}
	// No rendered Role/ClusterRole may grant any of these resources at all.
	// nodes is granted — but only to CDS's node-reader, which keeps the
	// sandbox-digests bound current from the live node list.
	banned := []string{"confidentialworkloads/finalizers", "replicasets", "secrets", "configmaps", "rolebindings"}
	var nodesGrantors []string
	iterateManifests(t, out, func(doc []byte) bool {
		var head docMeta
		if err := sigsyaml.Unmarshal(doc, &head); err != nil || (head.Kind != "ClusterRole" && head.Kind != "Role") {
			return false
		}
		var r struct {
			Rules []rbacv1.PolicyRule `json:"rules"`
		}
		if err := sigsyaml.Unmarshal(doc, &r); err != nil {
			t.Fatalf("decode %s %s rules: %v", head.Kind, head.Metadata.Name, err)
		}
		for _, rule := range r.Rules {
			for _, resource := range banned {
				if slices.Contains(rule.Resources, resource) {
					t.Errorf("%s %s grants broad RBAC resource %q", head.Kind, head.Metadata.Name, resource)
				}
			}
			if slices.Contains(rule.Resources, "nodes") {
				nodesGrantors = append(nodesGrantors, head.Metadata.Name)
			}
		}
		return false
	})
	if !slices.Equal(nodesGrantors, []string{"c8s-cds-node-reader"}) {
		t.Fatalf("nodes granted to %v, want only c8s-cds-node-reader", nodesGrantors)
	}
}

// operatorVerbsFor returns the verbs the ClusterRole grants on (apiGroup,
// resource), nil if no rule covers it. It does not expand wildcards: a "*"
// resource or apiGroup matches only a literal "*" lookup, which is intentional
// for least-privilege assertions.
func operatorVerbsFor(role rbacv1.ClusterRole, apiGroup, resource string) []string {
	for _, rule := range role.Rules {
		if slices.Contains(rule.APIGroups, apiGroup) && slices.Contains(rule.Resources, resource) {
			return rule.Verbs
		}
	}
	return nil
}

// CDS derives the sandbox-digests dial bound from the live node list unless
// cds.sandboxInventoryCIDRs pins it statically, so the node-reader role and
// the API token exist only in the default mode — and the grant is read-only.
func TestChartCDSNodeReaderRBAC(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var role rbacv1.ClusterRole
	if !findDoc(t, out, "ClusterRole", "c8s-cds-node-reader", &role) {
		t.Fatalf("default render missing the CDS node-reader ClusterRole\n%s", out)
	}
	if len(role.Rules) != 1 {
		t.Fatalf("CDS node-reader rules = %v, want nodes only", role.Rules)
	}
	if got := operatorVerbsFor(role, "", "nodes"); !slices.Equal(got, []string{"get", "list", "watch"}) {
		t.Fatalf("CDS nodes verbs = %v, want read-only [get list watch]", got)
	}
	var deploy appsv1.Deployment
	if !findDoc(t, out, "Deployment", "c8s-cds", &deploy) {
		t.Fatalf("render missing the CDS Deployment\n%s", out)
	}
	if am := deploy.Spec.Template.Spec.AutomountServiceAccountToken; am == nil || !*am {
		t.Fatalf("lister mode must mount the CDS API token, got %v", am)
	}

	staticOut, err := helmTemplate(t, "--set-string", "cds.sandboxInventoryCIDRs[0]=10.0.0.0/24")
	if err != nil {
		t.Fatalf("helm template static CIDRs: %v\n%s", err, staticOut)
	}
	if findDoc(t, staticOut, "ClusterRole", "c8s-cds-node-reader", &role) {
		t.Fatalf("static CIDRs rendered the node-reader role\n%s", staticOut)
	}
	if !findDoc(t, staticOut, "Deployment", "c8s-cds", &deploy) {
		t.Fatalf("render missing the CDS Deployment\n%s", staticOut)
	}
	if am := deploy.Spec.Template.Spec.AutomountServiceAccountToken; am == nil || *am {
		t.Fatalf("static CIDRs must not mount the CDS API token, got %v", am)
	}
}

func TestChartWebhookAddsCABundleRBAC(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var role rbacv1.ClusterRole
	if !findDoc(t, out, "ClusterRole", "c8s-operator", &role) {
		t.Fatalf("render missing ClusterRole c8s-operator\n%s", out)
	}
	if got := operatorVerbsFor(role, "admissionregistration.k8s.io", "mutatingwebhookconfigurations"); !slices.Equal(got, []string{"get", "update", "patch"}) {
		t.Fatalf("operator mutatingwebhookconfigurations verbs = %v, want [get update patch]", got)
	}
}

func TestChartRollsAttestationApiOnConfigChange(t *testing.T) {
	defaultOut, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template default config: %v\n%s", err, defaultOut)
	}
	defaultChecksum := renderedDaemonSet(t, defaultOut, "c8s-attestation-api").Spec.Template.Annotations["checksum/config"]
	if defaultChecksum == "" {
		t.Fatalf("default checksum/config is empty\n%s", defaultOut)
	}

	changedOut, err := helmTemplate(t,
		"--set", "attestationApi.platforms[0]=az-snp",
	)
	if err != nil {
		t.Fatalf("helm template changed config: %v\n%s", err, changedOut)
	}
	changedChecksum := renderedDaemonSet(t, changedOut, "c8s-attestation-api").Spec.Template.Annotations["checksum/config"]
	if changedChecksum == defaultChecksum {
		t.Fatalf("checksum/config did not change after changing platforms: %s", defaultChecksum)
	}
}

// TestChartCwLabelIntegrityPolicyRendersByDefault: the cw-label
// ValidatingAdmissionPolicy guards Service-membership identity and must ship
// on by default, with the immutability (oldObject) check present and the
// webhook's namespace exclusions mirrored.
func TestChartCwLabelIntegrityPolicyRendersByDefault(t *testing.T) {
	out, err := helmTemplate(t, "--set", "webhook.extraExcluded[0]=skip-me")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var policy admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, out, "ValidatingAdmissionPolicy", "c8s-cw-label-integrity", &policy) {
		t.Fatalf("missing cw-label-integrity ValidatingAdmissionPolicy\n%s", out)
	}
	ops := policy.Spec.MatchConstraints.ResourceRules[0].Operations
	if !slices.Contains(ops, admissionregv1.Update) {
		t.Fatalf("policy operations = %v, must include UPDATE (post-create label mutation is the attack)", ops)
	}
	if !slices.ContainsFunc(policy.Spec.Validations, func(v admissionregv1.Validation) bool {
		return strings.Contains(v.Expression, "oldObject")
	}) {
		t.Fatalf("policy has no oldObject immutability validation: %+v", policy.Spec.Validations)
	}
	// The cw label must not exist without the injected c8s-cert sidecar, or a
	// pod could keep workload identity while shedding attestation-bound
	// injection (webhook pod_mutator.go, injectInitContainers / VAP backstop).
	if !slices.ContainsFunc(policy.Spec.Variables, func(v admissionregv1.Variable) bool {
		return v.Name == "hasCertSidecar" && strings.Contains(v.Expression, "initContainers")
	}) {
		t.Fatalf("policy missing hasCertSidecar variable: %+v", policy.Spec.Variables)
	}
	if !slices.ContainsFunc(policy.Spec.Validations, func(v admissionregv1.Validation) bool {
		return strings.Contains(v.Expression, "hasCertSidecar")
	}) {
		t.Fatalf("policy has no c8s-cert sidecar-presence validation: %+v", policy.Spec.Validations)
	}
	var binding admissionregv1.ValidatingAdmissionPolicyBinding
	if !findDoc(t, out, "ValidatingAdmissionPolicyBinding", "c8s-cw-label-integrity", &binding) {
		t.Fatalf("missing cw-label-integrity ValidatingAdmissionPolicyBinding\n%s", out)
	}
	excluded := selectorExpressionValues(binding.Spec.MatchResources.NamespaceSelector,
		"kubernetes.io/metadata.name", metav1.LabelSelectorOpNotIn)
	for _, ns := range []string{"c8s-system", "kube-system", "kube-public", "kube-node-lease", "skip-me"} {
		if !slices.Contains(excluded, ns) {
			t.Fatalf("binding namespace exclusions %v missing %s (must mirror the webhook)", excluded, ns)
		}
	}
}

func TestChartCwLabelIntegrityPolicyDisabled(t *testing.T) {
	out, err := helmTemplate(t, "--set", "webhook.cwLabelPolicy.enabled=false")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "ValidatingAdmissionPolicy", "c8s-cw-label-integrity") {
		t.Fatalf("cw-label-integrity policy rendered while disabled\n%s", out)
	}
}

// On node-CVM the operator gets the host-dir mount source, from which the
// webhook derives the get-cert workload-claims injection.
func TestChartWorkloadClaimsOperatorFlags(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedOperatorArgs(t, out)
	var hasHostDir bool
	for _, a := range args {
		if strings.HasPrefix(a, "--workload-claims-host-dir=") {
			hasHostDir = true
		}
	}
	if !hasHostDir {
		t.Fatalf("operator missing workload-claims-host-dir flag: %v", args)
	}
}

func TestChartNoRuntimeClassOnRouter(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	dep := renderedDeployment(t, out, "c8s-router")
	if rc := dep.Spec.Template.Spec.RuntimeClassName; rc != nil {
		t.Errorf("c8s-router runtimeClassName = %q, want unset", *rc)
	}
}

// TestChartNriImagePolicyDistroSelectsContainerdLayout: nriImagePolicy.distro
// drives the host containerd directory the installer binds and the patch
// strategy. The drop-in file path itself is discovered at runtime (the config
// file name varies), so it is not asserted here — only the dir, mode, restart.
func TestChartNriImagePolicyDistroSelectsContainerdLayout(t *testing.T) {
	for _, tc := range []struct {
		distro      string
		wantDir     string
		wantMode    string
		wantRestart string
	}{
		{
			distro:      "k8s",
			wantDir:     "/etc/containerd",
			wantMode:    "patch",
			wantRestart: "systemctl restart containerd",
		},
		{
			distro:      "rke2",
			wantDir:     "/var/lib/rancher/rke2/agent/etc/containerd",
			wantMode:    "dropin",
			wantRestart: "if systemctl is-active --quiet rke2-server; then systemctl restart rke2-server; else systemctl restart rke2-agent; fi",
		},
	} {
		t.Run(tc.distro, func(t *testing.T) {
			out, err := helmTemplate(t, "--set-string", "nriImagePolicy.distro="+tc.distro)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			for _, name := range []string{"c8s-nri-image-policy-worker"} {
				ds := renderedDaemonSet(t, out, name)
				if got := hostPathVolume(t, ds, "host-containerd-config"); got != tc.wantDir {
					t.Fatalf("%s distro %q: host-containerd-config hostPath = %q, want %q", name, tc.distro, got, tc.wantDir)
				}
				script := strings.Join(containerArgs(t, &ds, "install"), "\n")
				for _, want := range []string{
					"CONTAINERD_DIR=/host" + tc.wantDir,
					`CONTAINERD_CONFIG_MODE="` + tc.wantMode + `"`,
					`RESTART_COMMAND="` + tc.wantRestart + `"`,
				} {
					if !strings.Contains(script, want) {
						t.Fatalf("%s distro %q: install script missing %q\n%s", name, tc.distro, want, script)
					}
				}
			}
		})
	}
}

// TestChartNriImagePolicyRejectsUnknownDistro: an unsupported distro must fail
// the render, not silently fall through to a wrong containerd layout.
func TestChartNriImagePolicyRejectsUnknownDistro(t *testing.T) {
	out, err := helmTemplate(t, "--set-string", "nriImagePolicy.distro=openshift")
	if err == nil {
		t.Fatalf("helm template succeeded for an unknown nriImagePolicy.distro, want failure\n%s", out)
	}
}

// TestChartNriImagePolicyDetachesContainerdRestart: the installer must hand the
// host containerd restart to systemd-run (host PID 1), not run it in this pod's
// process tree. A restart via `nsenter ... sh -c "$RESTART_COMMAND"` is killed
// with the pod when containerd bounces, which on a sole control-plane node
// interrupts the rke2 bootstrap and wedges it.
func TestChartNriImagePolicyDetachesContainerdRestart(t *testing.T) {
	out, err := helmTemplate(t, "--set-string", "nriImagePolicy.distro=rke2")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	if !strings.Contains(script, "systemd-run") {
		t.Fatalf("install script must detach the containerd restart via systemd-run\n%s", script)
	}
	// The bare in-pod form (nsenter ... -- sh -c "$RESTART_COMMAND") must be
	// gone; the restart now goes nsenter ... -- systemd-run ... sh -c "...".
	if strings.Contains(script, `-p -- sh -c "$RESTART_COMMAND"`) {
		t.Fatalf("install script still runs RESTART_COMMAND in-pod (not detached)\n%s", script)
	}
}

// TestChartNriImagePolicyContainerdPrepInitContainer: on rke2 the installer
// DaemonSet must run a containerd-prep initContainer before `install`, so the
// drop-in import exists by the time `install` writes its drop-in. On k8s the
// installer patches config.toml in place, so the prep must be absent.
func TestChartNriImagePolicyContainerdPrepInitContainer(t *testing.T) {
	t.Run("rke2", func(t *testing.T) {
		out, err := helmTemplate(t, "--set-string", "nriImagePolicy.distro=rke2")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		for _, name := range []string{"c8s-nri-image-policy-worker"} {
			ds := renderedDaemonSet(t, out, name)
			names := containerNames(ds.Spec.Template.Spec.InitContainers)
			prepIdx, installIdx := slices.Index(names, "containerd-prep"), slices.Index(names, "install")
			if prepIdx < 0 {
				t.Fatalf("rke2: %s missing containerd-prep initContainer; have %v", name, names)
			}
			// initContainers run in order: prep must precede install.
			if prepIdx > installIdx {
				t.Fatalf("%s: containerd-prep must run before install; initContainers=%v", name, names)
			}
			env := initContainerEnv(t, ds, "containerd-prep")
			if got := env["HOST_CONTAINERD_DIR"]; got != "/var/lib/rancher/rke2/agent/etc/containerd" {
				t.Errorf("%s HOST_CONTAINERD_DIR = %q, want the rke2 containerd dir", name, got)
			}
		}
	})

	t.Run("k8s", func(t *testing.T) {
		out, err := helmTemplate(t, "--set-string", "nriImagePolicy.distro=k8s")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		for _, name := range []string{"c8s-nri-image-policy-worker"} {
			ds := renderedDaemonSet(t, out, name)
			if _, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "containerd-prep"); ok {
				t.Fatalf("k8s: %s must not carry a containerd-prep initContainer", name)
			}
		}
	})
}

// initContainerEnv returns the env name->value map of a DaemonSet init container.
func initContainerEnv(t *testing.T, ds appsv1.DaemonSet, name string) map[string]string {
	t.Helper()
	for _, c := range ds.Spec.Template.Spec.InitContainers {
		if c.Name != name {
			continue
		}
		env := make(map[string]string, len(c.Env))
		for _, e := range c.Env {
			env[e.Name] = e.Value
		}
		return env
	}
	t.Fatalf("DaemonSet has no init container %q", name)
	return nil
}

// hostPathVolume returns the hostPath of the named volume on a DaemonSet.
func hostPathVolume(t *testing.T, ds appsv1.DaemonSet, name string) string {
	t.Helper()
	for _, v := range ds.Spec.Template.Spec.Volumes {
		if v.Name == name {
			if v.HostPath == nil {
				t.Fatalf("DaemonSet volume %q is not a hostPath volume", name)
			}
			return v.HostPath.Path
		}
	}
	t.Fatalf("DaemonSet has no volume %q", name)
	return ""
}

// baseNRIDigest is the nri-image-policy image digest the shared harness pins;
// the seed admits it argv-pinned, so the default fail-closed render is valid.
const baseNRIDigest = "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"

func helmTemplate(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm CLI not found")
	}
	base := []string{
		"template", "c8s", "c8s",
		// Pin the simulated cluster version at the chart's kubeVersion base
		// so the tests do not depend on the helm client's compiled default
		// (helm 3.14 simulates 1.29, below the base).
		"--kube-version", "1.30.0",
		"--namespace", "c8s-system",
		"--set", "image.tag=dev",
		"--set", "attestationApi.image.tag=dev",
		"--set", "cds.image.tag=dev",
		"--set", "ratlsMesh.image.tag=dev",
		"--set", "nriImagePolicy.image.tag=dev",
		// volumed is off by default, so its image is unused unless a test
		// enables it; set the tag here so those tests need not repeat it (its
		// own image requires a tag or digest, like every component).
		"--set", "volumed.image.tag=dev",
		// router has no default upstream (a silently-plaintext VIP was
		// removed); a c8s-<id> headless-Service address (what `c8s install
		// --upstream` derives) is the representative mesh-wrapped baseline, and
		// the chart recognizes that shape as mesh-wrapped. Tests for the
		// manual-upstream paths clear it via noUpstreamArgs.
		"--set-string", "router.upstream.address=c8s-infer.c8s-system.svc.cluster.local:8000",
		// The installer image must stay digest-pinned: the seed admits it
		// argv-pinned (c8s.argvPinnedEntries), which a tag cannot pin. No
		// bootstrap entry is needed — the uncovered_component_digest guard
		// exempts it as argvPinned. Tests that exercise the guard pin a
		// different, deliberately-uncovered component digest.
		"--set", "nriImagePolicy.image.digest=" + baseNRIDigest,
		"--set", "cds.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000001",
	}
	cmd := exec.Command("helm", append(base, args...)...)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// noUpstreamArgs clears the mesh-wrapped upstream that helmTemplate pins by
// default, for tests exercising the manual router.upstream paths.
func noUpstreamArgs(args ...string) []string {
	return append([]string{"--set-string", "router.upstream.address="}, args...)
}

// docMeta is the minimum we decode from each YAML doc to dispatch by kind+name.
type docMeta struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
}

// splitManifestDocs returns each non-empty doc in a multi-doc YAML stream as
// its own raw YAML chunk. helm template emits empty `---\n` separators that
// we silently drop.
func splitManifestDocs(manifest string) []string {
	var out []string
	for doc := range strings.SplitSeq(manifest, "\n---\n") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		out = append(out, doc)
	}
	return out
}

// findDoc returns the first YAML doc matching kind (and name when non-empty),
// decoded into out via sigs.k8s.io/yaml. Returns false if no match.
func findDoc(t *testing.T, manifest, kind, name string, out any) bool {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil {
			continue
		}
		if meta.Kind != kind {
			continue
		}
		if name != "" && meta.Metadata.Name != name {
			continue
		}
		if err := sigsyaml.Unmarshal([]byte(doc), out); err != nil {
			t.Fatalf("decode %s/%s: %v\n%s", kind, name, err, doc)
		}
		return true
	}
	return false
}

func renderedManifestHasKind(t *testing.T, manifest, kind string) bool {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err == nil && meta.Kind == kind {
			return true
		}
	}
	return false
}

func renderedManifestHasNamedKind(t *testing.T, manifest, kind, name string) bool {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err == nil && meta.Kind == kind && meta.Metadata.Name == name {
			return true
		}
	}
	return false
}

func renderedMutatingWebhook(t *testing.T, manifest, name string) admissionregv1.MutatingWebhook {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil || meta.Kind != "MutatingWebhookConfiguration" {
			continue
		}
		var cfg admissionregv1.MutatingWebhookConfiguration
		if err := sigsyaml.Unmarshal([]byte(doc), &cfg); err != nil {
			t.Fatalf("decode MutatingWebhookConfiguration: %v\n%s", err, doc)
		}
		for _, hook := range cfg.Webhooks {
			if hook.Name == name {
				return hook
			}
		}
	}
	t.Fatalf("rendered manifest missing MutatingWebhookConfiguration webhook %q\n%s", name, manifest)
	return admissionregv1.MutatingWebhook{}
}

func renderedMutatingWebhookNames(t *testing.T, manifest string) []string {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil || meta.Kind != "MutatingWebhookConfiguration" {
			continue
		}
		var cfg admissionregv1.MutatingWebhookConfiguration
		if err := sigsyaml.Unmarshal([]byte(doc), &cfg); err != nil {
			t.Fatalf("decode MutatingWebhookConfiguration: %v\n%s", err, doc)
		}
		names := make([]string, 0, len(cfg.Webhooks))
		for _, hook := range cfg.Webhooks {
			names = append(names, hook.Name)
		}
		return names
	}
	t.Fatalf("rendered manifest missing MutatingWebhookConfiguration\n%s", manifest)
	return nil
}

func selectorExpressionValues(selector *metav1.LabelSelector, key string, op metav1.LabelSelectorOperator) []string {
	if selector == nil {
		return nil
	}
	for _, expression := range selector.MatchExpressions {
		if expression.Key == key && expression.Operator == op {
			return expression.Values
		}
	}
	return nil
}

func renderedOperatorArgs(t *testing.T, manifest string) []string {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil || meta.Kind != "Deployment" {
			continue
		}
		var dep appsv1.Deployment
		if err := sigsyaml.Unmarshal([]byte(doc), &dep); err != nil {
			t.Fatalf("decode Deployment %q: %v\n%s", meta.Metadata.Name, err, doc)
		}
		for _, container := range dep.Spec.Template.Spec.Containers {
			if container.Name == "operator" {
				return container.Args
			}
		}
	}
	t.Fatalf("rendered manifest missing operator container\n%s", manifest)
	return nil
}

// TestChartCDSIsInMemorySingleton locks the two invariants the in-memory mesh
// CA depends on: the Deployment is a single replica (a second would mint a
// divergent trust root) and is annotated inMemory (the CA key never lands in a
// Secret/PVC). The cds component's presence is covered by
// TestChartDefaultRendersReplacementStack.
func TestChartCDSIsInMemorySingleton(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	dep := renderedDeployment(t, out, "c8s-cds")
	if got := dep.Spec.Template.Annotations["confidential.ai/trust-root-mode"]; got != "inMemory" {
		t.Fatalf("cds Deployment trust-root-mode annotation = %q, want inMemory", got)
	}
	if got := *dep.Spec.Replicas; got != 1 {
		t.Fatalf("cds replicas = %d, want 1 (in-memory CA singleton)", got)
	}
}

// TestChartPointsClientsAtCDS proves the operator-injected get-cert and the
// ratls-mesh daemonset both resolve their single --cds-url to the cds Service,
// and the mesh runs in cds cert-mode — this locks that wiring.
func TestChartPointsClientsAtCDS(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	const wantURL = "https://c8s-cds.c8s-system.svc:8443"

	operatorArgs := renderedOperatorArgs(t, out)
	assertContainerHasArg(t, "operator", operatorArgs, "--cds-url="+wantURL)

	meshArgs := renderedDaemonSetContainer(t, out, "c8s-ratls-mesh", "ratls-mesh").Args
	if got, ok := containerArgValue(meshArgs, "--cds-url"); !ok || got != wantURL {
		t.Fatalf("ratls-mesh --cds-url = (%q, %v), want %q\nargs: %v", got, ok, wantURL, meshArgs)
	}
	if got, ok := containerArgValue(meshArgs, "--cert-mode"); !ok || got != "cds" {
		t.Fatalf("ratls-mesh --cert-mode = (%q, %v), want cds\nargs: %v", got, ok, meshArgs)
	}
}

// TestChartCDSWiresInProcessTrustRoot confirms the flag set: the in-memory CA
// (no Secret/ca-cert flag) and the allowlist DB.
func TestChartCDSWiresInProcessTrustRoot(t *testing.T) {
	// gke: host-side attestation-api over the on-node Unix socket. node points
	// CDS at the baked host attestation-api via HOST_IP (covered separately),
	// so pin the socket mode here.
	out, err := helmTemplate(t, "--set", "attestationApi.cvmMode=gke")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	for _, want := range []string{
		"--attestation-api-url=unix:///var/run/nri-image-policy/attestation-api.sock",
		"--allowlist-db=/data/allowlist.db",
		"--ca-common-name=c8s Mesh CA",
		"--ca-cert-validity=8760h",
	} {
		assertContainerHasArg(t, "cds", args, want)
	}
}

// TestChartCDSAllowlistPersistentTracksPVC pins --allowlist-persistent to
// cds.persistence.enabled, so CDS knows whether its allowlist store is durable
// and warns at startup when it is not (operator-added digests are lost on a
// restart otherwise).
func TestChartCDSAllowlistPersistentTracksPVC(t *testing.T) {
	t.Run("default (no persistence) renders false", func(t *testing.T) {
		out, err := helmTemplate(t)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
		assertContainerHasArg(t, "cds", args, "--allowlist-persistent=false")
	})
	t.Run("persistence enabled renders true", func(t *testing.T) {
		out, err := helmTemplate(t, "--set", "cds.persistence.enabled=true")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
		assertContainerHasArg(t, "cds", args, "--allowlist-persistent=true")
	})
}

// TestChartCDSServesRATLS confirms the cds container renders with a non-empty
// --ratls-platform by default, i.e. RA-TLS serving is ON. An empty platform
// makes cds serve /attest over plaintext HTTP,
// collapsing the H1 bootstrap-channel MITM defence — a regression this guards.
func TestChartCDSServesRATLS(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	// Default cds.ratlsPlatform is snp; an empty value would render
	// "--ratls-platform=" and serve plaintext. Assert the exact default token.
	assertContainerHasArg(t, "cds", args, "--ratls-platform=snp")
}

// TestChartCDSDnsSanPatternAcceptsAnyNamespace pins the always-present
// in-cluster --dns-san-pattern and the identities it admits: CDS full-matches
// the regex (issuer.fullRegexMatch), so it must sign any
// <service>.<namespace>.svc (workloads live in their own namespaces, not just
// the release namespace) while still rejecting SANs that are not in-cluster
// Service DNS names. This pattern is emitted by the chart unconditionally, so a
// per-cluster public hostname (cds.dnsSanPatterns) only ever adds to it.
func TestChartCDSDnsSanPatternAcceptsAnyNamespace(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	const wantArg = "--dns-san-pattern=^[a-z0-9-]+[.][a-z0-9-]+[.]svc$"
	assertContainerHasArg(t, "cds", args, wantArg)

	re := regexp.MustCompile(strings.TrimPrefix(wantArg, "--dns-san-pattern="))
	fullMatch := func(s string) bool {
		loc := re.FindStringIndex(s)
		return loc != nil && loc[0] == 0 && loc[1] == len(s)
	}
	for _, san := range []string{
		"c8s-router.c8s-system.svc",
		"ratls-mesh.c8s-system.svc",
		"acme-vllm-router-service.vllm.svc",
		"acme-vllm-acme-opt-125m-engine-service.vllm.svc",
	} {
		if !fullMatch(san) {
			t.Fatalf("default dns-san-pattern should accept in-cluster SAN %q", san)
		}
	}
	for _, san := range []string{
		"evil.example.com",                    // not a .svc name
		"svc.cluster.local",                   // wrong shape
		"a.b.c.svc",                           // more than <name>.<ns>
		"router.c8s-system.svc.cluster.local", // trailing labels
	} {
		if fullMatch(san) {
			t.Fatalf("default dns-san-pattern should reject non-Service SAN %q", san)
		}
	}
}

// TestChartCDSDnsSanPatternsAppendPublicHostname proves that adding a public
// hostname via cds.dnsSanPatterns (the per-cluster ingress override that broke
// the mesh before this fix) leaves the always-present in-cluster pattern
// intact, so CDS renders both --dns-san-pattern args and both the public
// hostname and the mesh Service SANs validate.
func TestChartCDSDnsSanPatternsAppendPublicHostname(t *testing.T) {
	// helm --set strips backslashes, so use a literal pattern that needs no
	// escaping to prove plumbing without the assertion fighting --set parsing.
	const public = "confidential-gke-confidential-dot-ai"
	out, err := helmTemplate(t, "--set", "cds.dnsSanPatterns[0]="+public)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	assertContainerHasArg(t, "cds", args, "--dns-san-pattern=^[a-z0-9-]+[.][a-z0-9-]+[.]svc$")
	assertContainerHasArg(t, "cds", args, "--dns-san-pattern="+public)
}

// TestChartCertDependentPodStrategies pins router's rollout strategy to its
// constraint: with the default hostPort binding it must Recreate (two pods on
// a node would collide on the host port, and a surge pod could never schedule
// on a single-node cluster, deadlocking the roll); without hostPort it surges
// so the new cert-holding pod is Ready before the old one retires. An
// explicit router.strategy renders verbatim.
func TestChartCertDependentPodStrategies(t *testing.T) {
	t.Run("default hostPort binds, so Recreate", func(t *testing.T) {
		out, err := helmTemplate(t)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		router := renderedDeployment(t, out, "c8s-router")
		if router.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
			t.Errorf("c8s-router strategy = %q, want Recreate (host-port binding forbids two concurrent pods on a node)", router.Spec.Strategy.Type)
		}
	})

	t.Run("no hostPort surges with no gap", func(t *testing.T) {
		out, err := helmTemplate(t, "--set", "router.hostPort.enabled=false")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		router := renderedDeployment(t, out, "c8s-router")
		if router.Spec.Strategy.Type != appsv1.RollingUpdateDeploymentStrategyType {
			t.Errorf("c8s-router strategy = %q, want RollingUpdate", router.Spec.Strategy.Type)
		}
		if ru := router.Spec.Strategy.RollingUpdate; ru == nil ||
			ru.MaxUnavailable == nil || ru.MaxUnavailable.IntValue() != 0 ||
			ru.MaxSurge == nil || ru.MaxSurge.IntValue() != 1 {
			t.Errorf("c8s-router should surge (maxSurge=1, maxUnavailable=0), got %+v", ru)
		}
	})

	t.Run("explicit strategy renders verbatim", func(t *testing.T) {
		out, err := helmTemplate(t, "--set-string", "router.strategy.type=RollingUpdate")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		router := renderedDeployment(t, out, "c8s-router")
		if router.Spec.Strategy.Type != appsv1.RollingUpdateDeploymentStrategyType {
			t.Errorf("c8s-router strategy = %q, want the explicit RollingUpdate override", router.Spec.Strategy.Type)
		}
	})
}

// TestChartRouterHostPort covers the router.hostPort edge toggle. The default
// publishes nginx's TLS listener on the node's host port 443 (the in-pod
// listener stays on the unprivileged nginx.httpsPort). hostPort.enabled=false
// omits it so the pod schedules where another controller already owns 443
// (e.g. RKE2's bundled ingress-nginx). A custom host port binds independently
// of the listener port.
func TestChartRouterHostPort(t *testing.T) {
	nginxHTTPSPort := func(t *testing.T, out string) (containerPort, hostPort int32) {
		t.Helper()
		nginx := renderedDeploymentContainer(t, out, "c8s-router", "nginx")
		p, ok := namedContainerPort(nginx, "https")
		if !ok {
			t.Fatal("nginx container has no https port")
		}
		return p.ContainerPort, p.HostPort
	}

	t.Run("default binds host 443", func(t *testing.T) {
		out, err := helmTemplate(t)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cp, hp := nginxHTTPSPort(t, out)
		if cp != 8443 || hp != 443 {
			t.Fatalf("https = containerPort %d / hostPort %d, want 8443 / 443", cp, hp)
		}
	})

	t.Run("disabled omits the host port", func(t *testing.T) {
		out, err := helmTemplate(t, "--set", "router.hostPort.enabled=false")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cp, hp := nginxHTTPSPort(t, out)
		if hp != 0 {
			t.Fatalf("https hostPort = %d, want 0 (unbound)", hp)
		}
		if cp != 8443 {
			t.Fatalf("https containerPort = %d, must stay 8443 with hostPort disabled", cp)
		}
	})

	t.Run("custom host port decouples from the listener port", func(t *testing.T) {
		out, err := helmTemplate(t, "--set", "router.hostPort.https=8443")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cp, hp := nginxHTTPSPort(t, out)
		if cp != 8443 || hp != 8443 {
			t.Fatalf("https = containerPort %d / hostPort %d, want 8443 / 8443", cp, hp)
		}
	})

	t.Run("string bool is rejected", func(t *testing.T) {
		// A string "false" is truthy in templates and would silently keep the
		// port bound (and the strategy on Recreate) despite the opt-out.
		out, err := helmTemplate(t, "--set-string", "router.hostPort.enabled=false")
		if err == nil {
			t.Fatalf("helm template succeeded, want string-bool rejection\n%s", out)
		}
		assertHelmFailMessage(t, out, "router.hostPort.enabled must be a boolean; do not set it via --set-string, got: false")
	})
}

// TestChartNoTeeProxyRemnants sweeps the default render for any leftover
// tee-proxy wiring after the component's removal.
func TestChartNoTeeProxyRemnants(t *testing.T) {
	for _, tc := range []struct {
		name   string
		render func(t *testing.T, args ...string) (string, error)
	}{
		{"default", helmTemplate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.render(t)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			if strings.Contains(strings.ToLower(out), "tee-proxy") {
				t.Fatalf("render still references tee-proxy\n%s", out)
			}
		})
	}
}

// TestChartRejectsMalformedUpstreamAddress pins the catch-all upstream to the
// same charset guard every routes[].backend.address gets: an address with
// nginx metacharacters must fail the render, not corrupt the config.
func TestChartRejectsMalformedUpstreamAddress(t *testing.T) {
	// Clear the workload baseline and secure the manual upstream (https + verify)
	// so the render reaches the address-format check rather than tripping the
	// workload-conflict / unsecured-upstream guards first.
	out, err := helmTemplate(t, noUpstreamArgs(
		"--set-string", "router.upstream.address=bad addr;{}",
		"--set-string", "router.upstream.protocol=https",
		"--set", "router.upstream.tls.verify=true")...)
	if err == nil {
		t.Fatalf("helm template succeeded, want upstream address rejection\n%s", out)
	}
	assertHelmFailMessage(t, out, "router.upstream.address must be a host:port address without scheme, whitespace, semicolons, braces, slashes, or '#', got: bad addr;{}")
}

// TestChartRejectsLeftoverTeeProxyValues: helm silently ignores values keys
// the chart no longer reads, so a values file carried over from a release
// that still had tee-proxy would drop its settings (e.g. the hostPort
// opt-out) without a trace. The render must fail loud instead.
func TestChartRejectsLeftoverTeeProxyValues(t *testing.T) {
	out, err := helmTemplate(t, "--set", "teeProxy.hostPort.enabled=false")
	if err == nil {
		t.Fatalf("helm template succeeded, want removed_component failure\n%s", out)
	}
	if got := parseValidationErrorKind(out); got != "removed_component" {
		t.Fatalf("validation kind = %q, want removed_component\n%s", got, out)
	}
}

// TestChartGetCertRetriesInProcess proves the injected c8s-cert sidecar retries
// CDS in-process (--initial-retry-timeout) on the bootstrap fetch instead of
// exiting into kubelet CrashLoopBackOff on a transient CDS/mesh outage during
// a roll.
func TestChartGetCertRetriesInProcess(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	inits := renderedDeploymentInitContainers(t, out, "c8s-router")
	var cert *corev1.Container
	for i := range inits {
		if inits[i].Name == "c8s-cert" {
			cert = &inits[i]
		}
	}
	if cert == nil {
		t.Fatalf("router has no c8s-cert init container\n%s", out)
	}
	assertContainerHasArg(t, "c8s-cert", cert.Args, "--initial-retry-timeout=2m")
}

// TestChartCDSMeasurementsPlumbFlatAllowlist proves the flat cds.measurements
// list drives --measurements.
func TestChartCDSMeasurementsPlumbFlatAllowlist(t *testing.T) {
	const measurement = "0011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566ff"
	out, err := helmTemplate(t, "--set", "cds.measurements[0]="+measurement)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	assertContainerHasArg(t, "cds", args, "--measurements="+measurement)
}

// TestChartCDSStrategyIsRecreateSingleton pins the rollout to its constraint:
// two cds pods would mint divergent trust roots and cannot co-mount the RWO
// data PVC, so the pod is replaced, never surged. Replicas stays 1: EAR
// signing keys are per pod, so a second steady-state endpoint breaks EAR
// verification (see the active/active decision memo).
func TestChartCDSStrategyIsRecreateSingleton(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	dep := renderedDeployment(t, out, "c8s-cds")
	if dep.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
		t.Errorf("cds strategy = %q, want Recreate", dep.Spec.Strategy.Type)
	}
	if got := *dep.Spec.Replicas; got != 1 {
		t.Errorf("cds replicas = %d, want the fixed singleton 1", got)
	}
}

func renderedDeployment(t *testing.T, manifest, name string) appsv1.Deployment {
	t.Helper()
	var dep appsv1.Deployment
	if !findDoc(t, manifest, "Deployment", name, &dep) {
		t.Fatalf("rendered manifest missing Deployment %q\n%s", name, manifest)
	}
	return dep
}

func renderedDaemonSet(t *testing.T, manifest, name string) appsv1.DaemonSet {
	t.Helper()
	var ds appsv1.DaemonSet
	if !findDoc(t, manifest, "DaemonSet", name, &ds) {
		t.Fatalf("rendered manifest missing DaemonSet %q\n%s", name, manifest)
	}
	return ds
}

type nriRuntimeConfig struct {
	Allowlist struct {
		Pull struct {
			URL               string   `yaml:"url"`
			Interval          string   `yaml:"interval"`
			Timeout           string   `yaml:"timeout"`
			AttestationApiURL string   `yaml:"attestation_api_url"`
			CDSMeasurements   []string `yaml:"cds_measurements"`
			CDSRTMRs          []string `yaml:"cds_rtmrs"`
		} `yaml:"pull"`
		Push struct {
			PersistPath string `yaml:"persist_path"`
		} `yaml:"push"`
	} `yaml:"allowlist"`
}

func renderedNRIBootConfig(t *testing.T, manifest, daemonSetName string) nriRuntimeConfig {
	t.Helper()
	ds := renderedDaemonSet(t, manifest, daemonSetName)
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	raw := extractHeredoc(t, script, "IMAGE_POLICY_EOF")
	var cfg nriRuntimeConfig
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("decode %s boot config: %v\n%s", daemonSetName, err, raw)
	}
	return cfg
}

func extractHeredoc(t *testing.T, script, marker string) string {
	t.Helper()
	startMarker := "<<'" + marker + "'\n"
	start := strings.Index(script, startMarker)
	if start < 0 {
		t.Fatalf("script missing heredoc start marker %q\n%s", marker, script)
	}
	bodyStart := start + len(startMarker)
	end := strings.Index(script[bodyStart:], "\n"+marker)
	if end < 0 {
		t.Fatalf("script missing heredoc end marker %q\n%s", marker, script)
	}
	return script[bodyStart : bodyStart+end]
}

func renderedConfigMap(t *testing.T, manifest, name string) corev1.ConfigMap {
	t.Helper()
	var cm corev1.ConfigMap
	if !findDoc(t, manifest, "ConfigMap", name, &cm) {
		t.Fatalf("rendered manifest missing ConfigMap %q\n%s", name, manifest)
	}
	return cm
}

func renderedService(t *testing.T, manifest, name string) corev1.Service {
	t.Helper()
	var svc corev1.Service
	if !findDoc(t, manifest, "Service", name, &svc) {
		t.Fatalf("rendered manifest missing Service %q\n%s", name, manifest)
	}
	return svc
}

func renderedDaemonSetContainer(t *testing.T, manifest, daemonSetName, containerName string) corev1.Container {
	t.Helper()
	for _, container := range renderedDaemonSet(t, manifest, daemonSetName).Spec.Template.Spec.Containers {
		if container.Name == containerName {
			return container
		}
	}
	t.Fatalf("rendered DaemonSet %q missing container %q\n%s", daemonSetName, containerName, manifest)
	return corev1.Container{}
}

func renderedDeploymentInitContainers(t *testing.T, manifest, name string) []corev1.Container {
	t.Helper()
	return renderedDeployment(t, manifest, name).Spec.Template.Spec.InitContainers
}

func renderedDeploymentContainer(t *testing.T, manifest, deploymentName, containerName string) corev1.Container {
	t.Helper()
	for _, container := range renderedDeployment(t, manifest, deploymentName).Spec.Template.Spec.Containers {
		if container.Name == containerName {
			return container
		}
	}
	t.Fatalf("rendered Deployment %q missing container %q\n%s", deploymentName, containerName, manifest)
	return corev1.Container{}
}

// helmTemplateRouter renders the router component from the parent c8s chart in
// isolation: siblings are disabled and every caller-supplied --set/--set-string
// path is prefixed with router. so the existing subchart-relative test values
// (upstream.*, routes[*], nginx.*) keep working after the hoist. The release is
// named "c8s" so router.fullname resolves to c8s-router, matching the resource
// names the parent-chart router tests already assert. upstream.address is
// pinned to the standalone subchart's old default (vllm:8000) so the
// default-backend assertions remain a meaningful fixture rather than the
// parent's default upstream wiring.
func helmTemplateRouter(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm CLI not found")
	}
	base := []string{
		"template", "c8s", "c8s",
		"--kube-version", "1.30.0",
		"--namespace", "c8s-system",
		"--set", "image.tag=dev",
		"--set", "attestationApi.image.tag=dev",
		"--set", "cds.image.tag=dev",
		"--set", "ratlsMesh.enabled=false",
		// nri-image-policy is enabled in this render
		// (require_host_image_policy); pin its digest so the render is valid
		// (the seed admits it argv-pinned). Output is scoped to the router
		// templates below, so its manifests do not appear here.
		"--set", "nriImagePolicy.image.tag=dev",
		"--set", "cds.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000001",
		"--set", "nriImagePolicy.image.digest=" + baseNRIDigest,
		"--set-string", "router.upstream.address=vllm:8000",
		// Secured (https + verify) upstream baseline for the router subchart
		// tests, on a bare vllm address. A manual address must be app-TLS now
		// that no default ships and there is no unmeshed acknowledgment; tests
		// that exercise a specific upstream protocol override it.
		"--set", "router.upstream.protocol=https",
		"--set", "router.upstream.tls.verify=true",
		"--set", "router.nginx.image.tag=dev",
		"--show-only", "templates/router-configmap.yaml",
		"--show-only", "templates/router-deployment.yaml",
	}
	cmd := exec.Command("helm", append(base, prefixRouterSetArgs(args)...)...)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// prefixRouterSetArgs rewrites the value path of each --set/--set-string pair to
// live under the parent chart's router key, leaving the value (right of '=')
// untouched.
func prefixRouterSetArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i+1 < len(out); i++ {
		if out[i] != "--set" && out[i] != "--set-string" {
			continue
		}
		out[i+1] = "router." + out[i+1]
		i++
	}
	return out
}

// Example_routerConfig renders the router ConfigMap for a representative route
// set — one plaintext HTTP backend (/allowlist) and one RA-TLS-verified HTTPS
// backend (/tenant/) — and prints the generated nginx.conf. It doubles as a
// golden test of templates/configmap.yaml: a template edit that changes the
// rendered config must be reflected in the Output block, so the full config
// diff surfaces in review. helm is required, as it is for every test in this
// package; without it the render errors and the example fails.
func Example_routerConfig() {
	fmt.Print(renderExampleRouterNginxConf())
	// Output:
	// worker_processes auto;
	// error_log /var/log/nginx/error.log warn;
	// pid /tmp/nginx.pid;
	//
	// events {
	//     worker_connections 1024;
	// }
	//
	// http {
	//     include /etc/nginx/mime.types;
	//     default_type application/octet-stream;
	//
	//     log_format main '$remote_addr - $remote_user [$time_local] "$request" '
	//                     '$status $body_bytes_sent "$http_referer" '
	//                     '"$http_user_agent"';
	//     access_log /var/log/nginx/access.log main;
	//
	//     sendfile on;
	//     keepalive_timeout 65;
	//     upstream route_0 {
	//         server c8s-cds.c8s-system.svc:8443;
	//     }
	//     upstream route_1 {
	//         server tenant-router.c8s-system.svc:8080;
	//     }
	//     upstream catch_all {
	//         server vllm:8000;
	//     }
	//
	//     server {
	//         listen 8443 ssl;
	//         server_name c8s-router.c8s-system.svc;
	//
	//         ssl_certificate     /tls/cert.pem;
	//         ssl_certificate_key /tls/key.pem;
	//
	//         ssl_protocols TLSv1.2 TLSv1.3;
	//         ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;
	//         ssl_prefer_server_ciphers on;
	//         ssl_session_cache shared:SSL:10m;
	//         ssl_session_timeout 1d;
	//
	//         # Headroom for upstream responses with large headers.
	//         proxy_buffer_size 16k;
	//         proxy_buffers 4 16k;
	//         # Route: /allowlist -> https://c8s-cds.c8s-system.svc:8443
	//         location = /allowlist {
	//
	//             proxy_ssl_server_name on;
	//             proxy_ssl_name c8s-cds.c8s-system.svc;
	//             proxy_ssl_verify on;
	//             proxy_ssl_verify_depth 2;
	//             proxy_ssl_trusted_certificate /tls/ca.pem;
	//             proxy_pass https://route_0;
	//             proxy_set_header Host $host;
	//             proxy_set_header X-Real-IP $remote_addr;
	//             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	//             proxy_set_header X-Forwarded-Proto $scheme;
	//         }
	//         # Route: /tenant/ -> https://tenant-router.c8s-system.svc:8080
	//         location /tenant/ {
	//
	//             proxy_ssl_server_name on;
	//             proxy_ssl_name tenant-router.c8s-system.svc;
	//             proxy_ssl_verify on;
	//             proxy_ssl_verify_depth 2;
	//             proxy_ssl_trusted_certificate /tls/ca.pem;
	//             proxy_pass https://route_1;
	//             proxy_set_header Host $host;
	//             proxy_set_header X-Real-IP $remote_addr;
	//             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	//             proxy_set_header X-Forwarded-Proto $scheme;
	//         }
	//         location / {
	//
	//             proxy_ssl_certificate /tls/cert.pem;
	//             proxy_ssl_certificate_key /tls/key.pem;
	//             proxy_ssl_server_name on;
	//             proxy_ssl_name vllm;
	//             proxy_ssl_verify on;
	//             proxy_ssl_verify_depth 2;
	//             proxy_ssl_trusted_certificate /tls/cert.pem;
	//             proxy_pass https://catch_all;
	//             proxy_set_header Host $host;
	//             proxy_set_header X-Real-IP $remote_addr;
	//             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	//             proxy_set_header X-Forwarded-Proto $scheme;
	//             proxy_buffering off;
	//             proxy_http_version 1.1;
	//         }
	//
	//         location /healthz {
	//             access_log off;
	//             return 200 "ok\n";
	//             add_header Content-Type text/plain;
	//         }
	//     }
	// }
}

// containerVolumeMount returns the named volume mount from a container
// (read-only state checked separately by the caller).
func containerVolumeMount(c corev1.Container, name string) (corev1.VolumeMount, bool) {
	for _, m := range c.VolumeMounts {
		if m.Name == name {
			return m, true
		}
	}
	return corev1.VolumeMount{}, false
}

func podVolume(spec corev1.PodSpec, name string) (corev1.Volume, bool) {
	for _, v := range spec.Volumes {
		if v.Name == name {
			return v, true
		}
	}
	return corev1.Volume{}, false
}

// seedEntry finds the seed entry whose single container carries digest.
func seedEntry(seed *pkgallowlist.Allowlist, digest string) (pkgallowlist.Workload, bool) {
	for _, w := range seed.Workloads {
		for _, c := range w.Containers {
			if c.Digest.String() == digest {
				return w, true
			}
		}
	}
	return pkgallowlist.Workload{}, false
}

// seedLabel is the label of the entry admitting digest, or "" when none does.
func seedLabel(seed *pkgallowlist.Allowlist, digest string) string {
	w, _ := seedEntry(seed, digest)
	return w.Label
}

// anyArgvEntryArgs renders one bootstrapAllowlist.workloads entry admitting
// digest under any command, args, and mounts, as `helm --set-string` arguments.
func anyArgvEntryArgs(name, digest, image string) []string {
	p := "nriImagePolicy.bootstrapAllowlist.workloads." + name + "."
	return []string{
		"--set-string", p + "label=" + image,
		"--set-string", p + "containers[0].digest=" + digest,
		"--set-string", p + "containers[0].image=" + image,
		"--set-string", p + "containers[0].command.policy=any",
		"--set-string", p + "containers[0].args.policy=any",
		"--set-string", p + "containers[0].mounts.policy=any",
	}
}

// TestChartSeedsCDSAllowlistFromBootstrapEntries proves a
// bootstrapAllowlist.workloads entry and the CDS image self-entry are rendered
// into CDS's --allowlist-seed ConfigMap, so CDS's served /allowlist is
// non-empty on the first worker pull, and that an entry admitting its digest
// under any argv also reaches every plugin's base allowlist. Decoded with the
// same typed Allowlist shape CDS parses, not substring-matched.
func TestChartSeedsCDSAllowlistFromBootstrapEntries(t *testing.T) {
	const bootDigest = "sha256:abcdef0000000000000000000000000000000000000000000000000000000000"
	out, err := helmTemplate(t, anyArgvEntryArgs("coredns", bootDigest, "ghcr.io/x/coredns:v1")...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
	raw, ok := cm.Data["allowlist-seed.json"]
	if !ok {
		t.Fatalf("seed ConfigMap missing allowlist-seed.json key: %v", cm.Data)
	}

	seed, err := pkgallowlist.ParseJSON([]byte(raw))
	if err != nil {
		t.Fatalf("seed JSON does not parse as a Allowlist (CDS would fail closed): %v\n%s", err, raw)
	}

	w, ok := seed.Workloads["coredns"]
	if !ok {
		t.Fatalf("seed entry coredns missing\nseed: %v", seed.Workloads)
	}
	if w.Label != "ghcr.io/x/coredns:v1" || len(w.InitContainers) != 0 || len(w.Containers) != 1 {
		t.Errorf("seed entry = %#v, want label ghcr.io/x/coredns:v1 with one main container", w)
	}
	if c := w.Containers[0]; c.Digest.String() != bootDigest || c.Image != "ghcr.io/x/coredns:v1" || !c.AnyArgv() {
		t.Errorf("seed container = %#v, want %s under any command and args", c, bootDigest)
	}
	worker := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	if got := baseImages(worker.Allowlist.Base)[bootDigest]; got != "ghcr.io/x/coredns:v1" {
		t.Errorf("base[%s] = %q, want the entry's image\nbase: %v", bootDigest, got, worker.Allowlist.Base.Workloads)
	}
	// The CDS self-entry, derived from cds.image (set by the test harness to
	// digest ...0001); the reference is repository@digest.
	const cdsDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	const cdsRef = "ghcr.io/confidential-dot-ai/cds@" + cdsDigest
	if got := seedLabel(seed, cdsDigest); got != cdsRef {
		t.Errorf("seed CDS self-entry = %q, want %q\nseed: %v", got, cdsRef, seed.Workloads)
	}
	for _, al := range []pkgallowlist.Allowlist{*seed, worker.Allowlist.Base} {
		for _, entry := range al.Workloads {
			for _, c := range entry.Containers {
				if c.Digest.String() == cdsDigest && c.Mounts.Policy != pkgallowlist.PolicyAny {
					t.Errorf("generated CDS mount policy = %+v, want explicit any", c.Mounts)
				}
			}
		}
	}
}

func TestChartBasePreservesOperatorMountConstraints(t *testing.T) {
	cases := []struct {
		name   string
		policy string
		want   pkgallowlist.MountPolicy
	}{
		{"omitted", "", pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyDeny}},
		{"deny", pkgallowlist.PolicyDeny, pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyDeny}},
		{"exact", pkgallowlist.PolicyExact, pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyExact, Rules: []pkgallowlist.MountRule{{Destination: "/cache", Kind: pkgallowlist.MountEmptyDir}}}},
	}
	var args []string
	for i, tc := range cases {
		p := "nriImagePolicy.bootstrapAllowlist.workloads." + tc.name + ".containers[0]."
		args = append(args,
			"--set-string", p+"digest="+fmt.Sprintf("sha256:abcdef%058d", i),
			"--set-string", p+"command.policy=any",
			"--set-string", p+"args.policy=any",
		)
		if tc.policy != "" {
			args = append(args, "--set-string", p+"mounts.policy="+tc.policy)
		}
		if tc.policy == pkgallowlist.PolicyExact {
			args = append(args,
				"--set-string", p+"mounts.rules[0].destination=/cache",
				"--set-string", p+"mounts.rules[0].kind=emptyDir",
			)
		}
	}
	out, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	worker := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	base := baseImages(worker.Allowlist.Base)
	for _, tc := range cases {
		entry, ok := seed.Workloads[tc.name]
		if !ok || len(entry.Containers) != 1 {
			t.Fatalf("operator entry %q missing from served seed", tc.name)
		}
		c := entry.Containers[0]
		if !reflect.DeepEqual(c.Mounts, tc.want) {
			t.Errorf("operator entry %q mount policy = %+v, want %+v", tc.name, c.Mounts, tc.want)
		}
		if _, ok := base[c.Digest.String()]; ok {
			t.Errorf("operator entry %q with constrained mounts entered the boot base", tc.name)
		}
	}
}

// An entry that pins a command line is seed-only: the base allowlist admits
// by digest alone, so it carries only what the seed admits under any command
// and args.
func TestChartBaseSkipsPinnedEntries(t *testing.T) {
	const pinned = "sha256:abcdef0000000000000000000000000000000000000000000000000000000001"
	p := "nriImagePolicy.bootstrapAllowlist.workloads.infer.containers[0]."
	out, err := helmTemplate(t,
		"--set-string", p+"digest="+pinned,
		"--set-string", p+"command.policy=exact",
		"--set-string", p+"command.argv[0]=/bin/vllm",
		"--set-string", p+"args.policy=any",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
	}
	if _, ok := seed.Workloads["infer"]; !ok {
		t.Fatalf("pinned entry missing from the seed: %v", seed.Workloads)
	}
	worker := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	if _, ok := baseImages(worker.Allowlist.Base)[pinned]; ok {
		t.Errorf("a pinned entry's digest reached the base allowlist, where it would be admitted under any argv: %v", worker.Allowlist.Base.Workloads)
	}
}

// The derived name lowercases the digest whatever case the values key used, so
// the chart and pkg/allowlist DigestEntryName agree on it.
func TestChartSeedEntryNameIsCaseInsensitive(t *testing.T) {
	const d = "sha256:ABCDEF0000000000000000000000000000000000000000000000000000000000"
	out, err := helmTemplate(t, "--set-string", "cds.image.digest="+d)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
	}
	if _, ok := seed.Workloads["cds-abcdef000000"]; !ok {
		t.Fatalf("seed entry cds-abcdef000000 missing\nseed: %v", seed.Workloads)
	}
}

// The chart derives entry names with the rule pkg/allowlist DigestEntryName
// pins (TestDigestEntryName): the same inputs must yield the same names, tag
// and digest stripping, the "image" fallback and the 50-byte truncation
// included. Driven through the router nginx image, whose repository the
// operator sets freely.
func TestChartSeedEntryNamesMatchMigration(t *testing.T) {
	const d = "sha256:abcdef0000000000000000000000000000000000000000000000000000000000"
	for _, tc := range []struct{ repository, want string }{
		{"ghcr.io/x/coredns:v1", "coredns"},
		{"registry:5000/team/app", "app"},
		{"busybox", "busybox"},
		{"ghcr.io/x/not a name!", "image"},
		{"ghcr.io/x/" + strings.Repeat("y", 60), strings.Repeat("y", 50)},
	} {
		t.Run(tc.want, func(t *testing.T) {
			out, err := helmTemplate(t,
				"--set-string", "router.nginx.image.repository="+tc.repository,
				"--set-string", "router.nginx.image.digest="+d,
			)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
			seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
			if err != nil {
				t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
			}
			if _, ok := seed.Workloads[tc.want+"-abcdef000000"]; !ok {
				t.Errorf("repository %q: entry %q missing\nseed: %v", tc.repository, tc.want+"-abcdef000000", seed.Workloads)
			}
		})
	}
}

// A bootstrapAllowlist.workloads entry sharing a derived entry's name replaces
// it whole in the seed, so an operator can narrow a component's policy without
// the chart re-widening it; the component stays in the base allowlist regardless.
func TestChartSeedWorkloadsOverrideDerivedEntry(t *testing.T) {
	// The harness pins cds.image.digest to ...0001; its derived entry is
	// cds-000000000000.
	const d = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	p := "nriImagePolicy.bootstrapAllowlist.workloads.cds-000000000000.containers[0]."
	out, err := helmTemplate(t,
		"--set-string", p+"digest="+d,
		"--set-string", p+"command.policy=exact",
		"--set-string", p+"command.argv[0]=/cds",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
	}
	w, ok := seed.Workloads["cds-000000000000"]
	if !ok || len(w.Containers) != 1 {
		t.Fatalf("seed entry = %#v, want one container", w)
	}
	if c := w.Containers[0]; c.Command.Policy != pkgallowlist.PolicyExact || c.Digest.String() != d {
		t.Errorf("operator entry did not win over the derived one: %#v", c)
	}
	if w.Label != "" {
		t.Errorf("derived label leaked into the operator's entry: %q", w.Label)
	}
	worker := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	if _, ok := baseImages(worker.Allowlist.Base)[d]; !ok {
		t.Errorf("narrowing the seed entry dropped CDS from the base allowlist: %v", worker.Allowlist.Base.Workloads)
	}
}

// TestChartDerivesComponentDigestsIntoAllowlist proves that when the c8s
// component images are digest-pinned, each is auto-derived into the NRI
// allowlist seed with a repo@digest reference matching the rendered pod image —
// so a digest-pinned install self-allows the c8s components it deploys.
// nri-image-policy is not in the derive set: the chart seeds it argv-pinned
// (c8s.argvPinnedEntries), which carries the same repo@digest label.
func TestChartDerivesComponentDigestsIntoAllowlist(t *testing.T) {
	const (
		opD  = "sha256:00000000000000000000000000000000000000000000000000000000000000a1"
		asD  = "sha256:00000000000000000000000000000000000000000000000000000000000000a2"
		cdsD = "sha256:00000000000000000000000000000000000000000000000000000000000000a3"
		rmD  = "sha256:00000000000000000000000000000000000000000000000000000000000000a4"
		nriD = "sha256:00000000000000000000000000000000000000000000000000000000000000a5"
	)
	out, err := helmTemplate(t,
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set-string", "image.digest="+opD,
		"--set-string", "attestationApi.image.digest="+asD,
		"--set-string", "cds.image.digest="+cdsD,
		"--set-string", "ratlsMesh.image.digest="+rmD,
		"--set-string", "nriImagePolicy.image.digest="+nriD,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
	}

	// Each derived entry's reference must be repo@digest for the image the chart
	// actually deploys.
	want := map[string]string{
		opD:  "ghcr.io/confidential-dot-ai/c8s-operator@" + opD,
		asD:  "ghcr.io/confidential-dot-ai/attestation-api@" + asD,
		cdsD: "ghcr.io/confidential-dot-ai/cds@" + cdsD,
		rmD:  "ghcr.io/confidential-dot-ai/ratls-mesh@" + rmD,
		nriD: "ghcr.io/confidential-dot-ai/nri-image-policy@" + nriD,
	}
	for digest, ref := range want {
		if got := seedLabel(seed, digest); got != ref {
			t.Errorf("derived entry %s = %q, want %q\nseed: %v", digest, got, ref, seed.Workloads)
		}
	}

	// The same derived base must reach the worker plugin's base,
	// decoded as typed config (not substring-matched). The nri digest is
	// excluded: base is digest-only admission, and the installer is
	// argv-pinned by the seed.
	worker := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	for digest, ref := range want {
		if digest == nriD {
			if _, ok := baseImages(worker.Allowlist.Base)[digest]; ok {
				t.Errorf("worker base carries the nri digest — the argv pin would be bypassed\nfloor: %v", baseImages(worker.Allowlist.Base))
			}
			continue
		}
		if got := baseImages(worker.Allowlist.Base)[digest]; got != ref {
			t.Errorf("worker base[%s] = %q, want %q\nfloor: %v", digest, got, ref, baseImages(worker.Allowlist.Base))
		}
	}
}

// The router nginx image is a chart-deployed non-c8s system image: it is not in
// the tag-locked c8sComponents derive set, so a default install would otherwise
// leave it out of the allowlist and the NRI plugin would reject the router
// nginx container. It must be self-seeded from its pinned digest whenever
// router is enabled — independent of deriveComponents (off here) — and dropped
// when router is disabled.
func TestChartAllowlistsRouterNginxSelfEntry(t *testing.T) {
	const (
		nxDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000b1"
		nxRepo   = "example.test/nginx-unprivileged"
	)
	t.Run("enabled: self-entry present without deriveComponents", func(t *testing.T) {
		out, err := helmTemplate(t,
			"--set-string", "router.nginx.image.repository="+nxRepo,
			"--set-string", "router.nginx.image.digest="+nxDigest,
		)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
		seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
		if err != nil {
			t.Fatalf("seed JSON does not parse: %v", err)
		}
		if got, want := seedLabel(seed, nxDigest), nxRepo+"@"+nxDigest; got != want {
			t.Errorf("router nginx self-entry = %q, want %q\nseed: %v", got, want, seed.Workloads)
		}
	})

	t.Run("disabled: no self-entry", func(t *testing.T) {
		out, err := helmTemplate(t,
			"--set", "router.enabled=false",
			"--set-string", "router.nginx.image.repository="+nxRepo,
			"--set-string", "router.nginx.image.digest="+nxDigest,
		)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
		seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
		if err != nil {
			t.Fatalf("seed JSON does not parse: %v", err)
		}
		if _, ok := seedEntry(seed, nxDigest); ok {
			t.Errorf("router nginx self-entry present with router disabled: %v", seed.Workloads)
		}
	})
}

// volumed runs its own image, so like every other component its digest must be
// derived into the NRI base when it is enabled — otherwise the plugin denies
// the daemon's own container (the failure mode observed in testing). It must be
// absent when volumed is off (the default), so a plain install neither resolves
// nor allowlists an image it does not deploy.
func TestChartDerivesVolumedImageIntoFloor(t *testing.T) {
	const volD = "sha256:00000000000000000000000000000000000000000000000000000000000000d1"

	t.Run("enabled: digest in the base", func(t *testing.T) {
		out, err := helmTemplate(t,
			"--set", "volumed.enabled=true",
			"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
			"--set-string", "volumed.image.digest="+volD,
		)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
		seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
		if err != nil {
			t.Fatalf("seed JSON does not parse: %v", err)
		}
		if _, ok := seedEntry(seed, volD); !ok {
			t.Errorf("volumed digest not derived into the base; the plugin would deny volumed's own image\nseed: %v", seed.Workloads)
		}
	})

	t.Run("disabled: digest absent", func(t *testing.T) {
		out, err := helmTemplate(t,
			"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
			"--set-string", "volumed.image.digest="+volD,
		)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
		seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
		if err != nil {
			t.Fatalf("seed JSON does not parse: %v", err)
		}
		if _, ok := seedEntry(seed, volD); ok {
			t.Errorf("volumed digest derived into the base while volumed is disabled: %v", seed.Workloads)
		}
	})
}

// The volumed image entrypoint is ["/app/c8s", "volumed"], so the DaemonSet's
// args must NOT repeat the subcommand. Shipping it once produced
// `unknown command "volumed" for "c8s volumed"` and a CrashLoopBackOff daemon
// that no chart test caught, because nothing asserted on the invocation. cds
// has the same shape (its image entrypoint carries "cds") and its args start at
// a flag, so this checks the convention rather than one literal.
func TestChartComponentArgsDoNotRepeatTheEntrypointSubcommand(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "volumed.enabled=true",
		"--set-string", "volumed.image.tag=dev",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	for _, tc := range []struct {
		name   string
		args   []string
		forbid string
	}{
		{"volumed", renderedDaemonSetContainer(t, out, "c8s-volumed", "volumed").Args, "volumed"},
		{"cds", renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args, "cds"},
	} {
		if len(tc.args) == 0 {
			t.Errorf("%s: no args rendered", tc.name)
			continue
		}
		if tc.args[0] == tc.forbid {
			t.Errorf("%s: args start with %q, but the image entrypoint already supplies it; the container would run `c8s %s %s ...` and exit",
				tc.name, tc.forbid, tc.forbid, tc.forbid)
		}
		if !strings.HasPrefix(tc.args[0], "-") {
			t.Errorf("%s: first arg %q is not a flag; args must begin where the entrypoint leaves off", tc.name, tc.args[0])
		}
	}
}

// TestChartPinsCDSInBareMetalMode guards the node-as-CVM pin path. The node image
// bakes the plugin with empty cds_measurements, and the chart is the only thing
// that knows this release's pins — so an install that does not carry them into
// the baked config leaves the component deciding which images may run on the
// node willing to take its allowlist from ANY RA-TLS-attested CDS, and its
// sandbox-digests endpoint willing to answer any of them. Regression for a
// bare-metal run that found exactly that (2026-08-26).
func TestChartPinsCDSInBareMetalMode(t *testing.T) {
	const (
		pinM = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
		pinR = "1=bbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aa"
	)
	const pinsImageDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000d1"
	out, err := helmTemplate(t,
		"--set-string", "attestationApi.cvmMode=bare-metal",
		"--set", "attestationApi.enabled=false",
		"--set", "nriImagePolicy.baked=true",
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set-string", "nriImagePolicy.image.digest="+pinsImageDigest,
		"--set-string", "cds.measurements[0]="+pinM,
		"--set-string", "cds.rtmrs[0]="+pinR,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	for _, want := range []string{
		"set-cds-pins",
		"--cds-measurements \"" + pinM + "\"",
		"--cds-rtmrs \"" + pinR + "\"",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("bare-metal-mode installer script missing %q\n%s", want, script)
		}
	}

	// The baked config carries the image base whose RKE2 system digests only
	// the image build resolves, so the installer must patch it, never rewrite
	// it — and must leave the binary and the containerd registration alone.
	for _, forbidden := range []string{"IMAGE_POLICY_EOF", "install_file", "render_nri_toml"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("bare-metal-mode installer script must not run %q — it would replace what the node image measured\n%s", forbidden, script)
		}
	}
	for _, c := range ds.Spec.Template.Spec.InitContainers {
		if c.Name == "containerd-prep" {
			t.Errorf("bare-metal-mode installer renders containerd-prep; the node image owns the containerd NRI registration")
		}
	}

	// The installer image is a chart image, not a baked one, so the node admits
	// it only through the seed CDS serves.
	cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("bare-metal-mode seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
	}
	if got := seedLabel(seed, pinsImageDigest); got != "ghcr.io/confidential-dot-ai/nri-image-policy@"+pinsImageDigest {
		t.Errorf("seed[%s] = %q, want the pins installer image; the baked plugin would deny it", pinsImageDigest, got)
	}
}

// TestChartServesAllowlistSeedInBareMetalMode guards the node-as-CVM seed path: even
// with chart nriImagePolicy disabled, the baked plugin pulls the live allowlist
// from CDS. If the seed is not served, CDS starts empty and every un-baked
// component (operator, ratls-mesh, router's nginx) is denied until an operator
// hand-runs `c8s allowlist add`. The seed ConfigMap must render, be mounted,
// and carry the deployed digests.
func TestChartServesAllowlistSeedInBareMetalMode(t *testing.T) {
	const (
		opD = "sha256:00000000000000000000000000000000000000000000000000000000000000c1"
		rmD = "sha256:00000000000000000000000000000000000000000000000000000000000000c2"
	)
	out, err := helmTemplate(t,
		"--set-string", "attestationApi.cvmMode=bare-metal",
		"--set", "attestationApi.enabled=false",
		"--set", "nriImagePolicy.enabled=false",
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set-string", "image.digest="+opD,
		"--set-string", "ratlsMesh.image.digest="+rmD,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("bare-metal-mode seed JSON does not parse (CDS would start empty): %v\n%s", err, cm.Data["allowlist-seed.json"])
	}
	// The un-baked components denied in the un-seeded case: operator, ratls-mesh,
	// and router's nginx (default digest from values.yaml).
	if got := seedLabel(seed, opD); got != "ghcr.io/confidential-dot-ai/c8s-operator@"+opD {
		t.Errorf("bare-metal-mode seed missing operator entry; got %q\nseed: %v", got, seed.Workloads)
	}
	if got := seedLabel(seed, rmD); got != "ghcr.io/confidential-dot-ai/ratls-mesh@"+rmD {
		t.Errorf("bare-metal-mode seed missing ratls-mesh entry; got %q\nseed: %v", got, seed.Workloads)
	}
	const nginxD = "sha256:c2c3905bda3dc8de80023e19bed0a45745279d26e5586cdee64370c8f9b12348"
	if _, ok := seedEntry(seed, nginxD); !ok {
		t.Errorf("bare-metal-mode seed missing router nginx self-entry\nseed: %v", seed.Workloads)
	}
	// The flag/mount must be present so CDS actually loads the seed.
	cds := renderedDeploymentContainer(t, out, "c8s-cds", "cds")
	if !slices.Contains(cds.Args, "--allowlist-seed=/etc/cds/allowlist-seed.json") {
		t.Errorf("bare-metal-mode CDS missing --allowlist-seed flag; seed rendered but not loaded\nargs: %v", cds.Args)
	}
}

// The nri-image-policy containerd-prep init container (rke2 only) runs busybox,
// which is not a c8sComponent, so it is never in the derive set. The host plugin
// enforces every container node-wide, so unless busybox is self-seeded a
// DaemonSet re-roll self-deadlocks ("image not in allowlist: busybox"). The seed
// admits it argv-pinned (the prep script verbatim) — never by digest alone, in
// neither the seed nor the worker's base — and drops the entry on k8s
// where the init container is not rendered.
func TestChartAllowlistsContainerdPrepOnRke2(t *testing.T) {
	const (
		prepDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000c1"
		prepRepo   = "example.test/busybox"
	)
	t.Run("rke2: argv-pinned entry present", func(t *testing.T) {
		out, err := helmTemplate(t,
			"--set-string", "nriImagePolicy.distro=rke2",
			"--set-string", "nriImagePolicy.containerdPrep.image.repository="+prepRepo,
			"--set-string", "nriImagePolicy.containerdPrep.image.digest="+prepDigest,
		)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		wantRef := prepRepo + "@" + prepDigest

		seed := renderedSeed(t, out)
		if got := seedLabel(seed, prepDigest); got != wantRef {
			t.Errorf("containerd-prep seed entry = %q, want %q\nseed: %v", got, wantRef, seed.Workloads)
		}
		// The entry admits exactly the rendered init container's argv.
		worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
		prep, ok := findContainer(worker.Spec.Template.Spec.InitContainers, "containerd-prep")
		if !ok {
			t.Fatalf("rke2 render missing the containerd-prep initContainer")
		}
		admitArgvs(t, seed, prepDigest, effectiveArgv(prep))

		cfg := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
		if _, ok := baseImages(cfg.Allowlist.Base)[prepDigest]; ok {
			t.Errorf("worker base carries the busybox prep digest — the argv pin would be bypassed\nfloor: %v", baseImages(cfg.Allowlist.Base))
		}
	})

	t.Run("k8s: no self-entry", func(t *testing.T) {
		out, err := helmTemplate(t,
			"--set-string", "nriImagePolicy.distro=k8s",
			"--set-string", "nriImagePolicy.containerdPrep.image.repository="+prepRepo,
			"--set-string", "nriImagePolicy.containerdPrep.image.digest="+prepDigest,
		)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		seed := renderedSeed(t, out)
		if _, ok := seedEntry(seed, prepDigest); ok {
			t.Errorf("containerd-prep self-entry present on k8s (init container not rendered): %v", seed.Workloads)
		}
	})
}

// installerBootConfig is a typed view of the image-policy.yaml the installer
// writes. It mirrors the fields of the plugin's own config
// (internal/cmds/nri-image-policy/config.go, which is unexported) needed by the
// chart tests, so assertions are against typed fields rather than substrings.
type installerBootConfig struct {
	Allowlist struct {
		Base pkgallowlist.Allowlist `yaml:"base"`
		Pull struct {
			URL string `yaml:"url"`
		} `yaml:"pull"`
		Push struct {
			PersistPath string `yaml:"persist_path"`
		} `yaml:"push"`
	} `yaml:"allowlist"`
	Policy struct {
		Mode               string   `yaml:"mode"`
		ExemptNamespaces   []string `yaml:"exempt_namespaces"`
		ExemptSnapshotPath string   `yaml:"exempt_snapshot_path"`
	} `yaml:"policy"`
}

// baseImages indexes a boot config's base allowlist by digest: digest ->
// the entry's image reference.
func baseImages(f pkgallowlist.Allowlist) map[string]string {
	out := map[string]string{}
	for _, w := range f.Workloads {
		for _, c := range append(w.InitContainers, w.Containers...) {
			out[c.Digest.String()] = c.Image
		}
	}
	return out
}

// bootConfigHeredocRE captures the image-policy.yaml body the installer writes
// via a `write_file ... <<'IMAGE_POLICY_EOF' ... IMAGE_POLICY_EOF` heredoc.
var bootConfigHeredocRE = regexp.MustCompile(`(?s)<<'IMAGE_POLICY_EOF'\n(.*?)\nIMAGE_POLICY_EOF`)

// bootConfigFromInstaller decodes the image-policy.yaml an installer DaemonSet
// writes into a typed installerBootConfig. It uses gopkg.in/yaml.v3 — the same
// library the plugin's loadConfig uses — which (unlike sigs.k8s.io/yaml's JSON
// path) rejects the duplicate mapping keys that would crash the plugin at
// startup. (KnownFields is intentionally NOT set: the goal is duplicate-key
// detection plus typed field access, not mirroring the plugin's full schema.)
func bootConfigFromInstaller(t *testing.T, manifest, dsName string) installerBootConfig {
	t.Helper()
	ds := renderedDaemonSet(t, manifest, dsName)
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	m := bootConfigHeredocRE.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("install script for %s has no IMAGE_POLICY_EOF heredoc\n%s", dsName, script)
	}
	var cfg installerBootConfig
	if err := yaml.Unmarshal([]byte(m[1]), &cfg); err != nil {
		t.Fatalf("plugin would reject its boot config for %s (yaml.v3): %v\n%s", dsName, err, m[1])
	}
	if err := cfg.Allowlist.Base.Normalize(); err != nil {
		t.Fatalf("boot config base allowlist for %s does not validate the way the plugin's loader would: %v\n%s", dsName, err, m[1])
	}
	return cfg
}

// TestChartBootConfigParsesAsPluginYAML decodes each archetype's boot config
// exactly as the plugin does (yaml.v3 rejects duplicate keys, so a malformed
// render would crash-loop it) and validates the base allowlist the way the
// plugin's loader does, then asserts the archetype-specific mode.
func TestChartBootConfigParsesAsPluginYAML(t *testing.T) {
	out, err := helmTemplate(t,
		// deriveComponents on (and a second component digest) so the installer
		// image reaches the base allowlist both explicitly and via derivation.
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set-string", "cds.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000c5",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// The single installer is pull-mode: it configures a pull URL and never a
	// push block. Asserting both confirms the typed decode landed on the boot
	// config document, not just that some YAML parsed.
	if wl := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist; wl.Pull.URL == "" || wl.Push.PersistPath != "" {
		t.Errorf("worker boot config should configure pull, not push: pull.url=%q push.persist_path=%q", wl.Pull.URL, wl.Push.PersistPath)
	}
}

// By default the rendered worker boot config admits by the digest base alone:
// no exempt_namespaces key. Mirrors the node-image lockstep pin in
// image_policy_template_test.go. The opt-in render is covered below.
func TestChartBootConfigHasNoExemptNamespaces(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	m := bootConfigHeredocRE.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("install script has no IMAGE_POLICY_EOF heredoc\n%s", script)
	}
	if strings.Contains(m[1], "exempt_namespaces") {
		t.Errorf("worker boot config still renders exempt_namespaces:\n%s", m[1])
	}
}

// Setting nriImagePolicy.policy.exemptNamespaces renders the exempt_namespaces
// list, a snapshot path under the cache dir, and the install-time rm that
// re-captures on a boot config rewrite. Decoding through yaml.v3 also proves
// the block does not collide with the rest of the boot config.
func TestChartBootConfigRendersExemptNamespaces(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "nriImagePolicy.policy.exemptNamespaces={kube-system,gatekeeper-system}",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	if got := cfg.Policy.ExemptNamespaces; !slices.Equal(got, []string{"kube-system", "gatekeeper-system"}) {
		t.Errorf("exempt_namespaces = %v, want [kube-system gatekeeper-system]", got)
	}
	if !strings.HasSuffix(cfg.Policy.ExemptSnapshotPath, "/exempt-snapshot.json") {
		t.Errorf("exempt_snapshot_path = %q, want a .../exempt-snapshot.json path", cfg.Policy.ExemptSnapshotPath)
	}

	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	if !strings.Contains(script, "rm -f") || !strings.Contains(script, "exempt-snapshot.json") {
		t.Error("install script must delete the exempt snapshot on a boot config change so it re-captures")
	}
}

// deriveComponents is OFF by default (a demo convenience, like
// --resolve-digests): the seed carries only the CDS base self-entry and
// operator-supplied digests, not the auto-derived component images. Covers both
// the default (unset) and an explicit =false. Rendered in audit mode so the
// deliberately-uncovered operator digest exercises derivation, not the
// fail-closed uncovered_component_digest guard.
func TestChartDeriveComponentsDefaultsOff(t *testing.T) {
	const opD = "sha256:00000000000000000000000000000000000000000000000000000000000000a1"
	const cdsDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"default unset", []string{"--set", "nriImagePolicy.policy.mode=audit", "--set-string", "image.digest=" + opD}},
		{"explicit false", []string{"--set", "nriImagePolicy.policy.mode=audit", "--set-string", "image.digest=" + opD, "--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=false"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
			seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
			if err != nil {
				t.Fatalf("seed JSON does not parse: %v", err)
			}
			if _, ok := seedEntry(seed, opD); ok {
				t.Errorf("operator digest derived without deriveComponents: %v", seed.Workloads)
			}
			// The CDS base self-entry is always present, independent of derivation.
			if _, ok := seedEntry(seed, cdsDigest); !ok {
				t.Errorf("CDS base self-entry missing: %v", seed.Workloads)
			}
		})
	}
}

// TestChartWiresCDSAllowlistSeedFlagAndVolume proves the CDS container receives
// --allowlist-seed pointing at a read-only mount of the seed ConfigMap. The CDS
// pod runs readOnlyRootFilesystem, so the seed must be a read-only volume, not a
// writable path.
func TestChartWiresCDSAllowlistSeedFlagAndVolume(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	cds := renderedDeploymentContainer(t, out, "c8s-cds", "cds")
	assertContainerHasArg(t, "cds", cds.Args, "--allowlist-seed=/etc/cds/allowlist-seed.json")

	mount, ok := containerVolumeMount(cds, "allowlist-seed")
	if !ok {
		t.Fatalf("cds container missing allowlist-seed volume mount; mounts=%v", cds.VolumeMounts)
	}
	if mount.MountPath != "/etc/cds" {
		t.Errorf("allowlist-seed mountPath = %q, want /etc/cds", mount.MountPath)
	}
	if !mount.ReadOnly {
		t.Errorf("allowlist-seed mount must be readOnly (cds has readOnlyRootFilesystem)")
	}

	vol, ok := podVolume(renderedDeployment(t, out, "c8s-cds").Spec.Template.Spec, "allowlist-seed")
	if !ok {
		t.Fatalf("cds pod missing allowlist-seed volume")
	}
	if vol.ConfigMap == nil || vol.ConfigMap.Name != "c8s-cds-allowlist-seed" {
		t.Errorf("allowlist-seed volume should source ConfigMap c8s-cds-allowlist-seed; got %+v", vol.ConfigMap)
	}
}

// The CDS image must be admittable by digest in the base/seed; without
// cds.image.digest the image policy would deny CDS on its own node. The chart
// fails the render with a structured marker rather than shipping that deadlock.
func TestChartRejectsImagePolicyWithoutCDSDigest(t *testing.T) {
	out, err := helmTemplate(t, "--set-string", "cds.image.digest=")
	if err == nil {
		t.Fatalf("helm template succeeded without cds image digest, want guard failure\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "cds_image_digest" {
		t.Fatalf("validation error kind = %q, want cds_image_digest\n%s", kind, out)
	}
}

// In fail-closed mode with deriveComponents off, a digest-pinned component no
// bootstrapAllowlist.workloads entry admits under any argv would be denied on
// its own node, so the chart fails the render. cds.image is exempt (always
// seeded), and nriImagePolicy.image is exempt (seeded argv-pinned) — the cases
// use the operator image, which is neither.
func TestChartRejectsUncoveredComponentInFailClosed(t *testing.T) {
	// A digest distinct from anything the harness pins, so it is genuinely
	// uncovered unless a case below covers it.
	const opD = "sha256:bbbb000000000000000000000000000000000000000000000000000000000000"

	// Uncovered: the operator image is digest-pinned but no entry admits it,
	// deriveComponents off, fail-closed -> guard fires.
	out, err := helmTemplate(t,
		"--set", "nriImagePolicy.policy.mode=fail-closed",
		"--set-string", "image.digest="+opD,
	)
	if err == nil {
		t.Fatalf("helm template succeeded with an uncovered component in fail-closed, want guard failure\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "uncovered_component_digest" {
		t.Fatalf("validation error kind = %q, want uncovered_component_digest\n%s", kind, out)
	}

	// Covered three ways: each must render.
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"audit mode is non-blocking", []string{"--set-string", "image.digest=" + opD, "--set", "nriImagePolicy.policy.mode=audit"}},
		{"deriveComponents covers it", []string{"--set-string", "image.digest=" + opD, "--set", "nriImagePolicy.policy.mode=fail-closed", "--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true"}},
		{"any-argv entry admits it", append([]string{"--set-string", "image.digest=" + opD, "--set", "nriImagePolicy.policy.mode=fail-closed"}, anyArgvEntryArgs("c8s-operator", opD, "ghcr.io/confidential-dot-ai/c8s-operator@"+opD)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if out, err := helmTemplate(t, tc.args...); err != nil {
				t.Fatalf("helm template should render: %v\n%s", err, out)
			}
		})
	}

	// An entry that pins a component's command line is seed-only, so it does
	// not cover the component on its own node and the guard still fires.
	p := "nriImagePolicy.bootstrapAllowlist.workloads.c8s-operator.containers[0]."
	out, err = helmTemplate(t,
		"--set-string", "image.digest="+opD,
		"--set", "nriImagePolicy.policy.mode=fail-closed",
		"--set-string", p+"digest="+opD,
		"--set-string", p+"command.policy=exact",
		"--set-string", p+"command.argv[0]=/c8s",
	)
	if err == nil {
		t.Fatalf("helm template succeeded with the component covered only by a pinned entry\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "uncovered_component_digest" {
		t.Fatalf("validation error kind = %q, want uncovered_component_digest\n%s", kind, out)
	}
}

// The nri-image-policy component is exempt from the uncovered-component guard:
// the chart seeds it argv-pinned (c8s.argvPinnedEntries), so it never needs a
// bootstrapAllowlist.digests entry — and must not get one that holds (a
// same-named workloads entry is the override path).
func TestChartNriComponentCoveredByArgvPin(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "nriImagePolicy.policy.mode=fail-closed",
		"--set-string", "nriImagePolicy.image.digest=sha256:bbbb000000000000000000000000000000000000000000000000000000000000",
	)
	if err != nil {
		t.Fatalf("nri digest without a base entry must render (argv-pinned): %v\n%s", err, out)
	}
}

// golden stays gofmt-clean. Render errors are returned verbatim so the example
// fails loudly rather than masking a broken template.
func renderExampleRouterNginxConf() string {
	cmd := exec.Command("helm",
		"template", "c8s", "c8s",
		"--kube-version", "1.30.0",
		"--namespace", "c8s-system",
		"--set", "image.tag=dev",
		"--set", "attestationApi.image.tag=dev",
		"--set", "cds.image.tag=dev",
		"--set", "ratlsMesh.enabled=false",
		// nri-image-policy is enabled in this render
		// (require_host_image_policy); pin its digest (the seed admits it
		// argv-pinned). The render is scoped to the router ConfigMap, so nri
		// manifests do not appear.
		"--set", "nriImagePolicy.image.tag=dev",
		"--set", "cds.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000001",
		"--set", "nriImagePolicy.image.digest="+baseNRIDigest,
		// discovery defaults to enabled; scope this example to route rendering
		// (discovery's own locations are covered by a dedicated test above).
		"--set", "router.discovery.enabled=false",
		"--set", "router.attest.enabled=false",
		"--set-string", "router.upstream.address=vllm:8000",
		"--set", "router.upstream.protocol=https",
		"--set", "router.upstream.tls.verify=true",
		"--set", "router.nginx.image.tag=dev",
		"--set-string", "router.routes[0].path=/allowlist",
		"--set-string", "router.routes[0].match=exact",
		"--set-string", "router.routes[0].backend.address=c8s-cds.c8s-system.svc:8443",
		"--set-string", "router.routes[0].backend.protocol=https",
		"--set", "router.routes[0].backend.tls.verify=true",
		"--set-string", "router.routes[1].path=/tenant/",
		"--set-string", "router.routes[1].backend.address=tenant-router.c8s-system.svc:8080",
		"--set-string", "router.routes[1].backend.protocol=https",
		"--set", "router.routes[1].backend.tls.verify=true",
		"--show-only", "templates/router-configmap.yaml",
	)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("helm template failed: %v\n%s", err, out)
	}
	var cm corev1.ConfigMap
	if err := sigsyaml.Unmarshal(out, &cm); err != nil {
		return fmt.Sprintf("decode router ConfigMap: %v\n%s", err, out)
	}
	lines := strings.Split(cm.Data["nginx.conf"], "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	return strings.Join(lines, "\n")
}

// --- install-time image pull secret (imagePullSecret, a Secret name) ---

// pullSecretNames flattens an imagePullSecrets list to the referenced names.
func pullSecretNames(refs []corev1.LocalObjectReference) []string {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.Name)
	}
	return names
}

// The invariant the value exists for: every pod the default chart ships can
// authenticate its image pull from first start — either its pod spec lists the
// install-time Secret or its ServiceAccount does (kubelet merges both). And
// the chart must not render a Secret of its own: the named Secret pre-exists
// (kubectl / external-secrets), and helm cannot adopt an object it does not
// own, so rendering one would abort the install.
func TestChartImagePullSecretReachesEveryPodSpecWithoutCreatingASecret(t *testing.T) {
	out, err := helmTemplate(t, "--set-string", "imagePullSecret=ghcr-secret")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	const secretName = "ghcr-secret"

	if kinds := renderedKinds(t, out); kinds["Secret"] > 0 {
		t.Errorf("imagePullSecret mode rendered %d Secret(s), want 0 (the Secret pre-exists)", kinds["Secret"])
	}

	sasWithSecret := map[string]bool{}
	iterateManifests(t, out, func(doc []byte) bool {
		var sa corev1.ServiceAccount
		if err := sigsyaml.Unmarshal(doc, &sa); err != nil || sa.Kind != "ServiceAccount" {
			return false
		}
		if slices.Contains(pullSecretNames(sa.ImagePullSecrets), secretName) {
			sasWithSecret[sa.Name] = true
		}
		return false
	})

	type workload struct {
		kind, name string
		spec       corev1.PodSpec
	}
	var workloads []workload
	iterateManifests(t, out, func(doc []byte) bool {
		var obj struct {
			docMeta
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := sigsyaml.Unmarshal(doc, &obj); err != nil {
			return false
		}
		switch obj.Kind {
		case "Deployment", "DaemonSet", "Job":
			workloads = append(workloads, workload{obj.Kind, obj.Metadata.Name, obj.Spec.Template.Spec})
		}
		return false
	})
	// The default render ships at least operator, cds, and router Deployments
	// plus the attestation-api, ratls-mesh, and nri-image-policy DaemonSets;
	// fewer means the decode regressed and the loop below passes vacuously.
	if len(workloads) < 6 {
		t.Fatalf("decoded only %d pod-bearing workloads, want >= 6", len(workloads))
	}

	for _, w := range workloads {
		if slices.Contains(pullSecretNames(w.spec.ImagePullSecrets), secretName) {
			continue
		}
		if sasWithSecret[w.spec.ServiceAccountName] {
			continue
		}
		t.Errorf("%s %q can't reach the pull secret: pod spec lists %v, serviceAccount %q",
			w.kind, w.name, pullSecretNames(w.spec.ImagePullSecrets), w.spec.ServiceAccountName)
	}
}

// A component-local imagePullSecrets override replaces the chart-wide list but
// must NOT shed the install-time Secret — otherwise adding a credential for an
// extra registry would silently break pulling the component's own image.
func TestChartImagePullSecretAppendsToComponentLocalOverride(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "imagePullSecret=ghcr-secret",
		"--set", "router.imagePullSecrets[0].name=extra")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var names []string
	iterateManifests(t, out, func(doc []byte) bool {
		var obj struct {
			docMeta
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := sigsyaml.Unmarshal(doc, &obj); err != nil || obj.Kind != "Deployment" || obj.Metadata.Name != "c8s-router" {
			return false
		}
		names = pullSecretNames(obj.Spec.Template.Spec.ImagePullSecrets)
		return true
	})
	for _, want := range []string{"extra", "ghcr-secret"} {
		if !slices.Contains(names, want) {
			t.Errorf("router imagePullSecrets = %v, missing %q", names, want)
		}
	}
}

// An operator who also lists the install-time Secret explicitly in the
// chart-wide imagePullSecrets must not get a duplicate entry.
func TestChartImagePullSecretDedupsExplicitReference(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "imagePullSecret=ghcr-secret",
		"--set", "imagePullSecrets[0].name=ghcr-secret")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := findRATLSMeshDaemonSet(t, out)
	names := pullSecretNames(ds.Spec.Template.Spec.ImagePullSecrets)
	want := []string{"ghcr-secret"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("ratls-mesh imagePullSecrets = %v, want %v (no duplicate)", names, want)
	}
}

// Without imagePullSecret (and with the imagePullSecrets lists empty), no
// manifest may carry an imagePullSecrets block at all — the with-guard in the
// c8s.imagePullSecrets helper must keep suppressing empty lists.
func TestChartDefaultRendersNoPullSecretRefs(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	iterateManifests(t, out, func(doc []byte) bool {
		var raw map[string]any
		if err := yaml.Unmarshal(doc, &raw); err != nil {
			t.Fatalf("decode manifest: %v", err)
		}
		if path := findKey(raw, "imagePullSecrets"); path != "" {
			var meta docMeta
			_ = sigsyaml.Unmarshal(doc, &meta)
			t.Errorf("default render carries an imagePullSecrets block: %s %s at %s", meta.Kind, meta.Metadata.Name, path)
		}
		return false
	})
}

// routerUpstreamAddress returns the catch-all upstream address from the
// rendered router nginx config: the `upstream catch_all` block's server for a
// static dial, or the `set $backend_addr <addr>;` directive for the
// mesh-wrapped shape that is re-resolved per request.
func routerUpstreamAddress(t *testing.T, manifest string) string {
	t.Helper()
	cfg := renderedRouterNginxConfig(t, manifest)
	if block, ok := cfg.upstreams["catch_all"]; ok {
		servers := block.directives["server"]
		if len(servers) != 1 || len(servers[0]) != 1 {
			t.Fatalf("upstream catch_all must carry exactly one server; got %v", servers)
		}
		return servers[0][0]
	}
	sets := cfg.location(t, "prefix", "/").directives["set"]
	for _, args := range sets {
		if len(args) == 2 && args[0] == "$backend_addr" {
			return args[1]
		}
	}
	t.Fatalf("catch-all has neither an `upstream catch_all` block nor a `set $backend_addr <addr>;` directive; got %v", sets)
	return ""
}

// TestChartRouterUpstreamChoice: there is no default upstream. An unset upstream
// is a legal install-then-attach state (router serves with no catch-all); when
// an upstream IS set that is not a c8s-<id> headless Service it must be https
// with tls.verify=true (app-TLS) — a plaintext http address or unverified https
// fails instead of shipping a silently-plaintext hop.
func TestChartRouterUpstreamChoice(t *testing.T) {
	// No upstream renders a healthy front door with NO catch-all: the operator
	// attaches a workload later via --upstream. The cert, discovery, and
	// /healthz still render; only location / is withheld.
	t.Run("no-upstream-renders-without-catch-all", func(t *testing.T) {
		out, err := helmTemplate(t, noUpstreamArgs()...)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cfg := renderedRouterNginxConfig(t, out)
		if _, ok := cfg.locations[nginxLocationKey{match: "prefix", path: "/"}]; ok {
			t.Fatalf("no upstream should render no catch-all location /, but one is present\n%s", out)
		}
		// The front door is still healthy and serving.
		cfg.location(t, "prefix", "/healthz")
	})

	// An https upstream with tls.verify (verify defaults to true) terminates and
	// authenticates TLS itself: that hop is app-TLS, the only manual-address
	// shape the guard admits, and the address passes through verbatim.
	t.Run("verified-https-upstream-passes-verbatim", func(t *testing.T) {
		out, err := helmTemplate(t, noUpstreamArgs(
			"--set-string", "router.upstream.address=my-backend.other-ns.svc:8443",
			"--set", "router.upstream.protocol=https")...)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		if got, want := routerUpstreamAddress(t, out), "my-backend.other-ns.svc:8443"; got != want {
			t.Fatalf("upstream = %q, want %q", got, want)
		}
	})

	// A disabled router needs no upstream, and a leftover upstream (e.g. a
	// migration that flips router.enabled=false without clearing the value)
	// must not trip the secured-backend check: the unmeshed-hop risk cannot
	// occur when router renders nothing.
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"router-disabled-needs-no-upstream", noUpstreamArgs("--set", "router.enabled=false")},
		{"router-disabled-ignores-leftover-upstream", noUpstreamArgs(
			"--set", "router.enabled=false",
			"--set-string", "router.upstream.address=my-router.ns.svc:9000")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			// The render must not just succeed: a disabled router must emit no
			// Deployment, so no upstream (leftover or otherwise) can ship.
			if renderedManifestHasNamedKind(t, out, "Deployment", "c8s-router") {
				t.Fatalf("router.enabled=false still rendered a c8s-router Deployment\n%s", out)
			}
		})
	}
}

func TestChartUpstreamValidation(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		kind string
	}{
		{
			// A c8s-<id> headless-Service address is recognized as mesh-wrapped
			// (plaintext http, the mesh secures it), so https can only fail at runtime.
			name: "mesh-wrapped-https",
			args: []string{
				"--set-string", "router.upstream.address=c8s-infer.c8s-system.svc.cluster.local:8000",
				"--set", "router.upstream.protocol=https",
			},
			kind: "workload_https_upstream",
		},
		{
			// A plaintext http manual upstream cannot render: there is no
			// acknowledgment, only https + verify is admitted.
			name: "http-upstream",
			args: noUpstreamArgs("--set-string", "router.upstream.address=my-router.ns.svc:9000"),
			kind: "router_unsecured_upstream",
		},
		{
			// https alone does not secure the hop: verify=false is an
			// encrypted-but-unauthenticated backend, rejected like http.
			name: "unverified-https-upstream",
			args: noUpstreamArgs(
				"--set-string", "router.upstream.address=my-router.ns.svc:8443",
				"--set", "router.upstream.protocol=https",
				"--set", "router.upstream.tls.verify=false"),
			kind: "router_unsecured_upstream",
		},
		{
			// A near-miss of the c8s-<id>.<ns>.svc.cluster.local shape (here the
			// short .svc form) is NOT recognized as mesh-wrapped, so plaintext
			// http fails closed: only the exact headless-Service FQDN gets the
			// plaintext pass. Guards the shape regex against being too loose.
			name: "c8s-shape-short-svc-not-meshwrapped",
			args: noUpstreamArgs("--set-string", "router.upstream.address=c8s-infer.vllm.svc:8000"),
			kind: "router_unsecured_upstream",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, err := helmTemplate(t, tt.args...)
			if err == nil {
				t.Fatalf("helm template succeeded, want %s failure\n%s", tt.kind, out)
			}
			if got := parseValidationErrorKind(out); got != tt.kind {
				t.Fatalf("validation kind = %q, want %q\n%s", got, tt.kind, out)
			}
		})
	}
}

// TestChartRouterUpstreamDefaultEmpty guards the no-default-upstream invariant:
// a shipped default would silently render a catch-all and could put the
// inference hop back on an unmeshed Service VIP. Empty keeps the front door
// catch-all-free until an upstream is deliberately wired.
func TestChartRouterUpstreamDefaultEmpty(t *testing.T) {
	data, err := os.ReadFile("c8s/values.yaml")
	if err != nil {
		t.Fatalf("read values.yaml: %v", err)
	}
	var values struct {
		Router struct {
			Upstream struct {
				Address string `yaml:"address"`
			} `yaml:"upstream"`
		} `yaml:"router"`
	}
	if err := yaml.Unmarshal(data, &values); err != nil {
		t.Fatalf("unmarshal values.yaml: %v", err)
	}
	if values.Router.Upstream.Address != "" {
		t.Fatalf("router.upstream.address default = %q, want empty: a shipped default silently renders a catch-all and can leave the hop unmeshed", values.Router.Upstream.Address)
	}
}

// TestCDSPodDisruptionBudget guards the singleton trust root: the PDB must
// default to maxUnavailable: 0 (block voluntary drains so the in-memory CA is
// not silently evicted) and its selector must actually match the CDS
// Deployment's pods, not select nothing.
func TestCDSPodDisruptionBudget(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	var pdb policyv1.PodDisruptionBudget
	if !findDoc(t, out, "PodDisruptionBudget", "c8s-cds", &pdb) {
		t.Fatalf("rendered manifest missing CDS PodDisruptionBudget\n%s", out)
	}
	if pdb.Spec.MaxUnavailable == nil || pdb.Spec.MaxUnavailable.IntValue() != 0 {
		t.Fatalf("CDS PDB maxUnavailable = %v, want 0 (block voluntary disruption of the singleton trust root)", pdb.Spec.MaxUnavailable)
	}

	// The PDB selector must match the CDS Deployment's pod template labels, or
	// it protects nothing.
	dep := renderedDeployment(t, out, "c8s-cds")
	for k, v := range pdb.Spec.Selector.MatchLabels {
		if got := dep.Spec.Template.Labels[k]; got != v {
			t.Fatalf("CDS PDB selector %s=%q does not match Deployment pod label %q; PDB would select no pods", k, v, got)
		}
	}

	t.Run("maxUnavailable override", func(t *testing.T) {
		out, err := helmTemplate(t, "--set", "cds.podDisruptionBudget.maxUnavailable=1")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		var pdb policyv1.PodDisruptionBudget
		if !findDoc(t, out, "PodDisruptionBudget", "c8s-cds", &pdb) {
			t.Fatalf("rendered manifest missing CDS PodDisruptionBudget\n%s", out)
		}
		if pdb.Spec.MaxUnavailable == nil || pdb.Spec.MaxUnavailable.IntValue() != 1 {
			t.Fatalf("CDS PDB maxUnavailable = %v, want 1", pdb.Spec.MaxUnavailable)
		}
	})

	t.Run("disabled removes the PDB", func(t *testing.T) {
		out, err := helmTemplate(t, "--set", "cds.podDisruptionBudget.enabled=false")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		var pdb policyv1.PodDisruptionBudget
		if findDoc(t, out, "PodDisruptionBudget", "c8s-cds", &pdb) {
			t.Fatal("CDS PodDisruptionBudget rendered while podDisruptionBudget.enabled=false")
		}
	})
}

// TestAttestationApiSeccomp pins the seccomp profile on the attestation-api
// container. It must run privileged (device-cgroup access to the TEE device),
// but seccomp is independent of privileged and RuntimeDefault narrows the
// syscall surface of the node's widest container; it is easy to drop silently.
func TestAttestationApiSeccomp(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-attestation-api")
	c, ok := findContainer(ds.Spec.Template.Spec.Containers, "attestation-api")
	if !ok {
		t.Fatalf("attestation-api container not found; got %v", containerNames(ds.Spec.Template.Spec.Containers))
	}
	sc := c.SecurityContext
	if sc == nil || sc.Privileged == nil || !*sc.Privileged {
		t.Fatalf("attestation-api must be privileged (TEE device access); got %+v", sc)
	}
	if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("attestation-api must set seccompProfile.type: RuntimeDefault; got %+v", sc.SeccompProfile)
	}
}

// The injected secret fetcher verifies CDS before handing it a sandbox token
// and taking a value back, so cds.measurements has to reach the operator that
// renders the fetcher's args. Each hop is unit-tested; this asserts the chart
// end of the chain, which nothing else covers.
func TestChartOperatorCarriesCDSMeasurementsForSecretFetcher(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "cds.measurements[0]=aa11",
		"--set-string", "cds.measurements[1]=bb22",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := strings.Join(renderedDeploymentContainer(t, out, "c8s-operator", "operator").Args, " ")
	for _, want := range []string{"--cds-measurements=aa11", "--cds-measurements=bb22"} {
		if !strings.Contains(args, want) {
			t.Errorf("operator args missing %q; the fetcher would pin no measurement and accept any CDS: %s", want, args)
		}
	}
}

// With no measurements configured the flag is absent rather than empty, so the
// fetcher falls back to its own unpinned warning instead of parsing "".
func TestChartOperatorOmitsCDSMeasurementsWhenUnset(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := strings.Join(renderedDeploymentContainer(t, out, "c8s-operator", "operator").Args, " ")
	if strings.Contains(args, "--cds-measurements") {
		t.Errorf("operator carries --cds-measurements with none configured: %s", args)
	}
}

// volumed is off by default: it runs privileged with hostPID and a writable
// bind of the kubelet directory, and nothing needs it until a workload
// consumes a volume.
func TestChartVolumedOffByDefault(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-volumed") {
		t.Error("volumed DaemonSet rendered without volumed.enabled")
	}
}

// The privileges the daemon cannot work without: hostPID so SO_PEERCRED
// resolves a caller in another pod's namespace to a real PID, privileged plus
// Bidirectional propagation so the mount it makes reaches the workload's pod
// directory, and the device and cgroup trees it reads.
func TestChartVolumedDaemonSetShape(t *testing.T) {
	out, err := helmTemplate(t, "--set", "volumed.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-volumed")
	spec := ds.Spec.Template.Spec

	if !spec.HostPID {
		t.Error("hostPID is off; a peer in another pod's PID namespace resolves to PID 0")
	}
	if spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
		t.Error("volumed mounts an API token it has no use for")
	}

	c, ok := findContainer(spec.Containers, "volumed")
	if !ok {
		t.Fatalf("volumed container missing; have %v", containerNames(spec.Containers))
	}
	// volumed runs its own debian-slim image carrying cryptsetup/veritysetup,
	// NOT the distroless operator image (which has neither, so every open
	// would fail with "executable file not found").
	if !strings.Contains(c.Image, "/volumed") {
		t.Errorf("volumed image = %q, want its own /volumed image (not the operator image)", c.Image)
	}
	if c.SecurityContext == nil || c.SecurityContext.Privileged == nil || !*c.SecurityContext.Privileged {
		t.Error("volumed is not privileged; device-mapper and mount(2) need it")
	}
	// The image is nonroot (USER 65532) and privileged grants no effective
	// caps to a non-root process: without runAsUser 0 the daemon cannot even
	// bind its socket.
	if c.SecurityContext == nil || c.SecurityContext.RunAsUser == nil || *c.SecurityContext.RunAsUser != 0 {
		t.Error("volumed must set runAsUser: 0; the nonroot image user has no effective capabilities")
	}
	// RuntimeDefault seccomp blocks mount(2), so the daemon must not carry one.
	if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
		t.Errorf("seccomp profile %v would block mount(2)", c.SecurityContext.SeccompProfile.Type)
	}

	kubelet, ok := containerVolumeMount(c, "kubelet-root")
	if !ok {
		t.Fatal("no kubelet-root mount; there is nowhere to mount a volume")
	}
	if kubelet.MountPropagation == nil {
		t.Error("kubelet-root sets no mount propagation; the mount would not reach the pod")
	} else if *kubelet.MountPropagation != corev1.MountPropagationBidirectional {
		t.Errorf("kubelet-root propagation = %s, want Bidirectional; the mount would not reach the pod", *kubelet.MountPropagation)
	}
	if kubelet.ReadOnly {
		t.Error("kubelet-root is read-only; the daemon mounts into it")
	}

	for _, name := range []string{"dev", "sys", "cgroup", "inventory-socket-dir"} {
		if _, ok := containerVolumeMount(c, name); !ok {
			t.Errorf("missing %s mount", name)
		}
		if _, ok := podVolume(spec, name); !ok {
			t.Errorf("missing %s volume", name)
		}
	}
	// /sys whole rather than /sys/block: the block entries are symlinks into
	// /sys/devices, and the volume's serial is read through them.
	if v, ok := podVolume(spec, "sys"); ok && (v.HostPath == nil || v.HostPath.Path != "/sys") {
		t.Errorf("sys volume = %+v, want a hostPath of /sys", v.HostPath)
	}
}

// The daemon's socket has to land in the inventory's socket directory — the
// one nri-image-policy NRI-mounts into cw-pod sidecars, which the operator
// names via --workload-claims-host-dir. A daemon serving anywhere else is a
// daemon no confidential pod can reach. And a moved directory must not
// resurface in the VAP: the pod spec carries no hostPath anymore, so a
// carve-out would only reopen tenant access to the node filesystem.
func TestChartVolumedSocketDirTracksTheInventoryDir(t *testing.T) {
	const runtimeDir = "/var/run/c8s-inventory-elsewhere"
	out, err := helmTemplate(t,
		"--set", "volumed.enabled=true",
		"--set-string", "nriImagePolicy.hostPaths.runtimeDir="+runtimeDir,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	c, ok := findContainer(renderedDaemonSet(t, out, "c8s-volumed").Spec.Template.Spec.Containers, "volumed")
	if !ok {
		t.Fatal("volumed container missing")
	}
	if got := argAfter(c.Args, "--socket-dir"); got != runtimeDir {
		t.Errorf("--socket-dir = %q, want the inventory socket dir %q", got, runtimeDir)
	}
	operator := renderedDeploymentContainer(t, out, "c8s-operator", "operator")
	if !slices.Contains(operator.Args, "--workload-claims-host-dir="+runtimeDir) {
		t.Errorf("operator args %v missing --workload-claims-host-dir=%s", operator.Args, runtimeDir)
	}

	var vap admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, out, "ValidatingAdmissionPolicy", "c8s-deny-host-namespaces", &vap) {
		t.Fatal("ValidatingAdmissionPolicy c8s-deny-host-namespaces not rendered")
	}
	for _, v := range vap.Spec.Validations {
		if strings.Contains(v.Expression, strconv.Quote(runtimeDir)) {
			t.Errorf("the VAP names the socket dir %s; hostPath must be denied without carve-outs, expression=%q", runtimeDir, v.Expression)
		}
	}
}

// volumed resolves pod volume directories beneath the kubelet root, so the
// rendered arg, mount, and hostPath must agree, and an explicit value must win.
func TestChartVolumedKubeletRoot(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"default", nil, "/var/lib/kubelet"},
		{"rke2 distro keeps the default", []string{"--set-string", "nriImagePolicy.distro=rke2"}, "/var/lib/kubelet"},
		{"explicit wins", []string{
			"--set-string", "volumed.hostPaths.kubeletRoot=/custom/kubelet",
		}, "/custom/kubelet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"--set", "volumed.enabled=true"}, tc.args...)
			out, err := helmTemplate(t, args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			spec := renderedDaemonSet(t, out, "c8s-volumed").Spec.Template.Spec
			c, ok := findContainer(spec.Containers, "volumed")
			if !ok {
				t.Fatal("volumed container missing")
			}
			if got := argAfter(c.Args, "--kubelet-root"); got != tc.want {
				t.Errorf("--kubelet-root = %q, want %q", got, tc.want)
			}
			mount, ok := containerVolumeMount(c, "kubelet-root")
			if !ok {
				t.Fatal("no kubelet-root mount")
			}
			if mount.MountPath != tc.want {
				t.Errorf("kubelet-root mountPath = %q, want %q", mount.MountPath, tc.want)
			}
			v, ok := podVolume(spec, "kubelet-root")
			if !ok || v.HostPath == nil {
				t.Fatal("no kubelet-root hostPath volume")
			}
			if v.HostPath.Path != tc.want {
				t.Errorf("kubelet-root hostPath = %q, want %q", v.HostPath.Path, tc.want)
			}
			// The teardown hook unmounts under the same root; a divergent
			// path would sweep the wrong tree.
			hook := renderedDaemonSet(t, out, "c8s-volumed-teardown").Spec.Template.Spec
			hc, ok := findContainer(hook.InitContainers, "teardown")
			if !ok {
				t.Fatal("teardown init container missing")
			}
			hm, ok := containerVolumeMount(hc, "kubelet-root")
			if !ok {
				t.Fatal("no kubelet-root mount in the teardown hook")
			}
			if hm.MountPath != tc.want {
				t.Errorf("hook kubelet-root mountPath = %q, want %q", hm.MountPath, tc.want)
			}
			hv, ok := podVolume(hook, "kubelet-root")
			if !ok || hv.HostPath == nil {
				t.Fatal("no kubelet-root hostPath volume in the teardown hook")
			}
			if hv.HostPath.Path != tc.want {
				t.Errorf("hook kubelet-root hostPath = %q, want %q", hv.HostPath.Path, tc.want)
			}
		})
	}
}

// An empty kubeletRoot would render an empty hostPath the apiserver rejects
// long after helm reports success; the chart refuses to render it instead.
func TestChartVolumedKubeletRootMustNotBeEmpty(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "volumed.enabled=true",
		"--set-string", "volumed.hostPaths.kubeletRoot=")
	if err == nil {
		t.Fatal("rendered with an empty volumed.hostPaths.kubeletRoot")
	}
	if !strings.Contains(out, "volumed.hostPaths.kubeletRoot is required") {
		t.Errorf("render error does not name the value: %s", out)
	}
}

// argAfter returns the value following flag in an argv, or "" if absent.
func argAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// The sidecar reaches volumed through the directory the webhook mounts into cw
// pods, which the operator learns from --workload-claims-host-dir. If the two
// templates ever disagree the socket is simply not there, and every
// volume-consuming pod hangs waiting for a mount.
func TestChartVolumedAndWebhookAgreeOnTheSocketDir(t *testing.T) {
	out, err := helmTemplate(t, "--set", "volumed.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	daemon, ok := findContainer(renderedDaemonSet(t, out, "c8s-volumed").Spec.Template.Spec.Containers, "volumed")
	if !ok {
		t.Fatal("volumed container missing")
	}
	socketDir := argAfter(daemon.Args, "--socket-dir")
	if socketDir == "" {
		t.Fatal("volumed has no --socket-dir")
	}

	operator := renderedDeploymentContainer(t, out, "c8s-operator", "operator")
	var hostDir string
	for _, a := range operator.Args {
		if v, ok := strings.CutPrefix(a, "--workload-claims-host-dir="); ok {
			hostDir = v
		}
	}
	if hostDir != socketDir {
		t.Errorf("the operator mounts %q into cw pods but volumed serves in %q", hostDir, socketDir)
	}
}

// The shutdown cleanup must run `iptables-cleanup --keep-guard` so a
// terminating mesh keeps the fail-closed guard while workloads are still
// running. A regression dropping the flag would pass every rule-shape test but
// silently downgrade running workloads to plaintext on restart.
func TestChartDaemonSetShutdownCleanupKeepsGuard(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := findRATLSMeshDaemonSet(t, out)
	var found int
	for _, c := range allContainers(ds) {
		command := strings.Join(c.Command, " ")
		if !strings.Contains(command, "iptables-cleanup") {
			continue
		}
		found++
		for _, want := range []string{"--keep-guard", "--on-shutdown"} {
			if !strings.Contains(command, want) {
				t.Errorf("cleanup command %q does not carry %s", command, want)
			}
		}
	}
	if found == 0 {
		t.Fatal("no iptables-cleanup container found in the ratls-mesh DaemonSet")
	}
}

// The fail-closed egress guards carve out UDP/53 to any destination, so the
// daemonset names no resolver address. A reintroduced --cluster-dns-ip would
// scope the carve-out to one address again and silently drop every cw DNS
// query on a cluster whose resolver sits elsewhere.
func TestChartIptablesSyncNamesNoClusterDNS(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := findRATLSMeshDaemonSet(t, out)
	var flags []string
	for _, c := range allContainers(ds) {
		if c.Name != "iptables-sync" {
			continue
		}
		flags = c.Command
	}
	if len(flags) == 0 {
		t.Fatal("iptables-sync container command not found")
	}
	for _, f := range flags {
		if f == "--cluster-dns-ip" {
			t.Errorf("iptables-sync carries --cluster-dns-ip; the carve-out must name no address: %v", flags)
		}
	}
}

// schemaCoveredPaths are the values subtrees values.schema.json seals: the
// component blocks the docs tell operators to write by hand.
var schemaCoveredPaths = []string{"cds", "nriImagePolicy", "router", "volumed"}

// readChartFile decodes a file from the chart directory. JSON is a subset of
// YAML, so one decoder serves values.yaml and values.schema.json alike.
func readChartFile(t *testing.T, name string, into any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("c8s", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := yaml.Unmarshal(data, into); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

// Helm accepts values a chart never reads, so a misspelled key under a
// documented path is applied, silently dropped at render, and shows up only as
// whatever the un-applied value was protecting against. The schema turns that
// into a render-time error naming the key.
func TestChartValuesSchemaRejectsUnknownKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  string
	}{
		// The singular of the key whose loss bricked a cluster.
		{"nriImagePolicy.policy", "nriImagePolicy.policy.exemptNamespace=kube-system"},
		{"nriImagePolicy top level", "nriImagePolicy.exemptNamespaces=kube-system"},
		{"router.hostPort", "router.hostPort.enable=false"},
		{"cds.persistence", "cds.persistence.enable=true"},
		{"volumed", "volumed.enable=true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, _, _ := strings.Cut(tc.set, "=")
			out, err := helmTemplate(t, "--set", tc.set)
			if err == nil {
				t.Fatalf("helm template accepted the unknown key %s\n%s", key, out)
			}
			// Helm's wording for the same rejection differs by version
			// ("Additional property X is not allowed" vs "additional
			// properties 'X' not allowed"), so match on the shared stem.
			unknown := key[strings.LastIndexByte(key, '.')+1:]
			if !strings.Contains(strings.ToLower(out), "additional propert") || !strings.Contains(out, unknown) {
				t.Errorf("render failure does not name the unknown key %q:\n%s", unknown, out)
			}
		})
	}
}

// The schema is only as good as its coverage: a key added to values.yaml but
// not to the schema makes every render of the chart fail on its own default.
// This is the lockstep guard, checked against the chart's own values.
func TestChartValuesSchemaCoversValuesYAML(t *testing.T) {
	var values map[string]any
	readChartFile(t, "values.yaml", &values)
	var schema struct {
		Properties map[string]any `yaml:"properties"`
	}
	readChartFile(t, "values.schema.json", &schema)

	for _, top := range schemaCoveredPaths {
		node, ok := schema.Properties[top]
		if !ok {
			t.Errorf("values.schema.json does not cover %s", top)
			continue
		}
		assertSchemaCovers(t, values[top], node, top)
	}
}

// assertSchemaCovers walks a values subtree against its schema node: every key
// of a sealed object (one carrying "properties") must be declared, and the
// walk continues into each. A node with no "properties" is deliberately open —
// a label map, a digest map, a resources block — and ends the walk.
func assertSchemaCovers(t *testing.T, values, node any, path string) {
	t.Helper()
	schema, ok := node.(map[string]any)
	if !ok {
		t.Errorf("%s: schema node is not an object (%T)", path, node)
		return
	}
	props, sealed := schema["properties"].(map[string]any)
	if !sealed {
		return
	}
	if blocked, ok := schema["additionalProperties"].(bool); !ok || blocked {
		t.Errorf("%s: declares properties but does not set additionalProperties: false, so a typo still passes", path)
	}
	m, ok := values.(map[string]any)
	if !ok {
		return
	}
	for k, v := range m {
		child, ok := props[k]
		if !ok {
			t.Errorf("values.yaml sets %s.%s but values.schema.json does not declare it; every render would fail", path, k)
			continue
		}
		assertSchemaCovers(t, v, child, path+"."+k)
	}
}

// volumed is the only component that unmaps a pod's dm-crypt/dm-verity stack,
// so deleting the release under an open volume strands the mappings: they hold
// the backing disk and the next install cannot reopen it. The pre-delete hook
// reaps them while the release still exists — for any chart consumer, not just
// `c8s uninstall`.
func TestChartVolumedTeardownHook(t *testing.T) {
	out, err := helmTemplate(t, "--set", "volumed.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-volumed-teardown")

	// pre-delete, so it runs while the mounts are still reachable; helm waits
	// for Ready, which the pause container reaches only once the init
	// container has swept the node.
	if got := ds.Annotations["helm.sh/hook"]; got != "pre-delete" {
		t.Errorf("helm.sh/hook = %q, want pre-delete", got)
	}
	if got := ds.Annotations["helm.sh/hook-delete-policy"]; !strings.Contains(got, "hook-succeeded") {
		t.Errorf("helm.sh/hook-delete-policy = %q, want it to clean up after success", got)
	}
	// The nri-image-policy uninstaller restarts containerd, which would kill
	// this pod mid-sweep, so this hook must sort ahead of it.
	nriWeight := renderedDaemonSet(t, out, "c8s-nri-image-policy-uninstall").Annotations["helm.sh/hook-weight"]
	weight, err := strconv.Atoi(ds.Annotations["helm.sh/hook-weight"])
	if err != nil {
		t.Fatalf("helm.sh/hook-weight is not an int: %v", err)
	}
	if nri, err := strconv.Atoi(nriWeight); err != nil || weight >= nri {
		t.Errorf("teardown hook-weight = %d, want less than the nri uninstaller's %q", weight, nriWeight)
	}

	spec := ds.Spec.Template.Spec
	c, ok := findContainer(spec.InitContainers, "teardown")
	if !ok {
		t.Fatalf("teardown init container missing; have %v", containerNames(spec.InitContainers))
	}
	// cryptsetup/veritysetup live only in volumed's own debian-slim image.
	if !strings.Contains(c.Image, "/volumed") {
		t.Errorf("teardown image = %q, want volumed's own image", c.Image)
	}
	if c.SecurityContext == nil || c.SecurityContext.Privileged == nil || !*c.SecurityContext.Privileged {
		t.Error("teardown is not privileged; closing a dm target and unmounting need it")
	}
	if c.SecurityContext == nil || c.SecurityContext.RunAsUser == nil || *c.SecurityContext.RunAsUser != 0 {
		t.Error("teardown must set runAsUser: 0; the nonroot image user has no effective capabilities")
	}
	// The image entrypoint is ["/app/c8s", "volumed"]; the hook runs a script.
	if len(c.Command) == 0 || c.Command[0] != "/bin/sh" {
		t.Errorf("teardown command = %v, want the shell (the image entrypoint is the daemon)", c.Command)
	}

	// The unmount happens in this pod's namespace and has to propagate back to
	// the host, exactly as volumed's own mount does.
	kubelet, ok := containerVolumeMount(c, "kubelet-root")
	if !ok {
		t.Fatal("no kubelet-root mount; the c8s volume mounts are not reachable")
	}
	if kubelet.MountPropagation == nil || *kubelet.MountPropagation != corev1.MountPropagationBidirectional {
		t.Errorf("kubelet-root propagation = %v, want Bidirectional; the unmount would not reach the host", kubelet.MountPropagation)
	}
	if _, ok := containerVolumeMount(c, "dev"); !ok {
		t.Error("missing dev mount; /dev/mapper is where the mappings live")
	}

	// The script must close both halves of the stack: verity is stacked on the
	// crypt device, and the crypt device is what holds the disk.
	script := strings.Join(c.Args, "\n")
	for _, want := range []string{"c8s-verity-", "c8s-crypt-", "veritysetup", "cryptsetup", "umount"} {
		if !strings.Contains(script, want) {
			t.Errorf("teardown script does not mention %q:\n%s", want, script)
		}
	}
}

// The hook targets the nodes volumed ran on: a node selector or toleration
// that does not track volumed's leaves those nodes' mappings behind.
func TestChartVolumedTeardownHookTracksVolumedPlacement(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "volumed.enabled=true",
		"--set-string", "volumed.nodeSelector.storage=nvme",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	volumed := renderedDaemonSet(t, out, "c8s-volumed").Spec.Template.Spec
	teardown := renderedDaemonSet(t, out, "c8s-volumed-teardown").Spec.Template.Spec
	if !reflect.DeepEqual(volumed.NodeSelector, teardown.NodeSelector) {
		t.Errorf("teardown nodeSelector = %v, want volumed's %v", teardown.NodeSelector, volumed.NodeSelector)
	}
	if !reflect.DeepEqual(volumed.Tolerations, teardown.Tolerations) {
		t.Errorf("teardown tolerations = %v, want volumed's %v", teardown.Tolerations, volumed.Tolerations)
	}
}

// Nothing to reap where the daemon never ran.
func TestChartVolumedTeardownHookOffWithVolumed(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-volumed-teardown") {
		t.Error("volumed teardown hook rendered without volumed.enabled")
	}
}

// A non-default cds.service.nodePort must reach the NRI plugin's pull URL.
// The two used to be independent literals, so moving the port left the plugin
// pulling from 30808 and only validations.yaml's https:// prefix check looking.
func TestChartNRICDSURLFollowsTheNodePort(t *testing.T) {
	out, err := helmTemplate(t, "--set", "cds.service.nodePort=31234")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if want := "https://127.0.0.1:31234"; !strings.Contains(out, want) {
		t.Errorf("render does not carry the derived NRI pull URL %q", want)
	}
	if strings.Contains(out, "https://127.0.0.1:30808") {
		t.Error("render still carries the default NRI pull URL after moving the NodePort")
	}

	// An explicit url still wins; it is the escape hatch for a plugin that
	// should pull from somewhere else entirely.
	out, err = helmTemplate(t, "--set", "cds.service.nodePort=31234",
		"--set-string", "nriImagePolicy.cds.url=https://10.0.0.1:9999")
	if err != nil {
		t.Fatalf("helm template with an explicit url: %v\n%s", err, out)
	}
	if !strings.Contains(out, "https://10.0.0.1:9999") {
		t.Error("an explicit nriImagePolicy.cds.url did not override the derivation")
	}
}

// The derived URL is a node-local NodePort address, so a ClusterIP CDS with no
// nodePort has nothing to derive from and must say so rather than render
// "https://127.0.0.1:0".
func TestChartNRICDSURLRefusesAnUnderivableService(t *testing.T) {
	out, err := helmTemplate(t, "--set-string", "cds.service.type=ClusterIP")
	if err == nil {
		t.Fatalf("helm template succeeded, want an underivable-URL failure\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "nri_cds_url_underivable" {
		t.Errorf("validation kind = %q, want nri_cds_url_underivable", kind)
	}
}

// The node image bakes its own copy of the pull URL into the NRI base, and the
// chart cannot reach it. Keeping the two literals equal in-tree is the half
// that is enforceable here; a per-install -f override still cannot follow (the
// bare-metal-mode baked-config problem).
func TestChartCDSNodePortMatchesTheBakedNRIFloor(t *testing.T) {
	const bakedPath = "../../node-guest-image/c8s/image-policy.yaml.in"
	baked, err := os.ReadFile(bakedPath)
	if err != nil {
		t.Fatalf("read %s: %v", bakedPath, err)
	}
	m := regexp.MustCompile(`(?m)^\s*url:\s*"https://127\.0\.0\.1:(\d+)"`).FindSubmatch(baked)
	if m == nil {
		t.Fatalf("%s carries no loopback CDS pull url", bakedPath)
	}

	var values struct {
		CDS struct {
			Service struct {
				NodePort int `yaml:"nodePort"`
			} `yaml:"service"`
		} `yaml:"cds"`
	}
	readChartFile(t, "values.yaml", &values)

	if got, want := strconv.Itoa(values.CDS.Service.NodePort), string(m[1]); got != want {
		t.Errorf("baked NRI base pulls from :%s but cds.service.nodePort is %s — the node image's plugin would pull from the wrong port (%s)",
			want, got, bakedPath)
	}
}

// The node image bakes the pull interval too, and under nriImagePolicy.baked
// the installer runs set-cds-pins, which rewrites only the CDS pins. So the
// interval a node-CVM's gate actually runs on is the baked one, and a drift
// surfaces only as a policy change that bites later than the chart says.
func TestChartRefreshIntervalMatchesTheBakedNRIPull(t *testing.T) {
	const bakedPath = "../../node-guest-image/c8s/image-policy.yaml.in"
	baked, err := os.ReadFile(bakedPath)
	if err != nil {
		t.Fatalf("read %s: %v", bakedPath, err)
	}
	m := regexp.MustCompile(`(?m)^\s*interval:\s*"([^"]+)"`).FindSubmatch(baked)
	if m == nil {
		t.Fatalf("%s carries no allowlist pull interval", bakedPath)
	}
	want, err := time.ParseDuration(string(m[1]))
	if err != nil {
		t.Fatalf("baked pull interval %q: %v", m[1], err)
	}

	var values struct {
		NRIImagePolicy struct {
			Refresh struct {
				Interval time.Duration `yaml:"interval"`
			} `yaml:"refresh"`
		} `yaml:"nriImagePolicy"`
	}
	readChartFile(t, "values.yaml", &values)

	if got := values.NRIImagePolicy.Refresh.Interval; got != want {
		t.Errorf("baked NRI pull interval is %s but nriImagePolicy.refresh.interval is %s — a tightened entry reaches a node-CVM's gate on the baked value (%s)",
			want, got, bakedPath)
	}
}

// The root key set is closed, so a values file carried over from an older
// release — or one with a typo above the sealed subtrees — is refused instead
// of being silently dropped. This is the class that caused the incident the
// schema was added for; sealing only four subtrees left it open everywhere else.
func TestChartValuesSchemaRejectsUnknownRootKeys(t *testing.T) {
	for _, key := range []string{"webhookk", "clusterName", "nriImagePolicyy"} {
		t.Run(key, func(t *testing.T) {
			out, err := helmTemplate(t, "--set", key+".enabled=true")
			if err == nil {
				t.Fatalf("helm template accepted unknown root key %q\n%s", key, out)
			}
			// Wording differs across helm versions; match the shared stem.
			if lower := strings.ToLower(out); !strings.Contains(lower, "additional propert") ||
				!strings.Contains(lower, strings.ToLower(key)) {
				t.Errorf("failure does not name %q as an unknown key:\n%s", key, out)
			}
		})
	}
}

// teeProxy stays in the schema on purpose: validations.yaml answers it with a
// migration message, which a generic unknown-key refusal would replace.
func TestChartTeeProxyKeepsItsMigrationMessage(t *testing.T) {
	out, err := helmTemplate(t, "--set", "teeProxy.hostPort.enabled=true")
	if err == nil {
		t.Fatalf("helm template accepted teeProxy values\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "removed_component" {
		t.Errorf("validation kind = %q, want removed_component (the schema swallowed it)", kind)
	}
}

// A NodePort outside the service range, a mistyped service type, or a mistyped
// policy mode were all accepted silently: nothing in the chart checked any of
// the three, and the last one only surfaced when the plugin refused its config
// on the node.
func TestChartValuesSchemaConstrainsTheEnumsAndRanges(t *testing.T) {
	for _, tc := range []struct{ name, set string }{
		{"nodePort below the service range", "cds.service.nodePort=8443"},
		{"nodePort above the service range", "cds.service.nodePort=40000"},
		{"unknown service type", "cds.service.type=NodePortt"},
		{"unknown policy mode", "nriImagePolicy.policy.mode=failclosed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if out, err := helmTemplate(t, "--set", tc.set); err == nil {
				t.Fatalf("helm template accepted --set %s\n%s", tc.set, out)
			}
		})
	}

	// The in-range default and the other real mode still render.
	if out, err := helmTemplate(t, "--set", "cds.service.nodePort=31234",
		"--set-string", "nriImagePolicy.policy.mode=audit"); err != nil {
		t.Fatalf("a valid nodePort and mode were refused: %v\n%s", err, out)
	}
}

// Every component that serves a port had no ingress policy at all, so anything
// on the pod network could reach any port they happened to bind — the router
// sidecars bind loopback by intention, not by enforcement. These policies are
// default-deny with the declared ports carved back out.
func TestChartComponentIngressPoliciesAreDefaultDeny(t *testing.T) {
	out, err := helmTemplate(t, "--set", "volumed.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	for _, tc := range []struct {
		policy    string
		component string
		ports     []int32
	}{
		{"c8s-cds-ingress", "cds", []int32{8443}},
		{"c8s-operator-ingress", "operator", []int32{9443, 8081, 8080}},
		{"c8s-volumed-ingress", "volumed", nil},
		{"c8s-router-ingress", "", []int32{8443}},
	} {
		t.Run(tc.policy, func(t *testing.T) {
			var np networkingv1.NetworkPolicy
			if !findDoc(t, out, "NetworkPolicy", tc.policy, &np) {
				t.Fatalf("render is missing NetworkPolicy %q", tc.policy)
			}
			// Ingress only: ratls-mesh's tcp-only-egress selects every pod and
			// allows all TCP, so an egress rule here would be unioned away.
			if len(np.Spec.PolicyTypes) != 1 || np.Spec.PolicyTypes[0] != networkingv1.PolicyTypeIngress {
				t.Errorf("policyTypes = %v, want [Ingress]", np.Spec.PolicyTypes)
			}
			if tc.component != "" && np.Spec.PodSelector.MatchLabels["app.kubernetes.io/component"] != tc.component {
				t.Errorf("podSelector = %v, want component %q", np.Spec.PodSelector.MatchLabels, tc.component)
			}
			if len(np.Spec.PodSelector.MatchLabels) == 0 {
				t.Error("podSelector is empty: this policy would apply to every pod in the namespace")
			}

			var got []int32
			for _, rule := range np.Spec.Ingress {
				if len(rule.From) != 0 {
					t.Errorf("ingress rule restricts source (%v); these policies narrow which port answers, never who connects — router is a public front door, the API server dialling the webhook has no selectable address, and the CDS NodePort route arrives off-cluster", rule.From)
				}
				for _, p := range rule.Ports {
					if p.Port == nil {
						t.Fatalf("ingress rule opens every port on %s", tc.policy)
					}
					got = append(got, int32(p.Port.IntValue()))
				}
			}
			if !slices.Equal(got, tc.ports) {
				t.Errorf("allowed ports = %v, want %v", got, tc.ports)
			}
		})
	}
}

// router is the public front door, so its policy must leave the front-door port
// open to every source. A `from` here would also be unsatisfiable in principle:
// externalTrafficPolicy defaults to Local precisely to preserve arbitrary public
// client IPs, and no selector can enumerate the internet.
func TestChartRouterIngressPolicyStaysReachableFromOffCluster(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	var np networkingv1.NetworkPolicy
	if !findDoc(t, out, "NetworkPolicy", "c8s-router-ingress", &np) {
		t.Fatal("render is missing the router ingress policy")
	}
	if len(np.Spec.Ingress) != 1 {
		t.Fatalf("ingress rules = %d, want 1", len(np.Spec.Ingress))
	}
	if len(np.Spec.Ingress[0].From) != 0 {
		t.Fatalf("the front-door rule names sources (%v); external clients would be refused", np.Spec.Ingress[0].From)
	}

	// The allowed port must be the one the Service and hostPort both target,
	// or external traffic lands on a port the policy does not name.
	var svc corev1.Service
	if !findDoc(t, out, "Service", "c8s-router", &svc) {
		t.Fatal("render is missing the router Service")
	}
	if len(svc.Spec.Ports) != 1 {
		t.Fatalf("router Service exposes %d ports; the policy names one", len(svc.Spec.Ports))
	}
	target := svc.Spec.Ports[0].TargetPort.StrVal

	var deploy appsv1.Deployment
	if !findDoc(t, out, "Deployment", "c8s-router", &deploy) {
		t.Fatal("render is missing the router Deployment")
	}
	var wantPort int32
	for _, c := range deploy.Spec.Template.Spec.Containers {
		for _, p := range c.Ports {
			if p.Name == target {
				wantPort = p.ContainerPort
			}
		}
	}
	if wantPort == 0 {
		t.Fatalf("no containerPort named %q on the router pod", target)
	}
	if got := int32(np.Spec.Ingress[0].Ports[0].Port.IntValue()); got != wantPort {
		t.Errorf("policy admits :%d but the Service targets containerPort :%d — external traffic would be dropped", got, wantPort)
	}
}

// TestChartRTMRPinsFlagThrough confirms cds.rtmrs and ratlsMesh.rtmrs reach
// every consumer the way cds.measurements does: without the fan-out a TDX
// install's RTMR pins would validate in values and enforce nowhere.
func TestChartRTMRPinsFlagThrough(t *testing.T) {
	const (
		measurement = "abc1230000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff"
		rtmr1       = "1=111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
		rtmr2       = "2=222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
	)
	out, err := helmTemplate(t,
		"--set", "cds.measurements[0]="+measurement,
		"--set", "cds.rtmrs[0]="+rtmr1,
		"--set", "cds.rtmrs[1]="+rtmr2,
		"--set", "ratlsMesh.rtmrs[0]="+rtmr1,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	joined := rtmr1 + "," + rtmr2

	cdsArgs := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	assertContainerHasArg(t, "cds", cdsArgs, "--rtmrs="+joined)

	meshArgs := renderedDaemonSetContainer(t, out, "c8s-ratls-mesh", "ratls-mesh").Args
	if i := slices.Index(meshArgs, "--cds-rtmrs"); i < 0 || i+1 >= len(meshArgs) || meshArgs[i+1] != joined {
		t.Fatalf("ratls-mesh missing --cds-rtmrs %q\nargs: %v", joined, meshArgs)
	}
	if i := slices.Index(meshArgs, "--rtmrs"); i < 0 || i+1 >= len(meshArgs) || meshArgs[i+1] != rtmr1 {
		t.Fatalf("ratls-mesh missing --rtmrs %q\nargs: %v", rtmr1, meshArgs)
	}

	operatorArgs := renderedOperatorArgs(t, out)
	assertContainerHasArg(t, "operator", operatorArgs, "--cds-rtmrs="+rtmr1)
	assertContainerHasArg(t, "operator", operatorArgs, "--cds-rtmrs="+rtmr2)

	workerCfg := renderedNRIBootConfig(t, out, "c8s-nri-image-policy-worker")
	if want := []string{rtmr1, rtmr2}; !slices.Equal(workerCfg.Allowlist.Pull.CDSRTMRs, want) {
		t.Fatalf("worker CDS RTMR pins = %v, want %v", workerCfg.Allowlist.Pull.CDSRTMRs, want)
	}

	proxyArgs := renderedDeploymentContainer(t, out, "c8s-router", "allowlist-proxy").Args
	assertContainerHasArg(t, "allowlist-proxy", proxyArgs, "--cds-rtmrs="+joined)
}

// With no rtmrs set nothing renders the flags — the empty default must not
// emit empty pins.
func TestChartNoRTMRPinsRendersNoFlags(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cdsArgs := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	assertContainerNoArgPrefix(t, "cds", cdsArgs, "--rtmrs")
	meshArgs := renderedDaemonSetContainer(t, out, "c8s-ratls-mesh", "ratls-mesh").Args
	if slices.Contains(meshArgs, "--rtmrs") || slices.Contains(meshArgs, "--cds-rtmrs") {
		t.Fatalf("unpinned render emitted RTMR flags\nargs: %v", meshArgs)
	}
}

func TestChartRejectsImagePolicyOffOnManagedNodes(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "attestationApi.cvmMode=gke",
		"--set", "nriImagePolicy.enabled=false",
	)
	if err == nil {
		t.Fatalf("helm template succeeded with nriImagePolicy disabled on a managed-node cluster, want failure\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "require_host_image_policy" {
		t.Fatalf("validation error kind = %q, want require_host_image_policy\n%s", kind, out)
	}
}

func TestChartRejectsAttestationApiOffOnManagedNodes(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "attestationApi.cvmMode=gke",
		"--set", "attestationApi.enabled=false",
	)
	if err == nil {
		t.Fatalf("helm template succeeded with attestationApi disabled on a managed-node cluster, want failure\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "require_attestation_api" {
		t.Fatalf("validation error kind = %q, want require_attestation_api\n%s", kind, out)
	}
}

func TestRouterProbesUseHTTPSHealthChecks(t *testing.T) {
	type namedProbe struct {
		name  string
		probe *corev1.Probe
	}

	base, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, base)
	}
	nginx := renderedDeploymentContainer(t, base, "c8s-router", "nginx")
	for _, p := range []namedProbe{
		{"readiness", nginx.ReadinessProbe},
		{"liveness", nginx.LivenessProbe},
	} {
		if p.probe == nil || p.probe.HTTPGet == nil {
			t.Fatalf("base shape: router %s probe should be httpGet; got %+v", p.name, p.probe)
		}
		if got := p.probe.HTTPGet.Scheme; got != corev1.URISchemeHTTPS {
			t.Errorf("base shape: router %s probe scheme = %q, want HTTPS", p.name, got)
		}
		if got := p.probe.HTTPGet.Path; got != "/healthz" {
			t.Errorf("base shape: router %s probe path = %q, want /healthz", p.name, got)
		}
	}

}

func TestChartSweepMountAdmission(t *testing.T) {
	for _, baked := range []bool{false, true} {
		t.Run(fmt.Sprintf("baked=%v", baked), func(t *testing.T) {
			out, err := helmTemplate(t, "--set", "nriImagePolicy.baked="+strconv.FormatBool(baked))
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
			seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
			if err != nil {
				t.Fatal(err)
			}
			script, err := os.ReadFile("c8s/files/scripts/host-sweep.sh")
			if err != nil {
				t.Fatal(err)
			}
			idx := seed.BuildIndex()
			for _, tc := range []struct {
				name            string
				argv            []string
				hostMount, want bool
			}{
				{"sweep", []string{"/bin/sh", "-c", strings.TrimRight(string(script), "\n") + "\n"}, true, true},
				{"pause", []string{"/bin/sleep", "2147483647"}, false, true},
				{"pause with host mount", []string{"/bin/sleep", "2147483647"}, true, false},
				{"shell pause with host mount", []string{"/bin/sh", "-c", "sleep infinity"}, true, false},
				{"unpinned script", []string{"/bin/sh", "-c", "echo unexpected"}, true, false},
			} {
				mounts := []pkgallowlist.ObservedMount{}
				if tc.hostMount {
					mounts = append(mounts, pkgallowlist.ObservedMount{Source: "/", Destination: "/host", Class: pkgallowlist.MountHost, Storage: pkgallowlist.MountUnknown})
				}
				if got := idx.AdmitsContainer(pkgallowlist.RunningContainer{Digest: baseNRIDigest, Argv: tc.argv, Mounts: mounts}); got != tc.want {
					t.Errorf("%s admitted=%v, want %v", tc.name, got, tc.want)
				}
			}
		})
	}
}

func TestChartRouterPinnedAllowlist(t *testing.T) {
	out, err := helmTemplate(t, noUpstreamArgs(
		"--set", "router.attest.pinnedAllowlist=true",
		"--set-string", "router.upstream.address=my-backend.other-ns.svc:8443",
		"--set", "router.upstream.protocol=https",
	)...)
	if err != nil {
		t.Fatalf("helm template (pinned allowlist): %v\n%s", err, out)
	}
	assertContainerArgs(t, renderedDeploymentContainer(t, out, "c8s-router", "cds-attest"),
		"--cds-state-url=http://127.0.0.1:8801")

	if out, err := helmTemplate(t, noUpstreamArgs(
		"--set", "router.attest.pinnedAllowlist=true",
		"--set-string", "router.upstream.address=c8s-abc.ns.svc.cluster.local:80",
	)...); err == nil || !strings.Contains(out+err.Error(), "router.attest.pinnedAllowlist requires") {
		t.Fatalf("pinned allowlist with an http upstream rendered: %v", err)
	}
}
