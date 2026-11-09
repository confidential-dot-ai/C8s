package helmchart

import (
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// workerChart is the c8s-worker chart in the repository layout.
const workerChart = "worker"

// workerStockFiles are the worker chart's stock files, one per CPU TEE.
var workerStockFiles = []string{
	"values-sev-snp.yaml",
	"values-tdx.yaml",
}

// workerRenderArgs are the values the worker render commands pass.
var workerRenderArgs = []string{
	"--set-string", "armtlsMesh.image.digest=sha256:" + strings.Repeat("2", 64),
	"--set-string", "clusterDNS=10.53.0.10",
	"--set-string", "image.digest=" + c8sDigest,
}

// helmTemplateWorker renders the worker chart with the SEV-SNP stock file, as
// helmTemplate renders the cloud chart.
func helmTemplateWorker(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return helmTemplateWorkerStock(t, "values-sev-snp.yaml", args...)
}

// helmTemplateWorkerStock renders the worker chart with a stock file and the
// values the worker render commands pass.
func helmTemplateWorkerStock(t *testing.T, stockFile string, args ...string) (string, error) {
	t.Helper()
	base := []string{
		"template", "c8s", workerChart,
		"--kube-version", "1.30.0",
		"--namespace", "c8s-system",
		"--include-crds",
		"-f", workerChart + "/" + stockFile,
	}
	out, err := helmOutput(exec.Command("helm", slices.Concat(base, workerRenderArgs, args)...))
	return string(out), err
}

// chartRender is one chart's render with args: helmTemplate or helmTemplateWorker.
type chartRender struct {
	render func(t *testing.T, args ...string) (string, error)
	args   []string
}

// renderedObjectKeys lists each rendered object as kind/namespace/name.
func renderedObjectKeys(t *testing.T, manifest string) []string {
	t.Helper()
	var keys []string
	for _, doc := range splitManifestDocs(manifest) {
		var meta struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		}
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil {
			t.Fatalf("decode: %v\n%s", err, doc)
		}
		if meta.Kind != "" {
			keys = append(keys, meta.Kind+"/"+meta.Metadata.Namespace+"/"+meta.Metadata.Name)
		}
	}
	slices.Sort(keys)
	return keys
}

// A cluster of workers holds these objects and no other, and the operator's
// grants go to its user alone.
func TestWorkerChartRendersItsObjects(t *testing.T) {
	t.Parallel()
	want := []string{
		"ClusterRole//c8s-operator",
		"ClusterRole//c8s-router",
		"ClusterRole//c8s-worker-cilium",
		"ClusterRole//c8s-worker-cilium-operator",
		"ClusterRoleBinding//c8s-operator",
		"ClusterRoleBinding//c8s-router",
		"ClusterRoleBinding//c8s-worker-bootstrap",
		"ClusterRoleBinding//c8s-worker-bootstrap-client-cert",
		"ClusterRoleBinding//c8s-worker-cilium",
		"ClusterRoleBinding//c8s-worker-cilium-operator",
		"ClusterRoleBinding//c8s-worker-client-cert-renewal",
		"ClusterRoleBinding//c8s-worker-kube-proxy",
		"ConfigMap/c8s-system/c8s-allowlist-seed",
		"CustomResourceDefinition//confidentialworkloads.confidential.ai",
		"Deployment/c8s-router/c8s-router",
		"MutatingWebhookConfiguration//c8s-pod-injector",
		"Namespace//c8s-router",
		"Namespace//c8s-system",
		"NetworkPolicy/c8s-router/c8s-router-ingress",
		"Role/kube-system/c8s-worker-cilium-operator-lease",
		"RoleBinding/kube-system/c8s-worker-cilium-operator-lease",
		"Service/c8s-router/c8s-router",
		"Service/kube-system/kube-dns",
		"ServiceAccount/c8s-router/c8s-router",
		"ValidatingWebhookConfiguration//c8s-pod-validator",
	}
	for _, stockFile := range workerStockFiles {
		out, err := helmTemplateWorkerStock(t, stockFile)
		if err != nil {
			t.Fatalf("helm template %s: %v\n%s", stockFile, err, out)
		}
		if got := renderedObjectKeys(t, out); !slices.Equal(got, want) {
			t.Errorf("%s renders %v, want %v", stockFile, got, want)
		}
		var binding rbacv1.ClusterRoleBinding
		findDoc(t, out, "ClusterRoleBinding", "c8s-operator", &binding)
		operator := rbacv1.Subject{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: "c8s-operator"}
		if !slices.Equal(binding.Subjects, []rbacv1.Subject{operator}) {
			t.Errorf("%s binds the operator's grants to %v, want the user c8s-operator alone", stockFile, binding.Subjects)
		}
	}
}

func TestWorkerChartRouterMatchesSeededEntry(t *testing.T) {
	t.Parallel()
	for _, stockFile := range workerStockFiles {
		out, err := helmTemplateWorkerStock(t, stockFile)
		if err != nil {
			t.Fatalf("helm template %s: %v\n%s", stockFile, err, out)
		}
		assertRouterMatches(t, out)
	}
}

func TestWorkerValuesSchemaCoversValuesYAML(t *testing.T) {
	t.Parallel()
	assertChartSchemaCovers(t, workerChart, []string{
		"armtlsMesh",
		"certProvisioning",
		"controlPlane",
		"image",
		"router",
	})
}

// The worker router reads the verified launch staging and nothing more
// private, and pins its seeded entry.
func TestWorkerChartRouterLaunchContract(t *testing.T) {
	t.Parallel()
	out, err := helmTemplateWorker(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// The CDS every client verifies is the VM the signed launch file names, so
	// the one component argv naming a policy reads it from the staged copy.
	wantPolicies := map[string]string{"c8s-router/cds-attest": "cds.json"}
	workloads := renderedPodSpecs(t, out)
	if len(workloads) != 1 {
		t.Fatalf("the worker chart should contain the router alone; got %d workloads", len(workloads))
	}
	for _, workload := range workloads {
		for _, volume := range workload.spec.Volumes {
			if volume.HostPath != nil && strings.HasPrefix(volume.HostPath.Path, "/run/confos") {
				t.Errorf("%s mounts the token-bearing launch directory", workload.name)
			}
			if volume.Name == "node-config" {
				if volume.HostPath == nil || volume.HostPath.Path != "/run/c8s-node" || volume.HostPath.Type == nil || *volume.HostPath.Type != corev1.HostPathDirectory {
					t.Errorf("%s must require the verified public launch directory", workload.name)
				}
			}
		}
		for _, container := range append(workload.spec.Containers, workload.spec.InitContainers...) {
			name := workload.name + "/" + container.Name
			for _, mount := range container.VolumeMounts {
				if mount.Name == "node-config" && (mount.MountPath != "/run/c8s-node" || !mount.ReadOnly) {
					t.Errorf("%s must mount verified policy read-only", name)
				}
			}
			policy, named := wantPolicies[name]
			if !named {
				continue
			}
			assertContainerHasArg(t, name, container.Args, "--image-policy-file=/run/c8s-node/"+policy)
			if !slices.ContainsFunc(container.VolumeMounts, func(m corev1.VolumeMount) bool { return m.Name == "node-config" }) {
				t.Errorf("%s cannot read its required policy", name)
			}
			delete(wantPolicies, name)
		}
		if workload.name == "c8s-router" {
			if workload.spec.SecurityContext == nil || !slices.Contains(workload.spec.SecurityContext.SupplementalGroups, int64(65532)) {
				t.Errorf("%s cannot connect to the host attestation socket", workload.name)
			}
		}
	}
	if len(wantPolicies) != 0 {
		t.Errorf("missing policy consumers: %v", wantPolicies)
	}
	for name, namespace := range map[string]string{"c8s-router": workloadclaims.RouterNamespace} {
		deployment := renderedDeployment(t, out, name)
		if deployment.Namespace != namespace || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
			t.Errorf("%s must be a singleton of %s with Recreate strategy", name, namespace)
		}
		// The pod runs on any worker, and no worker carries a node role label.
		if selector := deployment.Spec.Template.Spec.NodeSelector; len(selector) > 0 {
			t.Errorf("%s selects nodes by %v", name, selector)
		}
	}
	cert, ok := findContainer(renderedDeploymentInitContainers(t, out, "c8s-router"), "c8s-cert")
	if !ok {
		t.Fatal("router certificate sidecar missing")
	}
	assertContainerHasArg(t, "c8s-cert", cert.Args, "--san-file=/run/c8s-node/tls-san")
	assertContainerNoArgPrefix(t, "c8s-cert", cert.Args, "--san=")
	attest := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	assertContainerHasArg(t, "cds-attest", attest.Args, "--operator-keys-file=/run/c8s-node/operator-pubkey")
	assertContainerHasArg(t, "cds-attest", attest.Args, "--measured-policies-file=/run/nri-image-policy/measured-policies")
	if !slices.ContainsFunc(attest.VolumeMounts, func(m corev1.VolumeMount) bool { return m.MountPath == "/run/nri-image-policy" && m.ReadOnly }) {
		t.Error("cds-attest reads the measured-policy journal without mounting /run/nri-image-policy read-only")
	}
	if got, want := expectedWorkloadArg(cert), routerEntryName(t, renderedSeed(t, out)); want == "" || got != want {
		t.Errorf("c8s-cert --expected-workload = %q, want the seeded router entry %q", got, want)
	}
	nginx := renderedDeploymentContainer(t, out, "c8s-router", "nginx")
	port, ok := findContainerPort(nginx, "https")
	if !ok || port.ContainerPort != 8443 || port.HostPort != 443 {
		t.Error("router must expose host 443 through unprivileged container port 8443")
	}
	if !strings.Contains(libRouterNginxFiles(t)["nginx.conf"], "server_name _;") {
		t.Error("the worker's nginx config must answer as the default virtual host")
	}
}

func TestWorkerChartRouterReadsLaunchFiles(t *testing.T) {
	t.Parallel()
	out, err := helmTemplateWorker(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	snippets := libRouterNginxFiles(t)
	conf := snippets["nginx.conf"]
	for _, want := range []string{
		"server_name _;",
		"include /run/c8s-node/router/tls.conf;",
		"listen 8080;",
		"location /.well-known/acme-challenge/ {",
		"location /.well-known/c8s/ {",
		"location = /allowlist {",
		"location = /v1/discovery {",
		"location = /healthz {",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("nginx.conf lacks %q", want)
		}
	}
	for _, unwanted := range []string{"upstream catch_all", "upstream.conf", "$c8s_upstream", "resolver "} {
		if strings.Contains(conf, unwanted) {
			t.Errorf("launch-driven nginx.conf contains %q; location / must proxy to the routing listener", unwanted)
		}
	}
	if strings.Contains(conf, "ssl_certificate ") {
		t.Error("launch-driven nginx.conf must leave the certificate to tls.conf")
	}
	// The :80 redirect server also has a location /, so pick the routing one
	// by its proxy_pass.
	cfg := parseNginxConfig(t, conf)
	var route *nginxBlock
	for _, block := range cfg.all {
		if slices.ContainsFunc(block.directives["proxy_pass"], func(args []string) bool {
			return slices.Equal(args, []string{"http://127.0.0.1:8802"})
		}) {
			route = block
		}
	}
	if route == nil {
		t.Fatal("launch-driven routing location missing")
	}
	assertRouterWebSocketUpgrade(t, cfg, route)
	assertRouterRoutingLocation(t, route, "8802", "3600s")
	// The signed launch file sets the body limit, not a chart value.
	route.assertDirective(t, "include", "/run/c8s-node/router/request-body.conf")
	route.assertNoDirective(t, "client_max_body_size")

	for key, want := range map[string]string{
		"tls-cds.conf":  "ssl_certificate     /etc/c8s/certs/tls.crt$per_handshake;\nssl_certificate_key /etc/c8s/certs/tls.key$per_handshake;",
		"tls-acme.conf": "ssl_certificate     /etc/c8s-acme-tls/cert.pem$per_handshake;\nssl_certificate_key /etc/c8s-acme-key/key.pem$per_handshake;",
	} {
		if snippets[key] != want {
			t.Errorf("%s = %q, want %q", key, snippets[key], want)
		}
	}

	acme, ok := findContainer(renderedDeploymentInitContainers(t, out, "c8s-router"), "acme")
	if !ok {
		t.Fatal("launch-driven router lacks the acme sidecar")
	}
	for _, arg := range []string{
		"--domains-file=/run/c8s-node/router/hostnames",
		"--acme-email-file=/run/c8s-node/router/acme-email",
		"--acme-directory-url-file=/run/c8s-node/router/acme-directory-url",
		"--standby-cert-dir=/etc/c8s/certs",
	} {
		assertContainerHasArg(t, "acme", acme.Args, arg)
	}
	assertAcmeArgsParse(t, acme.Args)
	assertContainerNoArgPrefix(t, "acme", acme.Args, "--domains=")
	assertContainerMount(t, acme, "node-config", "/run/c8s-node")
	assertContainerMount(t, acme, "c8s-certs", "/etc/c8s/certs")

	// Discovery must report the mode the front door serves, never a
	// build-time cds while the launch file selects acme.
	cert, ok := findContainer(renderedDeploymentInitContainers(t, out, "c8s-router"), "c8s-cert")
	if !ok {
		t.Fatal("router certificate sidecar missing")
	}
	assertContainerHasArg(t, "c8s-cert", cert.Args, "--discovery-public-tls-mode-file=/run/c8s-node/router/front-door-mode")
	assertContainerHasArg(t, "c8s-cert", cert.Args, "--discovery-public-tls-hostnames-file=/run/c8s-node/router/hostnames")
	assertContainerNoArgPrefix(t, "c8s-cert", cert.Args, "--discovery-public-tls-mode=")
	assertContainerMount(t, cert, "node-config", "/run/c8s-node")

	nginx := renderedDeploymentContainer(t, out, "c8s-router", "nginx")
	assertContainerMount(t, nginx, "node-config", "/run/c8s-node")
	snippetDir := false
	for _, m := range nginx.VolumeMounts {
		if m.Name == "nginx-config" && m.MountPath == "/usr/lib/c8s/router-nginx" && m.ReadOnly {
			snippetDir = true
		}
	}
	if !snippetDir {
		t.Error("nginx must mount the TLS snippets read-only at /usr/lib/c8s/router-nginx")
	}
	if port, ok := findContainerPort(nginx, "http"); !ok || port.ContainerPort != 8080 || port.HostPort != 80 {
		t.Error("launch-driven router must publish the ACME challenge port on host 80")
	}
	assertRouterFrontDoorPorts(t, out, conf)

	attest := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	for _, arg := range []string{
		"--front-door-mode-file=/run/c8s-node/router/front-door-mode",
		"--serving-cert-file=/etc/c8s/certs/tls.crt",
		"--acme-serving-cert-file=/etc/c8s-acme-tls/cert.pem",
	} {
		assertContainerHasArg(t, "cds-attest", attest.Args, arg)
	}
	assertContainerNoArgPrefix(t, "cds-attest", attest.Args, "--front-door-mode=")
	assertContainerNoArgPrefix(t, "cds-attest", attest.Args, "--upstream")
	assertContainerMount(t, attest, "node-config", "/run/c8s-node")
}

// A measured router must also provide the workload identity that clients pin.
// Image admission alone does not put a matched-workload stamp in its mesh leaf.
func TestWorkerChartRouterRequestsWorkloadIdentity(t *testing.T) {
	t.Parallel()
	out, err := helmTemplateWorker(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	pod := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
	cert, ok := findContainer(pod.InitContainers, "c8s-cert")
	if !ok {
		t.Fatal("router certificate sidecar missing")
	}
	if slices.Contains(cert.Args, "--no-workload-claims") {
		t.Fatalf("worker router certificate sidecar opts out of workload claims\nargs: %v", cert.Args)
	}
	foundMount := false
	for _, mount := range cert.VolumeMounts {
		if mount.Name == "workload-claims" && mount.MountPath == "/run/c8s/workload-claims" && mount.ReadOnly {
			foundMount = true
		}
	}
	if !foundMount {
		t.Error("router certificate sidecar cannot reach the inventory socket")
	}
	foundVolume := false
	for _, volume := range pod.Volumes {
		if volume.Name == "workload-claims" && volume.HostPath != nil && volume.HostPath.Path == "/run/nri-image-policy" && volume.HostPath.Type != nil && *volume.HostPath.Type == corev1.HostPathDirectory {
			foundVolume = true
		}
	}
	if !foundVolume {
		t.Error("router must require the existing node inventory directory")
	}
	if pod.SecurityContext == nil || !slices.Contains(pod.SecurityContext.SupplementalGroups, int64(65532)) {
		t.Error("router certificate sidecar lacks inventory socket access")
	}
}

// The router's credential clients hold the measured credentials role, so the
// enforcer hands them the node's CDS endpoint, pins and attestation-api, and
// refuses an argument naming another (cmdsutil.ResolveCDSEndpoint,
// cmdsutil.ResolveCDSPins, cmdsutil.RequireNodeVerifier). The chart passes no
// endpoint and no pins and names the node's own verifier.
func TestWorkerChartRouterTakesItsCDSFromTheNode(t *testing.T) {
	out, err := helmTemplateWorker(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	want := []string{"allowlist-proxy", "c8s-cert"}
	var found []string
	for _, workload := range renderedPodSpecs(t, out) {
		if workload.name != "c8s-router" {
			continue
		}
		for _, c := range append(workload.spec.Containers, workload.spec.InitContainers...) {
			if !slices.Contains(want, c.Name) {
				continue
			}
			found = append(found, c.Name)
			assertNoArgWithPrefix(t, "router/"+c.Name, c.Args,
				"--cds-url", "--image-policy-file", "--cds-measurements", "--cds-rtmrs")
			assertContainerHasArg(t, "router/"+c.Name, c.Args,
				"--attestation-api-url=unix://"+workloadclaims.AttestationAPISocket)
		}
	}
	slices.Sort(found)
	if !slices.Equal(found, want) {
		t.Fatalf("the worker router renders the credential clients %v, want %v", found, want)
	}
}

// assertNoArgWithPrefix fails when a container names an argument the node
// hands it instead.
func assertNoArgWithPrefix(t *testing.T, name string, args []string, prefixes ...string) {
	t.Helper()
	for _, arg := range args {
		for _, prefix := range prefixes {
			if strings.HasPrefix(arg, prefix) {
				t.Errorf("%s names its own %s (%s); the node hands it one and refuses this", name, prefix, arg)
			}
		}
	}
}

// nodeCertificateBinding is the group a binding grants and the role it binds,
// of the bindings a kubelet's certificates rest on.
type nodeCertificateBinding struct {
	group string
	role  string
}

// grantsNodeCertificates holds of a binding that lets a node request a
// certificate or have one approved without an admin.
func grantsNodeCertificates(b nodeCertificateBinding) bool {
	return b.group == "system:bootstrappers" ||
		b.role == "system:node-bootstrapper" ||
		strings.HasPrefix(b.role, "system:certificates.k8s.io:")
}

// A worker's kubelet joins with a bootstrap token and rotates the client
// certificate it gets, so the render binds the three grants that carry it, and
// binds nothing else a node's certificates rest on.
func TestWorkerChartKubeletCertificateBindings(t *testing.T) {
	t.Parallel()
	out, err := helmTemplateWorker(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	want := map[string]nodeCertificateBinding{
		"c8s-worker-bootstrap":             {"system:bootstrappers", "system:node-bootstrapper"},
		"c8s-worker-bootstrap-client-cert": {"system:bootstrappers", "system:certificates.k8s.io:certificatesigningrequests:nodeclient"},
		"c8s-worker-client-cert-renewal":   {"system:nodes", "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient"},
	}
	got := map[string]nodeCertificateBinding{}
	for _, doc := range splitManifestDocs(out) {
		var binding rbacv1.ClusterRoleBinding
		if err := sigsyaml.Unmarshal([]byte(doc), &binding); err != nil || binding.Kind != "ClusterRoleBinding" {
			continue
		}
		if len(binding.Subjects) != 1 || binding.Subjects[0].Kind != rbacv1.GroupKind {
			continue
		}
		b := nodeCertificateBinding{binding.Subjects[0].Name, binding.RoleRef.Name}
		if grantsNodeCertificates(b) {
			got[binding.Name] = b
		}
	}
	if !maps.Equal(got, want) {
		t.Errorf("certificate bindings = %v, want %v", got, want)
	}
}

// The workers' kube-dns Service, at clusterDNS, selects the CoreDNS static pod
// on the asking pod's own node.
func TestWorkerChartKubeDNSSelectsTheWorkersCoreDNS(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(workerChart + "/files/static-pods/coredns.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var pod corev1.Pod
	if err := sigsyaml.Unmarshal(data, &pod); err != nil {
		t.Fatal(err)
	}
	out, err := helmTemplateWorker(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var service corev1.Service
	findDoc(t, out, "Service", "kube-dns", &service)
	if len(service.Spec.Selector) == 0 || service.Spec.ClusterIP != "10.53.0.10" {
		t.Fatalf("kube-dns = %+v, want a selector and clusterDNS", service)
	}
	if p := service.Spec.InternalTrafficPolicy; p == nil || *p != corev1.ServiceInternalTrafficPolicyLocal {
		t.Fatalf("kube-dns internalTrafficPolicy = %v, want Local: a lookup leaves its node otherwise", p)
	}
	for k, v := range service.Spec.Selector {
		if pod.Labels[k] != v {
			t.Fatalf("kube-dns selects %v, which the CoreDNS static pod's labels %v do not carry", service.Spec.Selector, pod.Labels)
		}
	}
}
