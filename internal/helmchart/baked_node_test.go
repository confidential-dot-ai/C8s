package helmchart

import (
	"os"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// bakedArgs is the chart shape `c8s node-image render` produces.
var bakedArgs = []string{
	"--set", "node.baked=true",
	"--set", "attestationApi.cvmMode=bare-metal",
	"--set", "attestationApi.enabled=false",
	"--set", "nriImagePolicy.enabled=false",
	"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
	"--set", "image.digest=sha256:" + strings.Repeat("1", 64),
	"--set", "armtlsMesh.image.digest=sha256:" + strings.Repeat("2", 64),
	"--set", "image.pullPolicy=Never",
	"--set", "cds.image.pullPolicy=Never",
	"--set", "armtlsMesh.image.pullPolicy=Never",
	"--set", "router.nginx.image.pullPolicy=Never",
	"--set", "router.attest.enabled=true",
}

func TestChartBakedNodeLaunchContract(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, bakedArgs...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// CDS alone: the router's clients hold platform roles, so the enforcer
	// mounts the node's policy for them and the chart passes none.
	wantPolicies := map[string]string{"c8s-cds/cds": "peers.json"}
	workloads := renderedPodSpecs(t, out)
	if len(workloads) != 3 {
		t.Fatalf("baked chart should contain operator, CDS and router; got %d workloads", len(workloads))
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
			if container.ImagePullPolicy != corev1.PullNever {
				t.Errorf("%s does not honor the preloaded image pull policy", name)
			}
			if policy, ok := wantPolicies[name]; ok {
				assertContainerHasArg(t, name, container.Args, "--image-policy-file=/run/c8s-node/"+policy)
				mountFound := false
				for _, mount := range container.VolumeMounts {
					if mount.Name == "node-config" {
						mountFound = true
						if mount.MountPath != "/run/c8s-node" || !mount.ReadOnly {
							t.Errorf("%s must mount verified policy read-only", name)
						}
					}
				}
				if !mountFound {
					t.Errorf("%s cannot read its required policy", name)
				}
				delete(wantPolicies, name)
			}
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

	for name, namespace := range map[string]string{"c8s-cds": "c8s-system", "c8s-router": workloadclaims.RouterNamespace} {
		deployment := renderedDeployment(t, out, name)
		if deployment.Namespace != namespace || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
			t.Errorf("%s must be a singleton of %s with Recreate strategy", name, namespace)
		}
		if deployment.Spec.Template.Spec.NodeSelector["node-role.kubernetes.io/control-plane"] != "true" {
			t.Errorf("%s must run on the signed server node", name)
		}
	}
	cds := renderedDeploymentContainer(t, out, "c8s-cds", "cds")
	for _, arg := range []string{
		"--operator-keys=/run/c8s-node/operator-pubkey",
		"--allowlist-seed=/run/c8s-node/allowlist-seed.json",
		"--dns-san-file=/run/c8s-node/tls-san",
	} {
		assertContainerHasArg(t, "cds", cds.Args, arg)
	}
	cert, ok := findContainer(renderedDeploymentInitContainers(t, out, "c8s-router"), "c8s-cert")
	if !ok {
		t.Fatal("router certificate sidecar missing")
	}
	assertContainerHasArg(t, "c8s-cert", cert.Args, "--san-file=/run/c8s-node/tls-san")
	assertContainerNoArgPrefix(t, "c8s-cert", cert.Args, "--san=")
	attest := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	assertContainerHasArg(t, "cds-attest", attest.Args, "--operator-keys-file=/run/c8s-node/operator-pubkey")
	assertContainerNoArgPrefix(t, "cds-attest", attest.Args, "--allow-unpinned-cds")
	if got, want := expectedWorkloadArg(cert), routerEntryName(t, renderedSeed(t, out)); want == "" || got != want {
		t.Errorf("c8s-cert --expected-workload = %q, want the seeded router entry %q", got, want)
	}
	nginx := renderedDeploymentContainer(t, out, "c8s-router", "nginx")
	port, ok := findContainerPort(nginx, "https")
	if !ok || port.ContainerPort != 8443 || port.HostPort != 443 {
		t.Error("router must expose host 443 through unprivileged container port 8443")
	}
	config := renderedConfigMap(t, out, "c8s-router-nginx")
	if config.Namespace != workloadclaims.RouterNamespace || !strings.Contains(config.Data["nginx.conf"], "server_name _;") {
		t.Error("baked router must retain its namespaced nginx config with a default virtual host")
	}
}

func TestChartBakedRouterReadsLaunchFiles(t *testing.T) {
	t.Parallel()
	args := append(slices.Clone(bakedArgs), "--set-string", "nriImagePolicy.distro=rke2")
	out, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	conf := renderedConfigMap(t, out, "c8s-router-nginx").Data["nginx.conf"]
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

	snippets := renderedConfigMap(t, out, "c8s-router-nginx").Data
	for key, want := range map[string]string{
		"tls-cds.conf":  "ssl_certificate     /etc/c8s/certs/tls.crt;\nssl_certificate_key /etc/c8s/certs/tls.key;",
		"tls-acme.conf": "ssl_certificate     /etc/c8s-acme-tls/cert.pem;\nssl_certificate_key /etc/c8s-acme-key/key.pem;",
	} {
		if snippets[key] != want {
			t.Errorf("%s = %q, want %q", key, snippets[key], want)
		}
	}

	deployment := renderedDeployment(t, out, "c8s-router")
	if deployment.Spec.Template.Spec.NodeSelector["node-role.kubernetes.io/control-plane"] != "true" {
		t.Error("the router must run on the server, the only node with launch router inputs")
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
	assertRouterFrontDoorPorts(t, out)

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

func TestChartBakedRouterRejectsChartTLSMode(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, append(slices.Clone(bakedArgs), "--set", "router.publicTLS.mode=acme")...)
	if err == nil || !strings.Contains(out, "node.baked takes the public TLS mode") {
		t.Fatalf("render accepted or failed elsewhere: %v\n%s", err, out)
	}
}

// A baked router runs the ACME sidecar whatever router.publicTLS.mode says.
func TestChartBakedRouterRoutingPortAvoidsACMEPorts(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, append(slices.Clone(bakedArgs), "--set", "router.routing.port=8080")...)
	if err == nil {
		t.Fatalf("helm template succeeded, want the ACME port collision refused\n%s", out)
	}
	assertHelmFailMessage(t, out, "router.routing.port must differ from the ACME HTTP port, got: 8080")
}

// A regular Helm install never reads launch files.
func TestChartRouterDefaultIgnoresLaunchFiles(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, unwanted := range []string{"/run/c8s-node/router", "--domains-file", "--discovery-public-tls-mode-file", "--front-door-mode-file"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("unbaked render contains %q", unwanted)
		}
	}
}

// A measured router must also provide the workload identity that clients pin.
// Image admission alone does not put a matched-workload stamp in its mesh leaf.
func TestChartBakedRouterRequestsWorkloadIdentity(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, bakedArgs...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	pod := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
	cert, ok := findContainer(pod.InitContainers, "c8s-cert")
	if !ok {
		t.Fatal("router certificate sidecar missing")
	}
	if slices.Contains(cert.Args, "--no-workload-claims") {
		t.Fatalf("baked router certificate sidecar opts out of workload claims\nargs: %v", cert.Args)
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
// endpoint and no pins, on a baked node or anywhere else, and names the
// node's own verifier.
func TestChartRouterTakesItsCDSFromTheNode(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "node.baked=true",
		"--set", "attestationApi.cvmMode=bare-metal",
		"--set", "attestationApi.enabled=false",
		"--set", "nriImagePolicy.enabled=false",
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set", "image.digest=sha256:"+strings.Repeat("1", 64),
		"--set", "armtlsMesh.image.digest=sha256:"+strings.Repeat("2", 64),
	)
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
		t.Fatalf("the baked router renders the credential clients %v, want %v", found, want)
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

// On a baked node the mesh's exempt namespaces are measured into the image, so
// the render refuses a release whose injection scope could diverge from them.
func TestChartBakedNodeHoldsInjectionScopeToTheMeasuredExemptSet(t *testing.T) {
	baked := []string{
		"--set", "node.baked=true",
		"--set", "attestationApi.cvmMode=bare-metal",
		"--set", "attestationApi.enabled=false",
		"--set", "nriImagePolicy.enabled=false",
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set", "image.digest=sha256:" + strings.Repeat("1", 64),
		"--set", "armtlsMesh.image.digest=sha256:" + strings.Repeat("2", 64),
	}
	if out, err := helmTemplate(t, baked...); err != nil {
		t.Fatalf("the baked default must render: %v\n%s", err, out)
	}

	for _, tc := range []struct {
		name string
		args []string
		kind string
	}{
		{
			name: "another release namespace",
			args: []string{"--namespace", "tenant-platform"},
			kind: "kind=baked_release_namespace",
		},
		{
			name: "an exclusion only the webhooks know",
			args: []string{"--set", "webhook.extraExcluded={tenant-a}"},
			kind: "kind=baked_webhook_exclusions",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, append(baked, tc.args...)...)
			if err == nil {
				t.Fatalf("the render accepted %s: %s", tc.name, out)
			}
			if !strings.Contains(out, tc.kind) {
				t.Fatalf("render failed for another reason, want %s:\n%s", tc.kind, out)
			}
		})
	}
}

// The measured mesh policy refuses an identity to every sandbox it does not
// protect, so a chart pod that asserts its workload instance through the
// node's inventory must be a mesh member on a baked node: outside the exempt
// namespaces the image measures, with the mesh endpoint as its first
// container. v0.62.0 measured the policy while the router still ran in
// c8s-system, and its c8s-cert was refused on every boot (C8s#1000).
func TestChartBakedCredentialClientsRunInMemberPods(t *testing.T) {
	t.Parallel()
	const bakedPath = "../../node-guest-image/c8s/image-policy.yaml.in"
	body, err := os.ReadFile(bakedPath)
	if err != nil {
		t.Fatalf("read %s: %v", bakedPath, err)
	}
	var measured struct {
		Mesh *struct {
			ExemptNamespaces []string `json:"exempt_namespaces"`
		} `json:"mesh"`
	}
	if err := sigsyaml.Unmarshal(body, &measured); err != nil {
		t.Fatalf("parse %s: %v", bakedPath, err)
	}
	if measured.Mesh == nil {
		t.Fatalf("%s measures no mesh policy", bakedPath)
	}

	out, err := helmTemplate(t, bakedArgs...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	clients := 0
	iterateManifests(t, out, func(doc []byte) bool {
		var obj struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := sigsyaml.Unmarshal(doc, &obj); err != nil {
			return false
		}
		spec := obj.Spec.Template.Spec
		if !slices.ContainsFunc(append(spec.InitContainers, spec.Containers...), func(c corev1.Container) bool {
			return workloadclaims.IsSocketConsumer(c.Name)
		}) {
			return false
		}
		clients++
		name := obj.Kind + "/" + obj.Metadata.Name
		if slices.Contains(measured.Mesh.ExemptNamespaces, obj.Metadata.Namespace) {
			t.Errorf("%s asserts its workload instance from namespace %s, which the measured mesh policy exempts", name, obj.Metadata.Namespace)
		}
		if len(spec.InitContainers) == 0 || spec.InitContainers[0].Name != workloadclaims.MeshContainerName {
			t.Errorf("%s asserts its workload instance but does not start the mesh endpoint first", name)
		}
		return false
	})
	if clients == 0 {
		t.Fatal("the baked chart renders no credential client, so this test checks nothing")
	}
}
