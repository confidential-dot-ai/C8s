package helmchart

import (
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// bakedArgs is the chart shape `c8s node-image render` produces. A baked
// router reads its upstream from the launch file, so the shape clears the
// mesh-wrapped address helmTemplate pins by default.
var bakedArgs = []string{
	"--set-string", "router.upstream.address=",
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
	out, err := helmTemplate(t, bakedArgs...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	wantPolicies := map[string]string{
		"c8s-cds/cds":                 "peers.json",
		"c8s-operator/operator":       "cds.json",
		"c8s-router/c8s-cert":         "cds.json",
		"c8s-router/allowlist-proxy":  "cds.json",
		"c8s-armtls-mesh/armtls-mesh": "peers.json",
	}
	workloads := renderedPodSpecs(t, out)
	if len(workloads) != 4 {
		t.Fatalf("baked chart should contain operator, CDS, router and mesh; got %d workloads", len(workloads))
	}
	for _, workload := range workloads {
		volumeFound := false
		for _, volume := range workload.spec.Volumes {
			if volume.HostPath != nil && strings.HasPrefix(volume.HostPath.Path, "/run/confos") {
				t.Errorf("%s mounts the token-bearing launch directory", workload.name)
			}
			if volume.Name == "node-config" {
				volumeFound = true
				if volume.HostPath == nil || volume.HostPath.Path != "/run/c8s-node" || volume.HostPath.Type == nil || *volume.HostPath.Type != corev1.HostPathDirectory {
					t.Errorf("%s must require the verified public launch directory", workload.name)
				}
			}
		}
		if !volumeFound {
			t.Errorf("%s lacks its verified launch policy volume", workload.name)
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
		if workload.name == "c8s-router" || workload.name == "c8s-armtls-mesh" {
			if workload.spec.SecurityContext == nil || !slices.Contains(workload.spec.SecurityContext.SupplementalGroups, int64(65532)) {
				t.Errorf("%s cannot connect to the host attestation socket", workload.name)
			}
		}
	}
	if len(wantPolicies) != 0 {
		t.Errorf("missing policy consumers: %v", wantPolicies)
	}

	mesh := renderedDaemonSet(t, out, "c8s-armtls-mesh")
	meshContainer, ok := findContainer(mesh.Spec.Template.Spec.Containers, "armtls-mesh")
	if !ok {
		t.Fatal("mesh container missing")
	}
	assertContainerHasArg(t, "armtls-mesh", meshContainer.Args, "--cds-image-policy-file=/run/c8s-node/cds.json")
	if mesh.Spec.Template.Spec.ServiceAccountName != "c8s-armtls-mesh" || strings.Contains(out, "name: system:nodes") {
		t.Error("mesh must use its ServiceAccount instead of node credentials")
	}

	for _, name := range []string{"c8s-cds", "c8s-router"} {
		deployment := renderedDeployment(t, out, name)
		if deployment.Namespace != "c8s-system" || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
			t.Errorf("%s must be a namespaced singleton with Recreate strategy", name)
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
	nginx := renderedDeploymentContainer(t, out, "c8s-router", "nginx")
	port, ok := findContainerPort(nginx, "https")
	if !ok || port.ContainerPort != 8443 || port.HostPort != 443 {
		t.Error("router must expose host 443 through unprivileged container port 8443")
	}
	config := renderedConfigMap(t, out, "c8s-router-nginx")
	if config.Namespace != "c8s-system" || !strings.Contains(config.Data["nginx.conf"], "server_name _;") {
		t.Error("baked router must retain its namespaced nginx config with a default virtual host")
	}
}

func TestChartBakedRouterReadsLaunchFiles(t *testing.T) {
	args := append(slices.Clone(bakedArgs), "--set-string", "nriImagePolicy.distro=rke2")
	out, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	conf := renderedConfigMap(t, out, "c8s-router-nginx").Data["nginx.conf"]
	for _, want := range []string{
		"server_name _;",
		"include /run/c8s-node/router/tls.conf;",
		"resolver rke2-coredns-rke2-coredns.kube-system.svc.cluster.local;",
		"include /run/c8s-node/router/upstream.conf;",
		"if ($c8s_upstream = \"\") {",
		"proxy_pass http://$c8s_upstream;",
		"listen 8080;",
		"location /.well-known/acme-challenge/ {",
		"location /.well-known/c8s/ {",
		"location = /allowlist {",
		"location = /v1/discovery {",
		"location /healthz {",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("nginx.conf lacks %q", want)
		}
	}
	if strings.Contains(conf, "upstream catch_all") {
		t.Error("launch-driven router must not render a static catch-all")
	}
	if strings.Contains(conf, "ssl_certificate ") {
		t.Error("launch-driven nginx.conf must leave the certificate to tls.conf")
	}
	snippets := renderedConfigMap(t, out, "c8s-router-nginx").Data
	for key, want := range map[string]string{
		"tls-cds.conf":  "ssl_certificate     /tls/cert.pem;\nssl_certificate_key /tls/key.pem;",
		"tls-acme.conf": "ssl_certificate     /etc/c8s-acme-tls/cert.pem;\nssl_certificate_key /etc/c8s-acme-tls/key.pem;",
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
		"--standby-cert-dir=/tls",
		"--cert-dir=/etc/c8s-acme-tls",
	} {
		assertContainerHasArg(t, "acme", acme.Args, arg)
	}
	assertContainerNoArgPrefix(t, "acme", acme.Args, "--domains=")
	assertContainerMount(t, acme, "node-config", "/run/c8s-node")
	assertContainerMount(t, acme, "tls-certs", "/tls")

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
		if m.Name == "nginx-config" && m.MountPath == "/etc/nginx/c8s" && m.ReadOnly {
			snippetDir = true
		}
	}
	if !snippetDir {
		t.Error("nginx must mount the TLS snippets read-only at /etc/nginx/c8s")
	}
	if port, ok := findContainerPort(nginx, "http"); !ok || port.ContainerPort != 8080 || port.HostPort != 80 {
		t.Error("launch-driven router must publish the ACME challenge port on host 80")
	}
	assertRouterFrontDoorPorts(t, out)

	attest := renderedDeploymentContainer(t, out, "c8s-router", "cds-attest")
	for _, arg := range []string{
		"--front-door-mode-file=/run/c8s-node/router/front-door-mode",
		"--upstream-file=/run/c8s-node/router/upstream",
		"--serving-cert-file=/tls/cert.pem",
		"--acme-serving-cert-file=/etc/c8s-acme-tls/cert.pem",
	} {
		assertContainerHasArg(t, "cds-attest", attest.Args, arg)
	}
	assertContainerNoArgPrefix(t, "cds-attest", attest.Args, "--front-door-mode=")
	assertContainerNoArgPrefix(t, "cds-attest", attest.Args, "--upstream=")
	assertContainerMount(t, attest, "node-config", "/run/c8s-node")
}

func TestChartBakedRouterRejectsReplacedValues(t *testing.T) {
	for name, args := range map[string][]string{
		"upstream": append(slices.Clone(bakedArgs), "--set-string", "router.upstream.address=c8s-infer.c8s-system.svc.cluster.local:8000"),
		"tls mode": append(slices.Clone(bakedArgs), "--set", "router.publicTLS.mode=acme"),
	} {
		t.Run(name, func(t *testing.T) {
			out, err := helmTemplate(t, args...)
			if err == nil || !strings.Contains(out, "node.baked takes the") {
				t.Fatalf("render accepted or failed elsewhere: %v\n%s", err, out)
			}
		})
	}
}

// A regular Helm install never reads launch files.
func TestChartRouterDefaultIgnoresLaunchFiles(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, unwanted := range []string{"/run/c8s-node/router", "--domains-file", "--discovery-public-tls-mode-file", "--front-door-mode-file", "--upstream-file", "$c8s_upstream"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("unbaked render contains %q", unwanted)
		}
	}
}

// A measured router must also provide the workload identity that clients pin.
// Image admission alone does not put a matched-workload stamp in its mesh leaf.
func TestChartBakedRouterRequestsWorkloadIdentity(t *testing.T) {
	out, err := helmTemplate(t, bakedArgs...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	pod := renderedDeployment(t, out, "c8s-router").Spec.Template.Spec
	cert, ok := findContainer(pod.InitContainers, "c8s-cert")
	if !ok {
		t.Fatal("router certificate sidecar missing")
	}
	assertContainerHasArg(t, "c8s-cert", cert.Args, "--workload-claims")
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
		if volume.Name == "workload-claims" && volume.HostPath != nil && volume.HostPath.Path == "/var/run/nri-image-policy" && volume.HostPath.Type != nil && *volume.HostPath.Type == corev1.HostPathDirectory {
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
