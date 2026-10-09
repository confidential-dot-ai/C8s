package helmchart

import (
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestChartBakedNodeLaunchContract(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "node.baked=true",
		"--set", "attestationApi.cvmMode=bare-metal",
		"--set", "attestationApi.enabled=false",
		"--set", "nriImagePolicy.enabled=false",
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set", "image.digest=sha256:"+strings.Repeat("1", 64),
		"--set", "armtlsMesh.image.digest=sha256:"+strings.Repeat("2", 64),
		"--set", "image.pullPolicy=Never",
		"--set", "cds.image.pullPolicy=Never",
		"--set", "armtlsMesh.image.pullPolicy=Never",
		"--set", "router.nginx.image.pullPolicy=Never",
		"--set", "router.attest.enabled=true",
	)
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
	nginx := renderedDeploymentContainer(t, out, "c8s-router", "nginx")
	port, ok := findContainerPort(nginx, "https")
	if !ok || port.ContainerPort != 8443 || port.HostPort != 443 {
		t.Error("router must expose host 443 through unprivileged container port 8443")
	}
	// The baked front door answers the launch-signed SAN its certificate
	// sidecar reads at runtime, so its only virtual host accepts any name.
	assertContainerHasArg(t, "nginx", nginx.Args, "--san=_")
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
