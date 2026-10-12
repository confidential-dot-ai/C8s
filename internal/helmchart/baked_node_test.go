package helmchart

import (
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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
	// The measured image names the guest it boots, so CDS admits no evidence
	// that identifies only a provider's firmware.
	assertContainerNoArgPrefix(t, "cds", cds.Args, "--admit-azure-snp")
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
