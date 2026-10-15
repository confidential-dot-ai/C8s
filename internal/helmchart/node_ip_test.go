package helmchart

import (
	"maps"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

var bareMetalHostAPI = []string{
	"--set", "attestationApi.cvmMode=bare-metal",
	"--set", "attestationApi.enabled=false",
	"--set", "router.attest.enabled=true",
}

// attestationURLs maps each rendered container that takes an attestation-api
// URL to it, keyed by workload/container.
func attestationURLs(t *testing.T, out string) map[string]renderedContainer {
	t.Helper()
	urls := map[string]renderedContainer{}
	for _, w := range renderedPodSpecs(t, out) {
		for _, c := range slices.Concat(w.spec.InitContainers, w.spec.Containers) {
			argv := slices.Concat(c.Command, c.Args)
			for i, arg := range argv {
				url, ok := strings.CutPrefix(arg, "--attestation-api-url=")
				if arg == "--attestation-api-url" && i+1 < len(argv) {
					url, ok = argv[i+1], true
				}
				if ok {
					urls[w.name+"/"+c.Name] = renderedContainer{url: url, spec: w.spec, container: c}
				}
			}
		}
	}
	for _, want := range []string{"c8s-cds/cds", "c8s-armtls-mesh/armtls-mesh", "c8s-router/cds-attest", "c8s-router/c8s-cert"} {
		if _, ok := urls[want]; !ok {
			t.Fatalf("%s takes no attestation-api URL; have %v", want, slices.Sorted(maps.Keys(urls)))
		}
	}
	return urls
}

type renderedContainer struct {
	url       string
	spec      corev1.PodSpec
	container corev1.Container
}

func hasEnv(c corev1.Container, name string) bool {
	return slices.ContainsFunc(c.Env, func(e corev1.EnvVar) bool { return e.Name == name })
}

// Under a fail-closed policy on bare-metal, every component reads the node
// address from the node-ip file through a pinned read-only host path, never
// from HOST_IP. The operator keeps $(HOST_IP): it hands the URL to injected
// sidecars, whose args and env the webhook writes.
func TestChartBareMetalReadsNodeIPFile(t *testing.T) {
	out, err := helmTemplate(t, bareMetalHostAPI...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for name, rc := range attestationURLs(t, out) {
		if strings.HasPrefix(name, "c8s-operator/") {
			if rc.url != "http://$$(HOST_IP):8400" {
				t.Errorf("%s --attestation-api-url = %q, want the $(HOST_IP) form for injected sidecars", name, rc.url)
			}
			continue
		}
		if rc.url != "http://$$(NODE_IP):8400" {
			t.Errorf("%s --attestation-api-url = %q, want http://$$(NODE_IP):8400", name, rc.url)
		}
		if hasEnv(rc.container, "HOST_IP") {
			t.Errorf("%s sets HOST_IP", name)
		}
		i := slices.IndexFunc(rc.container.VolumeMounts, func(m corev1.VolumeMount) bool { return m.MountPath == "/run/c8s/node-ip" })
		if i < 0 || !rc.container.VolumeMounts[i].ReadOnly {
			t.Errorf("%s mounts = %+v, want the node-ip file read-only at /run/c8s/node-ip", name, rc.container.VolumeMounts)
			continue
		}
		v := slices.IndexFunc(rc.spec.Volumes, func(v corev1.Volume) bool { return v.Name == rc.container.VolumeMounts[i].Name })
		if v < 0 || rc.spec.Volumes[v].HostPath == nil || rc.spec.Volumes[v].HostPath.Path != "/var/run/nri-image-policy/node-ip" ||
			rc.spec.Volumes[v].HostPath.Type == nil || *rc.spec.Volumes[v].HostPath.Type != corev1.HostPathFile {
			t.Errorf("%s node-ip volume = %+v, want hostPath /var/run/nri-image-policy/node-ip of type File", name, rc.spec.Volumes)
		}
	}
}

// Under audit nothing is refused, so the chart keeps $(HOST_IP) from the
// downward API.
func TestChartBareMetalAuditKeepsHostIP(t *testing.T) {
	out, err := helmTemplate(t, slices.Concat(bareMetalHostAPI, []string{"--set", "nriImagePolicy.policy.mode=audit"})...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for name, rc := range attestationURLs(t, out) {
		if rc.url != "http://$$(HOST_IP):8400" {
			t.Errorf("%s --attestation-api-url = %q, want http://$$(HOST_IP):8400", name, rc.url)
		}
		if !strings.HasPrefix(name, "c8s-operator/") && !hasEnv(rc.container, "HOST_IP") {
			t.Errorf("%s does not set HOST_IP", name)
		}
	}
}

func TestChartRefusesHostIPArgvWhenFailClosed(t *testing.T) {
	out, err := helmTemplate(t, slices.Concat(bareMetalHostAPI, []string{"--set-string", "router.attest.attestationApiURL=http://$$(HOST_IP):8400"})...)
	if err == nil {
		t.Fatalf("helm template succeeded with $$(HOST_IP) in a fail-closed component argv\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "host_ip_argv" {
		t.Fatalf("validation error kind = %q, want host_ip_argv\n%s", kind, out)
	}
	out, err = helmTemplate(t, slices.Concat(bareMetalHostAPI, []string{"--set-string", "router.attest.attestationApiURL=http://$$(HOST_IP):8400", "--set", "nriImagePolicy.policy.mode=audit"})...)
	if err != nil {
		t.Fatalf("helm template under audit: %v\n%s", err, out)
	}
}
