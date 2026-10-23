package helmchart

import (
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	sigsyaml "sigs.k8s.io/yaml"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

type kubeStateMetricsValues struct {
	KubeStateMetrics struct {
		Image struct {
			Repository string `yaml:"repository"`
			Digest     string `yaml:"digest"`
		} `yaml:"image"`
		Entrypoint []string          `yaml:"entrypoint"`
		ImageEnv   map[string]string `yaml:"imageEnv"`
		ClusterIP  string            `yaml:"clusterIP"`
		Port       uint16            `yaml:"port"`
	} `yaml:"kubeStateMetrics"`
}

// A baked node runs kube-state-metrics in kube-system as a singleton with
// read-only RBAC, behind the fixed Service address, and the seed admits it
// under exactly the argv, mounts and env the chart renders.
func TestChartBakedKubeStateMetrics(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, bakedArgs...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var values kubeStateMetricsValues
	readChartFile(t, "values.yaml", &values)
	ksm := values.KubeStateMetrics

	deployment := renderedDeployment(t, out, "kube-state-metrics")
	if deployment.Namespace != "kube-system" || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 {
		t.Fatalf("kube-state-metrics must be a singleton of kube-system")
	}
	spec := deployment.Spec.Template.Spec
	if len(spec.Containers) != 1 || len(spec.InitContainers) != 0 || len(spec.Volumes) != 0 {
		t.Fatalf("kube-state-metrics must run one container and mount no volumes")
	}
	c := spec.Containers[0]
	if c.Image != ksm.Image.Repository+"@"+ksm.Image.Digest {
		t.Errorf("kube-state-metrics image = %s, want the pinned digest", c.Image)
	}

	service := renderedService(t, out, "kube-state-metrics")
	if service.Namespace != "kube-system" || service.Spec.ClusterIP != ksm.ClusterIP || len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != int32(ksm.Port) {
		t.Errorf("kube-state-metrics Service = %s/%s %s %+v, want kube-system %s:%d alone", service.Namespace, service.Name, service.Spec.ClusterIP, service.Spec.Ports, ksm.ClusterIP, ksm.Port)
	}

	// RKE2's default policy admits kube-system ingress from kube-system
	// alone; the member pods' exit reaches the metrics port from any
	// namespace, and nothing else.
	var policy networkingv1.NetworkPolicy
	if !findDoc(t, out, "NetworkPolicy", "kube-state-metrics", &policy) {
		t.Fatal("kube-state-metrics NetworkPolicy missing")
	}
	ingress := policy.Spec.Ingress
	if policy.Namespace != "kube-system" || policy.Spec.PodSelector.MatchLabels["app.kubernetes.io/name"] != "kube-state-metrics" ||
		len(ingress) != 1 || len(ingress[0].From) != 1 || ingress[0].From[0].NamespaceSelector == nil ||
		len(ingress[0].From[0].NamespaceSelector.MatchLabels)+len(ingress[0].From[0].NamespaceSelector.MatchExpressions) != 0 ||
		len(ingress[0].Ports) != 1 || ingress[0].Ports[0].Port == nil || ingress[0].Ports[0].Port.String() != "http-metrics" {
		t.Errorf("kube-state-metrics NetworkPolicy %+v must admit its metrics port from every namespace alone", policy.Spec)
	}

	var role rbacv1.ClusterRole
	if !findDoc(t, out, "ClusterRole", "c8s-kube-state-metrics", &role) {
		t.Fatal("kube-state-metrics ClusterRole missing")
	}
	for _, rule := range role.Rules {
		if !slices.Equal(rule.Verbs, []string{"list", "watch"}) {
			t.Errorf("kube-state-metrics rule %+v grants more than list and watch", rule)
		}
		for _, resource := range rule.Resources {
			if resource == "secrets" || resource == "configmaps" || resource == "*" {
				t.Errorf("kube-state-metrics reads %s", resource)
			}
		}
	}

	seed := renderedSeed(t, out)
	var entries []pkgallowlist.Container
	for _, workload := range seed.Workloads {
		for _, container := range workload.Containers {
			if container.Digest.String() == ksm.Image.Digest {
				entries = append(entries, container)
			}
		}
	}
	if len(entries) != 1 {
		t.Fatalf("seed carries %d kube-state-metrics containers, want one", len(entries))
	}
	entry := entries[0]
	if entry.Command.Policy != pkgallowlist.PolicyExact || !slices.Equal(entry.Command.Argv, ksm.Entrypoint) ||
		entry.Args.Policy != pkgallowlist.PolicyExact || !slices.Equal(entry.Args.Argv, c.Args) ||
		entry.Mounts.Policy != pkgallowlist.PolicyDeny || entry.Env.Policy != pkgallowlist.PolicyMatch {
		t.Errorf("seeded kube-state-metrics entry %+v is not pinned exactly", entry)
	}
	launch := renderedLaunch(t, spec, c, componentPin{entrypoint: ksm.Entrypoint, imageEnv: ksm.ImageEnv})
	if !seed.BuildIndex().AdmitsContainer(launch) {
		t.Error("seed refuses the rendered kube-state-metrics container")
	}
	launch.Argv = append(slices.Clone(launch.Argv), "--resources=secrets")
	if seed.BuildIndex().AdmitsContainer(launch) {
		t.Error("seed admits kube-state-metrics with an argv the chart does not render")
	}
}

// Off a baked node no mesh policy names its address, so the chart refuses it.
func TestChartKubeStateMetricsRequiresABakedNode(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, "--set", "kubeStateMetrics.enabled=true")
	if err == nil || !strings.Contains(out+err.Error(), "kind=kube_state_metrics_unbaked") {
		t.Fatalf("helm template accepted kube-state-metrics off a baked node: %v\n%s", err, out)
	}
}

// The measured mesh policy gives every member pod the kube-state-metrics
// Service as its one platform exit, so its address and port are the chart's,
// inside the cluster's Service range.
func TestChartKubeStateMetricsAddressIsTheMeasuredMeshExit(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("../../node-guest-image/c8s/image-policy.yaml.in")
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Mesh struct {
			Exits []string `json:"exits"`
		} `json:"mesh"`
	}
	if err := sigsyaml.Unmarshal(body, &policy); err != nil {
		t.Fatal(err)
	}
	var values kubeStateMetricsValues
	readChartFile(t, "values.yaml", &values)
	want := netip.AddrPortFrom(netip.MustParseAddr(values.KubeStateMetrics.ClusterIP), values.KubeStateMetrics.Port)
	if len(policy.Mesh.Exits) != 1 || policy.Mesh.Exits[0] != want.String() {
		t.Errorf("measured mesh exits = %q, want the kube-state-metrics Service %s alone", policy.Mesh.Exits, want)
	}

	config, err := os.ReadFile("../../node-guest-image/c8s/mkosi.extra/etc/rancher/rke2/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var rke2 struct {
		ServiceCIDR string `json:"service-cidr"`
		ClusterDNS  string `json:"cluster-dns"`
	}
	if err := sigsyaml.Unmarshal(config, &rke2); err != nil {
		t.Fatal(err)
	}
	if !netip.MustParsePrefix(rke2.ServiceCIDR).Contains(want.Addr()) || want.Addr().String() == rke2.ClusterDNS {
		t.Errorf("kube-state-metrics address %s must be a free address of service-cidr %s", want.Addr(), rke2.ServiceCIDR)
	}
}
