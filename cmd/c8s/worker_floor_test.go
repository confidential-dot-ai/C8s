//go:build !c8s_node

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	yamlv3 "gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/worker"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// The worker chart's router pins its launch and reads only files worker stage
// publishes, so a worker image's floor builds from the render, and the
// release's component set carries the router entry declaring the HTTPS and
// HTTP host ports its Deployment maps. The floor itself holds the image's
// static pods and nothing that publishes a host port.
func TestWorkerFloorBuildsFromTheRenderedChart(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal("helm CLI not found")
	}
	setCLIVersion(t, "v"+nodeImageTestSetVersion)
	out := t.TempDir()
	cmd := newNodeImageCmd()
	cmd.SetArgs([]string{
		"render", "--hardware-platform", "sev-snp", "--kube-version", "v1.36.6",
		"--chart-dir", workerChartDir,
		"--image-digest", testDigest, "--image-repository", "registry.example.com/c8s-operator",
		"--armtls-mesh-image-digest", nodeImageTestMeshDigest, "--armtls-mesh-image-repository", "registry.example.com/armtls-mesh",
		"--floor-template", floorTemplateFile,
		"--output-dir", out,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(floorTemplateFile)
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	routerRepo, routerDigest, _ := strings.Cut(strings.TrimSpace(string(read("router-image.txt"))), "@")
	nodeFloor := strings.NewReplacer(
		"@PLATFORM@", "snp",
		"@MESH_REPO@", "registry.example.com/armtls-mesh", "@MESH_DIGEST@", nodeImageTestMeshDigest,
		"@OPERATOR_REPO@", "registry.example.com/c8s-operator", "@OPERATOR_DIGEST@", testDigest,
		"@ROUTER_REPO@", routerRepo, "@ROUTER_DIGEST@", routerDigest,
	).Replace(string(template))
	templateDir := filepath.Join(out, "static-pods")
	entries, err := os.ReadDir(templateDir)
	if err != nil {
		t.Fatal(err)
	}
	templates := map[string][]byte{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(templateDir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		templates[entry.Name()] = data
	}
	floor, err := worker.Floor([]byte(nodeFloor), templates)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Allowlist struct {
			Base allowlist.Allowlist `yaml:"base"`
		} `yaml:"allowlist"`
	}
	if err := yamlv3.Unmarshal(floor, &doc); err != nil {
		t.Fatal(err)
	}
	for _, pod := range []string{"cilium", "coredns", "dcgm-exporter", "kube-proxy", "nvidia-device-plugin"} {
		if !doc.Allowlist.Base.Workloads[pod].StaticPod {
			t.Errorf("the floor holds no static-pod entry for the image's %s", pod)
		}
	}
	for name, w := range doc.Allowlist.Base.Workloads {
		if len(w.HostPorts) > 0 {
			t.Errorf("the floor's %s entry declares the host ports %+v; a release's components declare theirs in its component set", name, w.HostPorts)
		}
	}
	set, err := allowlist.ParseJSON(read("component-set.json"))
	if err != nil {
		t.Fatal(err)
	}
	mapped := map[int]int{}
	var router allowlist.HostPortList
	for name, entry := range set.Components[nodeImageTestSetVersion].Entries {
		if !strings.HasPrefix(name, "c8s-router-") || len(entry.HostPorts) == 0 {
			continue
		}
		if router != nil {
			t.Fatalf("two entries of the set declare host ports, %+v and %+v", router, entry.HostPorts)
		}
		router = entry.HostPorts
	}
	for _, p := range router {
		if p.Protocol == "TCP" {
			mapped[p.HostPort] = p.ContainerPort
		}
	}
	if len(router) != 2 || mapped[443] != 8443 || mapped[80] != 8080 {
		t.Fatalf("the set's router entry declares the host ports %+v, want TCP 443 from 8443 and 80 from 8080", router)
	}
}
