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

// The chart's baked router pins its launch and reads only files worker stage
// publishes, so a worker image's floor builds from it and the image's static
// pod templates, and the router's entry declares the HTTPS and HTTP host ports
// its Deployment maps.
func TestWorkerFloorBuildsFromTheRenderedChart(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	out := t.TempDir()
	cmd := newNodeImageCmd()
	cmd.SetArgs([]string{
		"render", "--hardware-platform", "sev-snp", "--kube-version", "v1.36.4",
		"--chart-dir", filepath.Join("..", "..", "internal", "helmchart", "c8s"),
		"--image-digest", testDigest, "--image-repository", "registry.example.com/c8s-operator",
		"--armtls-mesh-image-digest", nodeImageTestMeshDigest, "--armtls-mesh-image-repository", "registry.example.com/armtls-mesh",
		"--router-image-digest", nodeImageTestRouterDigest, "--router-image-repository", "registry.example.com/nginx",
		"--output-dir", out,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "..", "images", "node-guest", "worker", "image-policy.yaml.in"))
	if err != nil {
		t.Fatal(err)
	}
	nodeFloor := strings.NewReplacer(
		"@PLATFORM@", "snp",
		"@MESH_REPO@", "registry.example.com/armtls-mesh", "@MESH_DIGEST@", nodeImageTestMeshDigest,
		"@OPERATOR_REPO@", "registry.example.com/c8s-operator", "@OPERATOR_DIGEST@", testDigest,
		"@ROUTER_REPO@", "registry.example.com/nginx", "@ROUTER_DIGEST@", nodeImageTestRouterDigest,
	).Replace(string(template))
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	templateDir := filepath.Join("..", "..", "images", "node-guest", "worker", "mkosi.extra", "usr", "lib", "c8s", "worker", "static-pods")
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
	floor, err := worker.Floor([]byte(nodeFloor), read("allowlist-seed.json"), templates)
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
	for _, pod := range []string{"cilium", "coredns", "kube-proxy"} {
		if !doc.Allowlist.Base.Workloads[pod].StaticPod {
			t.Errorf("the floor holds no static-pod entry for the image's %s", pod)
		}
	}
	publishing := map[string]allowlist.HostPortList{}
	for name, w := range doc.Allowlist.Base.Workloads {
		if len(w.HostPorts) > 0 {
			publishing[name] = w.HostPorts
		}
	}
	mapped := map[int]int{}
	var router allowlist.HostPortList
	for name, ports := range publishing {
		router = ports
		if !strings.HasPrefix(name, "c8s-router-") || len(publishing) != 1 {
			t.Fatalf("entries declaring host ports = %v, want the router's alone", publishing)
		}
	}
	for _, p := range router {
		if p.Protocol == "TCP" {
			mapped[p.HostPort] = p.ContainerPort
		}
	}
	if len(router) != 2 || mapped[443] != 8443 || mapped[80] != 8080 {
		t.Fatalf("router entry host ports = %+v, want TCP 443 from 8443 and 80 from 8080", router)
	}
}
