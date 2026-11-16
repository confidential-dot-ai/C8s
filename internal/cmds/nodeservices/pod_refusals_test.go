package nodeservices

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/podlaunch"
)

func TestRenderPodRuntimeRefusesInvalidInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		floor  string
		change func(*podlaunch.AssignedPod)
		want   string
	}{
		{"node role", podFloor, func(a *podlaunch.AssignedPod) { a.Role = "agent" }, "not a Pod role document"},
		{"no policy section", strings.Replace(podFloor, "\npolicy:\n", "\nsettings:\n", 1), func(*podlaunch.AssignedPod) {}, "missing policy"},
		{"non-boolean policy measurement", strings.Replace(podFloor, "    timeout: 30s", "    timeout: 30s\n    measure_policies: sometimes", 1),
			func(*podlaunch.AssignedPod) {}, "measure_policies must be a boolean"},
		{"bad mesh peer", podFloor, func(a *podlaunch.AssignedPod) { a.Pod.MeshPeers = []string{"not-a-peer"} }, "pod.meshPeers"},
		{"invalid ingress port", podFloor, func(a *podlaunch.AssignedPod) {
			a.Pod.Manifest = strings.Replace(podManifest, `"name":"app","image"`, `"name":"app","ports":[{"containerPort":70000}],"image"`, 1)
		}, "invalid port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := preparePodRoot(t)
			writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(tc.floor))
			assigned := assignedPod(t, podManifest)
			tc.change(assigned)
			runtime, err := RenderPodRuntime(root, assigned)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if runtime.Policy != nil {
				t.Fatal("rendered policy from a rejected input")
			}
		})
	}
	if _, err := RenderPodRuntime(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "not a Pod role document") {
		t.Fatalf("no document: %v", err)
	}
	if _, err := RenderPodRuntime(t.TempDir(), assignedPod(t, podManifest)); err == nil {
		t.Fatal("rendered without a baked floor")
	}
}

func TestPodMeshPolicyRefusesMalformedBakedMesh(t *testing.T) {
	for _, tc := range []struct {
		name     string
		declared any
		want     string
	}{
		{"not a mapping", []any{}, "not a mapping"},
		{"roles not a list", map[string]any{"roles": "mesh"}, "not a list"},
		{"role not a mapping", map[string]any{"roles": []any{"mesh"}}, "role is string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := podMeshPolicy(tc.declared); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPodMeshBaseRequiresTheExactMeasuredEndpoint(t *testing.T) {
	const endpointBase = "schema: c8s.allowlist/v1\nworkloads:\n"
	decode := func(t *testing.T, workloads string) any {
		t.Helper()
		var declared any
		if err := yaml.Unmarshal([]byte(endpointBase+strings.ReplaceAll(workloads, "\n    ", "\n")[4:]), &declared); err != nil {
			t.Fatal(err)
		}
		return declared
	}
	if _, image, err := podMeshBase(decode(t, podEndpoint)); err != nil || !strings.HasPrefix(image, "registry.test/mesh@") {
		t.Fatalf("measured endpoint: %q, %v", image, err)
	}
	mesh, _, _ := strings.Cut(podEndpoint, "      c8s-get-cert:")
	second := podEndpoint + strings.Replace(mesh, "c8s-mesh-endpoint:", "second-endpoint:", 1)
	for _, tc := range []struct {
		name     string
		declared any
		want     string
	}{
		{"malformed base", map[string]any{"schema": "c8s.allowlist/v1", "unknown": true}, "baked NRI base"},
		{"two endpoints", decode(t, second), "more than one mesh endpoint"},
		{"unpinned command", decode(t, strings.Replace(podEndpoint, "argv: [/app/c8s, armtls-mesh]", "argv: [/bin/sh]", 1)), "must pin its image"},
		{"other volume", decode(t, strings.Replace(podEndpoint, "source: c8s-certs", "source: tenant", 1)), "private credential volume"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := podMeshBase(tc.declared); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
