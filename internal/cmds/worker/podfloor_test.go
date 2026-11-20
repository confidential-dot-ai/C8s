package worker

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/podlaunch"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// The pod manifest a Pod CVM is assigned, and the entries signed with it.
const (
	assignedPodManifest = `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":"tenant","uid":"u1"},` +
		`"spec":{"containers":[{"name":"app","image":"busybox@sha256:` + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + `"}]}}`
	assignedPodEntries = `{"schema":"c8s.allowlist/v1","workloads":{"app":{"containers":[{"digest":"sha256:` +
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`
)

// A Pod CVM renders its pod from the mesh endpoint its own image measures, so
// the Pod CVM image's floor carries the template's role entries while the
// worker image's floor carries none.
func TestPodImageFloorRendersAnAssignedPod(t *testing.T) {
	template := renderedTemplate(t)
	floor, err := PodImageFloor(template)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := workloadsOf(t, floor), mustRoleEntries(t, template); len(got) != len(want) {
		t.Fatalf("the Pod CVM floor holds %d entries, want the template's %d role entries", len(got), len(want))
	}
	for name, entry := range workloadsOf(t, floor) {
		if entry.Containers[0].Role == "" {
			t.Errorf("the Pod CVM floor's %s entry grants no role", name)
		}
	}
	worker, err := Floor(template, map[string][]byte{"agent.yaml": []byte(agentTemplate)})
	if err != nil {
		t.Fatal(err)
	}
	for name, entry := range workloadsOf(t, worker) {
		for _, c := range entry.Containers {
			if c.Role != "" {
				t.Errorf("the worker floor's %s entry grants the role %q; a cluster grants it from the component set", name, c.Role)
			}
		}
	}

	runtime, err := nodeservices.RenderPodRuntime(podImageRoot(t, floor), assignedPod(t))
	if err != nil {
		t.Fatalf("a Pod CVM cannot render its pod from the floor its image bakes: %v", err)
	}
	if len(runtime.Manifest) == 0 || len(runtime.Policy) == 0 {
		t.Fatal("the render wrote no manifest or no policy")
	}
	if _, err := nodeservices.RenderPodRuntime(podImageRoot(t, worker), assignedPod(t)); err == nil ||
		!strings.Contains(err.Error(), "mesh endpoint") {
		t.Fatalf("RenderPodRuntime over the worker floor = %v, want a refusal naming its missing mesh endpoint", err)
	}
}

// mustRoleEntries are the template's role entries.
func mustRoleEntries(t *testing.T, template []byte) map[string]allowlist.Workload {
	t.Helper()
	entries, err := RoleEntries(template)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

// podImageRoot is a Pod CVM's root as its image bakes it: the floor and the
// measured resolver drop-ins the pod's resolver file is written from.
func podImageRoot(t *testing.T, floor []byte) string {
	t.Helper()
	root := t.TempDir()
	resolved, err := os.ReadFile(filepath.Join("..", "..", "..", "images", "node-guest", "worker", "mkosi.extra",
		"etc", "systemd", "resolved.conf.d", "10-upstream.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"/usr/lib/c8s/image-policy.yaml":                floor,
		"/etc/systemd/resolved.conf.d/10-upstream.conf": resolved,
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// assignedPod is a Pod CVM's launch document with the pod it was assigned.
func assignedPod(t *testing.T) *podlaunch.AssignedPod {
	t.Helper()
	pins, err := refvalues.Load(filepath.Join("..", "..", "testdata", "node-identities.json"))
	if err != nil {
		t.Fatal(err)
	}
	image := pins.Images[0]
	doc := &podlaunch.Document{
		SchemaVersion: podlaunch.SchemaVersion,
		ClusterID:     "demo",
		Role:          podlaunch.Pod,
		CDS:           testDocument(t).CDS,
		Image: podlaunch.Image{
			Platform:    "tdx",
			Measurement: hex.EncodeToString(image.Digest),
			RTMRs:       map[int]string{1: hex.EncodeToString(image.Registers[1]), 2: hex.EncodeToString(image.Registers[2])},
		},
		Node:                 podlaunch.Node{Name: "p-pod"},
		PodOperatorPublicKey: string(pins.Images[1].Anchor),
	}
	assigned, err := podlaunch.Assign(doc, []byte(assignedPodManifest), []byte(assignedPodEntries), []byte("[]"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return assigned
}
