package nodeservices

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func workerDocument(t *testing.T) *launchconfig.Document {
	t.Helper()
	doc := document(t, launchconfig.Worker)
	doc.Kubernetes = &launchconfig.Kubernetes{
		APIServer: "c-0123.k8s.example", ClusterDNS: "10.96.0.10", ClusterDomain: "cluster.local",
		PodCIDR: "10.244.0.0/16", ServiceCIDR: "10.96.0.0/12",
	}
	return doc
}

// workerFloor is the baked node config with the agent's namespace exemption
// and an open system entry, which a worker must not inherit.
var workerFloor = strings.Replace(podFloor, "  enforce_existing: true\n",
	"  enforce_existing: true\n  exempt_namespaces: [kube-system]\n  exempt_snapshot_path: /var/lib/nri-image-policy/exempt.json\n  sandbox: audit\n", 1)

func prepareWorkerRoot(t *testing.T) string {
	t.Helper()
	root := prepareRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(workerFloor))
	return root
}

func stagedWorkerPolicy(t *testing.T, root string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, nriPolicyPath))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// A worker enforces the floor in the cluster network its signed document
// names instead of the image's own RKE2 cluster's.
func TestPrepareWorkerBindsItsClusterNetwork(t *testing.T) {
	root := prepareWorkerRoot(t)
	// A server's output from an earlier boot must not survive on a worker.
	writeInput(t, root, PublicDir+"/allowlist-seed.json", []byte(seed))
	doc := workerDocument(t)
	if err := Prepare(root, doc); err != nil {
		t.Fatal(err)
	}
	got := stagedWorkerPolicy(t, root)
	mesh := got["mesh"].(map[string]any)
	if mesh["resolver"] != "10.96.0.10" || !reflect.DeepEqual(mesh["cluster_ranges"], []any{"10.244.0.0/16", "10.96.0.0/12"}) {
		t.Fatalf("worker mesh network: resolver %v, ranges %v", mesh["resolver"], mesh["cluster_ranges"])
	}
	var before map[string]any
	if err := yaml.Unmarshal([]byte(workerFloor), &before); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(mesh["capture"], before["mesh"].(map[string]any)["capture"]) {
		t.Fatal("changed baked mesh capture")
	}
	pull := got["allowlist"].(map[string]any)["pull"].(map[string]any)
	if pull["url"] != doc.CDSURL() || pull["cds_measurements_config"] != launchDir+"cds.json" {
		t.Fatalf("bad pull config: %v", pull)
	}
	if _, err := os.Stat(filepath.Join(root, PublicDir, "allowlist-seed.json")); !os.IsNotExist(err) {
		t.Fatal("worker kept a server's seed")
	}
}

// The worker's control plane writes every pod spec in every namespace, so
// its floor exempts no namespace, holds no open system or chart entry, has no
// node TCB and enforces host privilege.
func TestPrepareWorkerTrustsNoNamespaceOrOpenEntry(t *testing.T) {
	root := prepareWorkerRoot(t)
	doc := workerDocument(t)
	if err := Prepare(root, doc); err != nil {
		t.Fatal(err)
	}
	got := stagedWorkerPolicy(t, root)
	policy := got["policy"].(map[string]any)
	if ns, ok := policy["exempt_namespaces"].([]any); !ok || len(ns) != 0 {
		t.Fatalf("policy exempt namespaces %v", policy["exempt_namespaces"])
	}
	if _, kept := policy["exempt_snapshot_path"]; kept {
		t.Fatal("kept the exempt snapshot")
	}
	if policy["sandbox"] != "enforce" {
		t.Fatalf("sandbox %v, want enforce", policy["sandbox"])
	}
	mesh := got["mesh"].(map[string]any)
	if ns, ok := mesh["exempt_namespaces"].([]any); !ok || len(ns) != 0 {
		t.Fatalf("mesh exempt namespaces %v", mesh["exempt_namespaces"])
	}

	section := got["allowlist"].(map[string]any)
	if section["node_tcb"] != false {
		t.Fatalf("node_tcb %v, want false", section["node_tcb"])
	}
	data, err := yaml.Marshal(section["base"])
	if err != nil {
		t.Fatal(err)
	}
	var base allowlist.Allowlist
	if err := yaml.Unmarshal(data, &base); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(base.Workloads))
	for name, workload := range base.Workloads {
		names = append(names, name)
		for _, c := range workload.Containers {
			if c.Role == "mesh" && c.Mounts.Policy != allowlist.PolicyExact {
				t.Fatalf("mesh endpoint %s mounts %q, want exact", name, c.Mounts.Policy)
			}
		}
	}
	// Only the measured mesh endpoint: the baked system entry, the open
	// credential client and the chart seed are gone, and every workload
	// comes from CDS's policy.
	if len(base.Workloads) != 1 || base.Workloads["c8s-mesh-endpoint"].Containers == nil {
		t.Fatalf("worker base %v, want the mesh endpoint alone", names)
	}
}
