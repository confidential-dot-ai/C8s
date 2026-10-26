package nodeservices

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
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

// A worker enforces the baked floor like an agent, in the cluster network its
// signed document names instead of the image's own RKE2 cluster's.
func TestPrepareWorkerBindsItsClusterNetwork(t *testing.T) {
	root := prepareRoot(t)
	// A server's output from an earlier boot must not survive on a worker.
	writeInput(t, root, PublicDir+"/allowlist-seed.json", []byte(seed))
	doc := workerDocument(t)
	if err := Prepare(root, doc); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, nriPolicyPath))
	if err != nil {
		t.Fatal(err)
	}
	var got, before map[string]any
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(meshFloor), &before); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got["policy"], before["policy"]) {
		t.Fatal("changed baked enforcement policy")
	}
	mesh := got["mesh"].(map[string]any)
	if mesh["resolver"] != "10.96.0.10" || !reflect.DeepEqual(mesh["cluster_ranges"], []any{"10.244.0.0/16", "10.96.0.0/12"}) {
		t.Fatalf("worker mesh network: resolver %v, ranges %v", mesh["resolver"], mesh["cluster_ranges"])
	}
	baked := before["mesh"].(map[string]any)
	for _, key := range []string{"exempt_namespaces", "capture"} {
		if !reflect.DeepEqual(mesh[key], baked[key]) {
			t.Fatalf("changed baked mesh %s", key)
		}
	}
	pull := got["allowlist"].(map[string]any)["pull"].(map[string]any)
	if pull["url"] != doc.CDSURL() || pull["cds_measurements_config"] != launchDir+"cds.json" {
		t.Fatalf("bad pull config: %v", pull)
	}
	if _, err := os.Stat(filepath.Join(root, PublicDir, "allowlist-seed.json")); !os.IsNotExist(err) {
		t.Fatal("worker kept a server's seed")
	}
}
