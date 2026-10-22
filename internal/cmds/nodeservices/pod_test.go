package nodeservices

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

const podWorkloads = `{"schema":"c8s.allowlist/v1","workloads":{"app":{"containers":[{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`

func podDocument(t *testing.T) *launchconfig.Document {
	t.Helper()
	doc := document(t, launchconfig.Pod)
	doc.Server.Address = ""
	doc.Node.Name = "p-pod"
	doc.Workloads = podWorkloads
	doc.Pod = &launchconfig.PodSpec{UID: "u1", Namespace: "tenant", Name: "app",
		Manifest: `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":"tenant","uid":"u1"},"spec":{"containers":[{"name":"app","image":"busybox@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}}`}
	return doc
}

func TestPreparePodRefusesAPlatformWithoutARuntimeRegister(t *testing.T) {
	root := prepareRoot(t)
	doc := podDocument(t)
	doc.Image.Platform = "snp"
	// Prepare checks the staged pins' family first; the pod step is what
	// must refuse, so call it as Prepare would.
	err := preparePod(root, doc, map[string][]byte{})
	if err == nil || !strings.Contains(err.Error(), "runtime register") {
		t.Fatalf("got %v, want a runtime register refusal", err)
	}
	if _, err := os.Stat(filepath.Join(root, nriPolicyPath)); !os.IsNotExist(err) {
		t.Fatalf("policy written without measurement: %v", err)
	}
}

func TestPreparePodAdmitsOnlySignedWorkloads(t *testing.T) {
	root := prepareRoot(t)
	// A server boot earlier must not leave its inputs to the pod.
	writeInput(t, root, PublicDir+"/allowlist-seed.json", []byte(seed))
	doc := podDocument(t)
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
	if err := yaml.Unmarshal([]byte(floor), &before); err != nil {
		t.Fatal(err)
	}
	// One key: the journal lives under the baked inventory directory and the
	// seed is the staged launch key, neither of which the document chooses.
	if m := got["measure"].(map[string]any); m["rtmr3"] != true || len(m) != 1 {
		t.Fatalf("measure = %v", m)
	}
	a := got["allowlist"].(map[string]any)
	if _, ok := a["pull"]; ok {
		t.Fatal("pod role must not pull a CDS allowlist")
	}
	if a["node_tcb"] != false {
		t.Fatal("pod workloads must not be exempt from the sandbox policy")
	}
	if !reflect.DeepEqual(got["mesh"], map[string]any{"isolated": true}) {
		t.Fatalf("pod mesh policy = %v, want isolation without cluster exceptions", got["mesh"])
	}
	base := basePolicy(t, a["base"])
	if len(base.Workloads) != 1 || len(base.Workloads["app"].Containers) != 1 {
		t.Fatalf("base = %v, want only the signed workloads", base.Workloads)
	}
	policy := got["policy"].(map[string]any)
	if policy["sandbox"] != "enforce" || policy["mode"] != "fail-closed" {
		t.Fatalf("policy = %v", policy)
	}
	delete(policy, "sandbox")
	if !reflect.DeepEqual(policy, before["policy"]) {
		t.Fatal("changed baked enforcement policy beyond sandbox")
	}

	for path, want := range map[string]string{
		podManifestPath:   doc.Pod.Manifest,
		podKubeletEnvPath: "KUBELET_HOSTNAME=p-pod\n",
		podUnmanagedLinks: podUnmanagedConfig,
	} {
		got, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v", path, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, PublicDir, "allowlist-seed.json")); !os.IsNotExist(err) {
		t.Fatal("pod kept a server output")
	}
	if _, err := os.Stat(filepath.Join(root, PublicDir, "peers.json")); err != nil {
		t.Fatal(err)
	}
}

func TestPreparePodFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		change func(*launchconfig.Document)
		want   string
	}{
		{"no pod", func(d *launchconfig.Document) { d.Pod = nil }, "requires a pod"},
		{"no workloads", func(d *launchconfig.Document) { d.Workloads = "" }, "requires a pod"},
		{"bad workloads", func(d *launchconfig.Document) { d.Workloads = "{" }, "launch workloads"},
		{"bad manifest", func(d *launchconfig.Document) { d.Pod.Manifest = "kind: Deployment" }, "pod.manifest"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := prepareRoot(t)
			doc := podDocument(t)
			tc.change(doc)
			err := Prepare(root, doc)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(root, nriPolicyPath)); !os.IsNotExist(err) {
				t.Fatal("published NRI policy from a rejected pod launch")
			}
		})
	}
}
