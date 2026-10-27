package nodeservices

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGenericPodPreparationPublishesOnlyWaitingPolicy(t *testing.T) {
	root := preparePodRoot(t)
	doc := podDocument(t)
	doc.Pod = nil
	doc.Workloads = ""
	if err := preparePodFixture(root, doc); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, podManifestPath)); !os.IsNotExist(err) {
		t.Fatal("generic boot published a manifest")
	}
	data, err := os.ReadFile(filepath.Join(root, nriPolicyPath))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Pod struct {
			Waiting, Generic bool
			UID              string
		}
		Measure   struct{ RTMR3 bool }
		Allowlist struct {
			NodeTCB bool `yaml:"node_tcb"`
		}
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Pod.Waiting || !cfg.Pod.Generic || cfg.Pod.UID != "" || !cfg.Measure.RTMR3 || cfg.Allowlist.NodeTCB {
		t.Fatalf("generic boot lost waiting floor: %+v", cfg)
	}
}

func TestAssignedRuntimeRendersWithoutWritingAndMarksOrigin(t *testing.T) {
	root := preparePodRoot(t)
	doc := podDocument(t)
	for _, entries := range []string{"", "{\"schema\":\"c8s.allowlist/v1\",\"workloads\":{}}", podWorkloads} {
		doc.Workloads = entries
		runtime, err := RenderAssignedPodRuntime(root, doc)
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Pod struct {
				Waiting, Generic bool
				UID              string
			}
		}
		if err := yaml.Unmarshal(runtime.Policy, &cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.Pod.Waiting || !cfg.Pod.Generic || cfg.Pod.UID != doc.Pod.UID || len(runtime.Manifest) == 0 {
			t.Fatal("assigned policy lost generic origin or identity")
		}
		for _, path := range []string{nriPolicyPath, podManifestPath} {
			if _, err := os.Stat(filepath.Join(root, path)); !os.IsNotExist(err) {
				t.Fatal("render mutated guest state")
			}
		}
	}
	cold, err := RenderPodRuntime(root, doc)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct{ Pod struct{ Generic bool } }
	if err := yaml.Unmarshal(cold.Policy, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Pod.Generic {
		t.Fatal("static launch gained generic restart exception")
	}
}
