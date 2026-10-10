package steps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestManifestCopiesContainers: a multi-container pod is the backend's
// single-container manifest with its container repeated, each keeping the
// security context and taking its own name, image and command.
func TestManifestCopiesContainers(t *testing.T) {
	rendered := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"gamma","namespace":"ns"},` +
		`"spec":{"restartPolicy":"Never","nodeName":"n","containers":[{"name":"curl","image":"a",` +
		`"command":["sleep","3600"],"securityContext":{"allowPrivilegeEscalation":false}}]}}`
	script := filepath.Join(t.TempDir(), "fake.sh")
	if err := os.WriteFile(script, []byte("#!/usr/bin/env bash\ncase \"$1\" in pod_manifest) printf '%s' '"+rendered+"' ;; *) exit 2 ;; esac\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := &world{be: backend{script: script}, namespace: "ns"}
	p := &pod{name: "gamma"}
	p.add("a")
	p.add("b").command = []string{"serve"}

	out, err := w.manifest(p, "n")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			NodeName   string `json:"nodeName"`
			Containers []struct {
				Name            string         `json:"name"`
				Image           string         `json:"image"`
				Command         []string       `json:"command"`
				SecurityContext map[string]any `json:"securityContext"`
			} `json:"containers"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Metadata.Name != "gamma" || doc.Spec.NodeName != "n" {
		t.Fatalf("pod identity lost: %s", out)
	}
	if len(doc.Spec.Containers) != 2 {
		t.Fatalf("want 2 containers, got %d: %s", len(doc.Spec.Containers), out)
	}
	c1, c2 := doc.Spec.Containers[0], doc.Spec.Containers[1]
	if c1.Name != "c1" || c1.Image != "a" || c1.Command[0] != "sleep" {
		t.Errorf("first container: %+v", c1)
	}
	if c2.Name != "c2" || c2.Image != "b" || c2.Command[0] != "serve" {
		t.Errorf("second container: %+v", c2)
	}
	for _, c := range doc.Spec.Containers {
		if v, ok := c.SecurityContext["allowPrivilegeEscalation"]; !ok || v != false {
			t.Errorf("%s lost its security context: %v", c.Name, c.SecurityContext)
		}
	}
}
