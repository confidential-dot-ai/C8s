package webhook

import (
	"encoding/json"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// operatorDenyBelow reads the denyBelow list the chart seeds for the operator
// image, which the injected sidecars share.
func operatorDenyBelow(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../helmchart/c8s/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var values struct {
		Components []struct {
			ValuePath string   `json:"valuePath"`
			DenyBelow []string `json:"denyBelow"`
		} `json:"c8sComponents"`
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	for _, c := range values.Components {
		if c.ValuePath == "image" {
			return c.DenyBelow
		}
	}
	t.Fatal("values.yaml seeds no c8s image component")
	return nil
}

// Every sidecar the webhook injects runs the operator image, so the node
// admits it under that image's component entry. Its mounts must pass the
// entry's confined policy without an unconfined destination: the injected
// volumes are memory-backed, and the inventory socket directory is a
// read-only host path.
func TestInjectedContainerMountsPassTheOperatorPolicy(t *testing.T) {
	cfg := secretsConfig()
	cfg.WorkloadClaimsHostDir = "/var/run/nri-image-policy"
	pod := podWithApp()
	mutatePod(pod, &injection{
		WorkloadID: "api",
		Secrets:    secretsSpec{Specs: []string{"DB=/api/db"}},
		Volumes:    volumesSpec{Specs: []string{"weights=/tenant-a/volumes/weights"}},
	}, cfg)

	const digest = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	entry := map[string]any{"containers": []any{map[string]any{
		"digest":  digest,
		"command": map[string]any{"policy": "exact", "argv": []string{secrets.InjectedBinary}},
		"args":    map[string]any{"policy": "any"},
		"mounts":  map[string]any{"policy": "confined", "denyBelow": operatorDenyBelow(t)},
	}}}
	doc, err := json.Marshal(map[string]any{"schema": "c8s.allowlist/v1", "workloads": map[string]any{"c8s": entry}})
	if err != nil {
		t.Fatal(err)
	}
	al, err := allowlist.ParseJSON(doc)
	if err != nil {
		t.Fatal(err)
	}
	index := al.BuildIndex()

	volumes := map[string]corev1.Volume{}
	for _, v := range pod.Spec.Volumes {
		volumes[v.Name] = v
	}
	checked := 0
	for _, c := range pod.Spec.InitContainers {
		if !workloadclaims.IsInjectedContainerName(c.Name) {
			continue
		}
		var mounts []allowlist.ObservedMount
		for _, m := range c.VolumeMounts {
			v := volumes[m.Name]
			if v.EmptyDir == nil || v.EmptyDir.Medium != corev1.StorageMediumMemory {
				t.Errorf("%s mounts %s at %s, not a memory emptyDir", c.Name, m.Name, m.MountPath)
			}
			mounts = append(mounts, allowlist.ObservedMount{Destination: m.MountPath, Class: allowlist.MountEmptyDir, Storage: allowlist.MountMemory})
		}
		if workloadclaims.IsSocketConsumer(c.Name) {
			mounts = append(mounts, allowlist.ObservedMount{Destination: workloadclaims.SidecarSocketDir, Class: allowlist.MountHost, ReadOnly: true, HostSourceDigest: "3b2e1f"})
		}
		argv := c.Command
		if len(argv) == 0 {
			argv = append([]string{secrets.InjectedBinary}, c.Args...)
		}
		checked++
		if !index.AdmitsContainer(allowlist.RunningContainer{Digest: digest, Argv: argv, Mounts: mounts, Env: &allowlist.EnvObservation{}}) {
			t.Errorf("operator entry refuses injected %s with mounts %+v", c.Name, mounts)
		}
	}
	if checked != 4 {
		t.Fatalf("checked %d injected containers, want the cert sidecar, cert-wait gate, secret fetcher, and volume fetcher", checked)
	}
}
