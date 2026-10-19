//go:build !c8s_node

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	allowlistcmd "github.com/confidential-dot-ai/c8s/internal/cmds/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestAllowlistUploadRenderedCvmTopology(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal("helm is required to verify the install/upload topology contract")
	}
	resetCLIState(t)
	for _, mode := range []string{"bare-metal", "gke", "aks"} {
		t.Run(mode, func(t *testing.T) {
			desired := renderedTopologyAllowlist(t, mode)
			apiEntries := []string{}
			for name, workload := range desired.Workloads {
				for _, container := range workload.Containers {
					if strings.Contains(container.Image, "attestation-api") {
						apiEntries = append(apiEntries, name)
					}
				}
			}
			if wantAPI := mode != "bare-metal"; (len(apiEntries) > 0) != wantAPI {
				t.Fatalf("rendered attestation-api entries = %v, want present: %v", apiEntries, wantAPI)
			}
			if err := dryRunTopologyUpload(t, mode, desired); err != nil {
				t.Fatalf("upload rendered %s allowlist: %v", mode, err)
			}
			if len(apiEntries) == 0 {
				return
			}
			for _, name := range apiEntries {
				delete(desired.Workloads, name)
			}
			if err := dryRunTopologyUpload(t, mode, desired); err == nil || !strings.Contains(err.Error(), "attestation-api") {
				t.Fatalf("upload without chart-managed attestation-api = %v, want missing component error", err)
			}
		})
	}
}

func renderedTopologyAllowlist(t *testing.T, mode string) pkgallowlist.Allowlist {
	t.Helper()
	args := []string{"template", "c8s", filepath.Join("..", "..", "internal", "helmchart", "c8s"), "--skip-tests", "--kube-version", "v1.34.5", "--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true"}
	for i, path := range []string{"image", "cds.image", "attestationApi.image", "armtlsMesh.image", "nriImagePolicy.image", "volumed.image"} {
		args = append(args, "--set-string", fmt.Sprintf("%s.digest=sha256:%064x", path, i+1))
	}
	args, err := appendCvmModeInstallArgs(args, mode, "sev-snp")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "helm", args...)
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	rendered, err := cmd.Output()
	if err != nil {
		t.Fatalf("helm template: %v\n%s\n%s", err, rendered, diagnostics.Bytes())
	}
	desired := pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{}}
	for name, raw := range nodeImageDocuments(t, rendered) {
		if !strings.HasPrefix(name, "Deployment/") && !strings.HasPrefix(name, "DaemonSet/") {
			continue
		}
		var workload struct {
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := yaml.Unmarshal(raw, &workload); err != nil {
			t.Fatal(err)
		}
		pod := workload.Spec.Template.Spec
		for _, container := range append(pod.InitContainers, pod.Containers...) {
			_, digestText, pinned := strings.Cut(container.Image, "@")
			if !pinned {
				t.Fatalf("%s container %s has unpinned image %q", name, container.Name, container.Image)
			}
			digest, err := types.ParseDigest(digestText)
			if err != nil {
				t.Fatal(err)
			}
			entryName := pkgallowlist.DigestEntryName(digest, container.Image)
			desired.Workloads[entryName] = pkgallowlist.DigestEntry(digest, container.Image)
		}
	}
	return desired
}

func dryRunTopologyUpload(t *testing.T, mode string, desired pkgallowlist.Allowlist) error {
	t.Helper()
	body, err := desired.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "allowlist.json")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/allowlist" {
			t.Errorf("unexpected CDS request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	cmd := allowlistcmd.NewCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"upload", file, "--cvm-mode", mode, "--dry-run", "--url", server.URL, "--insecure"})
	err = cmd.Execute()
	if err == nil && !strings.Contains(output.String(), "dry-run: would replace allowlist") {
		t.Fatalf("missing dry-run result: %s", &output)
	}
	return err
}
