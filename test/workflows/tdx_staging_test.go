package workflows

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Shared root disks are reused only after an authoritative read confirms both
// CI ownership and the complete immutable import endpoint.
func TestTDXStagingPreservesExistingRootDisks(t *testing.T) {
	var action lifecycleDocument
	readYAML(t, "../../.github/actions/tdx-metal-e2e/action.yml", &action)
	var stage workflowStep
	for _, step := range action.Runs.Steps {
		if step.Name == "stage the node image on the host (no-op when already staged)" {
			stage = step
		}
	}
	if stage.Run == "" || stage.If != "inputs.exact_image != 'true'" {
		t.Fatal("missing shared image staging step")
	}
	fixture := t.TempDir()
	kubectl := `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FIXTURE_COMMANDS"
if [[ $# == 8 && $1 == -n && $2 == confai-images && $3 == get && $4 == pvc && $5 == "$rootPvc" && $6 == --ignore-not-found && $7 == -o && $8 == json ]]; then
  case "$FIXTURE_MODE" in
    'read failure') exit 1 ;;
    'absent') exit 0 ;;
    *) cat "$FIXTURE_PVC" ;;
  esac
elif [[ $# == 7 && $1 == -n && $2 == confai-images && $3 == get && $4 == pvc && $5 == "$rootPvc" && $6 == -o && $7 == 'jsonpath={.metadata.annotations.cdi\.kubevirt\.io/storage\.pod\.phase}' ]]; then
  printf Succeeded
elif [[ $# == 3 && $1 == create && $2 == -f && $3 == - ]]; then
  cat > "$FIXTURE_CREATED"
else
  echo "unexpected kubectl operation: $*" >&2
  exit 1
fi
`
	if err := os.WriteFile(filepath.Join(fixture, "kubectl"), []byte(kubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	image := "ghcr.io/confidential-dot-ai/node-guest-base@sha256:" + strings.Repeat("a", 64)
	rootPVC := "c8s-root-" + strings.Repeat("a", 12)
	for _, tc := range []struct {
		name       string
		ok, create bool
	}{
		{name: "matching", ok: true},
		{name: "absent", ok: true, create: true},
		{name: "read failure"},
		{name: "same digest prefix different image"},
		{name: "unmanaged"},
		{name: "different resource kind"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := t.TempDir()
			labels := map[string]string{"ci.confidential.ai/managed": "true", "ci.confidential.ai/resource": "tdx-node-root"}
			endpoint := "docker://" + image
			switch tc.name {
			case "same digest prefix different image":
				endpoint = "docker://ghcr.io/confidential-dot-ai/node-guest-base@sha256:" + strings.Repeat("a", 12) + strings.Repeat("b", 52)
			case "unmanaged":
				delete(labels, "ci.confidential.ai/managed")
			case "different resource kind":
				labels["ci.confidential.ai/resource"] = "another-resource"
			}
			pvc, err := json.Marshal(map[string]any{"metadata": map[string]any{
				"name": rootPVC, "labels": labels,
				"annotations": map[string]string{"cdi.kubevirt.io/storage.import.endpoint": endpoint},
			}})
			if err != nil {
				t.Fatal(err)
			}
			pvcPath := filepath.Join(output, "pvc.json")
			if err := os.WriteFile(pvcPath, pvc, 0o644); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", stage.Run)
			cmd.Env = append(os.Environ(), "PATH="+fixture+string(os.PathListSeparator)+os.Getenv("PATH"),
				"NS=confai-images", "rootPvc="+rootPVC, "image="+image,
				"FIXTURE_MODE="+tc.name, "FIXTURE_PVC="+pvcPath,
				"FIXTURE_CREATED="+filepath.Join(output, "created.yaml"), "FIXTURE_COMMANDS="+filepath.Join(output, "commands"))
			log, err := cmd.CombinedOutput()
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected staging result: err=%v log=%s", err, log)
			}
			commands, readErr := os.ReadFile(filepath.Join(output, "commands"))
			if readErr != nil {
				t.Fatal(readErr)
			}
			wantCommands := "-n confai-images get pvc " + rootPVC + " --ignore-not-found -o json\n"
			if tc.create {
				wantCommands += "create -f -\n"
			}
			if tc.ok {
				wantCommands += "-n confai-images get pvc " + rootPVC + " -o jsonpath={.metadata.annotations.cdi\\.kubevirt\\.io/storage\\.pod\\.phase}\n"
			}
			if string(commands) != wantCommands {
				t.Fatalf("unsafe or unexpected staging operation: got %q want %q", commands, wantCommands)
			}
			if !tc.create {
				if _, err := os.Stat(filepath.Join(output, "created.yaml")); !os.IsNotExist(err) {
					t.Fatalf("existing or unreadable root claim reached creation: %v", err)
				}
				return
			}
			var created struct {
				Kind     string
				Metadata struct {
					Name, Namespace     string
					Labels, Annotations map[string]string
				}
			}
			readYAML(t, filepath.Join(output, "created.yaml"), &created)
			if created.Kind != "PersistentVolumeClaim" || created.Metadata.Name != rootPVC || created.Metadata.Namespace != "confai-images" ||
				created.Metadata.Labels["ci.confidential.ai/managed"] != "true" ||
				created.Metadata.Labels["ci.confidential.ai/resource"] != "tdx-node-root" ||
				created.Metadata.Annotations["cdi.kubevirt.io/storage.import.endpoint"] != "docker://"+image {
				t.Fatalf("created root disk does not identify the selected immutable image: %+v", created)
			}
		})
	}
}

func TestTDXSharedRootReaperRequiresUnusedInventory(t *testing.T) {
	var action lifecycleDocument
	readYAML(t, "../../.github/actions/tdx-metal-e2e/action.yml", &action)
	var script string
	for _, step := range action.Runs.Steps {
		if step.Name == "reap leaked CVMs from finished runs" {
			script = step.Run
		}
	}
	if script == "" {
		t.Fatal("missing reaper step")
	}
	script = strings.NewReplacer("${{ github.run_id }}", "123", "${{ github.repository }}", "fixture/c8s").Replace(script)
	fixture := t.TempDir()
	for name, body := range map[string]string{
		"kubectl": `#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  '-n confai-images get vm -l ci.confidential.ai/managed=true -o name') ;;
  '-n confai-images get vmi -o json')
    [[ $FIXTURE_MODE != 'VMI read failure' ]] || exit 1
    printf '%s' "$FIXTURE_VMIS" ;;
  '-n confai-images get vm -o json')
    [[ $FIXTURE_MODE != 'VM read failure' ]] || exit 1
    printf '%s' "$FIXTURE_VMS" ;;
  '-n confai-images get pvc -l ci.confidential.ai/managed=true,ci.confidential.ai/resource in (tdx-node-root, tdx-cds-root) -o name')
    printf 'persistentvolumeclaim/%s\npersistentvolumeclaim/%s\n' "$FIXTURE_ROOT" "$FIXTURE_CDS_ROOT" ;;
  "-n confai-images get persistentvolumeclaim/$FIXTURE_ROOT -o jsonpath={.metadata.creationTimestamp}" | \
  "-n confai-images get persistentvolumeclaim/$FIXTURE_CDS_ROOT -o jsonpath={.metadata.creationTimestamp}")
    printf old ;;
  "-n confai-images delete persistentvolumeclaim/$FIXTURE_ROOT --ignore-not-found --wait=false" | \
  "-n confai-images delete persistentvolumeclaim/$FIXTURE_CDS_ROOT --ignore-not-found --wait=false")
    printf '%s\n' "${4#persistentvolumeclaim/}" >> "$FIXTURE_DELETIONS" ;;
  *) printf '%s\n' "$*" >> "$FIXTURE_UNEXPECTED"; exit 1 ;;
esac
`,
		"date": `#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  '-u +%s') printf 1000000 ;;
  '-u -d old +%s') printf 0 ;;
  *) exit 1 ;;
esac
`,
	} {
		if err := os.WriteFile(filepath.Join(fixture, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	rootPVC := "c8s-root-" + strings.Repeat("a", 12)
	cdsPVC := "c8s-cds-root-" + strings.Repeat("b", 12)
	claim := func(name string) string { return `{"persistentVolumeClaim":{"claimName":"` + name + `"}}` }
	// The lane stages a node image and a CDS image, so each case says which of
	// the two shared roots a guest holds; every other root is unused.
	for _, name := range []string{"unused old roots", "stopped VM reference", "VMI reference", "DataVolume reference",
		"CDS root in use", "VMI read failure", "VM read failure", "malformed inventory"} {
		t.Run(name, func(t *testing.T) {
			output := t.TempDir()
			vms, vmis := `{"items":[]}`, `{"items":[]}`
			switch name {
			case "stopped VM reference":
				vms = `{"items":[{"spec":{"runStrategy":"Halted","template":{"spec":{"volumes":[` + claim(rootPVC) + `]}}}}]}`
			case "VMI reference":
				vmis = `{"items":[{"spec":{"volumes":[` + claim(rootPVC) + `]}}]}`
			case "DataVolume reference":
				vms = `{"items":[{"spec":{"template":{"spec":{"volumes":[{"dataVolume":{"name":"` + rootPVC + `"}}]}}}}]}`
			case "CDS root in use":
				vmis = `{"items":[{"spec":{"volumes":[` + claim(cdsPVC) + `]}}]}`
			case "malformed inventory":
				vmis = `{broken`
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", script)
			cmd.Env = append(os.Environ(), "PATH="+fixture+string(os.PathListSeparator)+os.Getenv("PATH"),
				"NS=confai-images", "FIXTURE_ROOT="+rootPVC, "FIXTURE_CDS_ROOT="+cdsPVC, "FIXTURE_MODE="+name,
				"FIXTURE_VMS="+vms, "FIXTURE_VMIS="+vmis,
				"FIXTURE_DELETIONS="+filepath.Join(output, "deletions"), "FIXTURE_UNEXPECTED="+filepath.Join(output, "unexpected"))
			log, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("reaper failed: %v\n%s", err, log)
			}
			for _, file := range []string{"deletions", "unexpected"} {
				contents, readErr := os.ReadFile(filepath.Join(output, file))
				if readErr != nil && !os.IsNotExist(readErr) {
					t.Fatal(readErr)
				}
				want := ""
				if file == "deletions" {
					switch name {
					case "unused old roots":
						want = rootPVC + "\n" + cdsPVC + "\n"
					case "stopped VM reference", "VMI reference", "DataVolume reference":
						want = cdsPVC + "\n"
					case "CDS root in use":
						want = rootPVC + "\n"
					}
				}
				if string(contents) != want {
					t.Fatalf("unsafe root reaping: %s got %q want %q; log=%s", file, contents, want, log)
				}
			}
		})
	}
}
