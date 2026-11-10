//go:build !c8s_node

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// mustUninstallNoMutation asserts the run left the cluster as it found it.
func mustUninstallNoMutation(t *testing.T, calls []string) {
	t.Helper()
	for _, prefix := range []string{"helm uninstall", "kubectl apply", "kubectl delete"} {
		mustNotContainPrefix(t, calls, prefix)
	}
}

// volumeHoldingPodStub answers the volume-pod query with one running pod
// holding a c8s encrypted volume.
const volumeHoldingPodStub = `*c8s-volumes*) /usr/bin/printf 'default\tinference-0\tRunning\tweights=/tenant-a/volumes/weights\n' ;;
`

// Every refusal that reads the cluster leaves it untouched: deleting the NRI
// installer already stops the nodes from re-adding the plugin, and the
// release's values and allowlist seed are only readable while it exists.
func TestUninstallRefusalsRunNoMutatingCommand(t *testing.T) {
	for _, tc := range []struct {
		name         string
		values       string
		kubectlExtra string
		args         []string
		wantErr      string
	}{
		{
			name:         "a pod still holds a c8s encrypted volume",
			values:       volumedReleaseValuesFile(t),
			kubectlExtra: volumeHoldingPodStub,
			wantErr:      "default/inference-0",
		},
		{
			name:         "the sweep has no node to run on",
			values:       hostReleaseValuesFile(t),
			kubectlExtra: `"get nodes -l ` + linuxNodeSelector() + ` -o name") ;;` + "\n",
			wantErr:      "no node matches",
		},
		{
			name:         "a pod holds a volume on the host-sweep-only path",
			values:       volumedReleaseValuesFile(t),
			kubectlExtra: volumeHoldingPodStub,
			args:         []string{"--host-sweep-only"},
			wantErr:      "default/inference-0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newUninstallStubs(t, tc.values, tc.kubectlExtra, false)
			err := runC8s(t, append([]string{"uninstall"}, tc.args...)...)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("uninstall = %v, want an error containing %q", err, tc.wantErr)
			}
			mustUninstallNoMutation(t, s.f.calls(t))
		})
	}
}

// A release that is not there is refused before the embedded chart is read for
// the sweep defaults.
func TestUninstallReleaseNotFoundRefusesBeforeTheChartDefaults(t *testing.T) {
	s := newUninstallStubs(t, "", "", false)
	err := runC8s(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "nothing to uninstall") {
		t.Fatalf("uninstall = %v, want the not-found refusal", err)
	}
	calls := s.f.calls(t)
	mustNotContainPrefix(t, calls, "helm show")
	mustUninstallNoMutation(t, calls)
}

// --host-sweep=false sweeps nothing, so it reads neither the nodes a sweep
// would run on nor the allowlist seed whose argv it would replay.
func TestUninstallHostSweepFalseReadsNoSweepSpec(t *testing.T) {
	imageRef := "ghcr.io/confidential-dot-ai/nri-image-policy@" + testDigest
	cm := seedCMFile(t, imageRef, [][]string{
		{"/bin/sh", "-c", hostSweepScript},
		{"/bin/sleep", "2147483646"},
	})
	nodeless := `"get nodes -l ` + linuxNodeSelector() + ` -o name") ;;` + "\n"
	s := newUninstallStubs(t, hostReleaseValuesNRIFile(t, imageRef), seedCMStub(cm)+nodeless, false)

	if err := runC8s(t, "uninstall", "--host-sweep=false"); err != nil {
		t.Fatalf("uninstall --host-sweep=false: %v", err)
	}
	calls := s.f.calls(t)
	mustContainLine(t, calls, "helm uninstall c8s --namespace c8s-system --wait --timeout=5m")
	mustNotContainPrefix(t, calls, "kubectl get configmap")
	mustNotContainPrefix(t, calls, "kubectl get nodes")
}

// sweptReleaseValuesFile writes the computed values of a release whose NRI
// plugin went to a host path the chart does not default to.
func sweptReleaseValuesFile(t *testing.T, imageRef, pluginDir string) string {
	t.Helper()
	repo, digest, _ := strings.Cut(imageRef, "@")
	data, err := json.Marshal(map[string]any{"nriImagePolicy": map[string]any{
		"image":     map[string]any{"repository": repo, "digest": digest},
		"hostPaths": map[string]any{"pluginDir": pluginDir},
	}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "release-values.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// --host-sweep-only on a release that is still there sweeps what that release
// installed — its host paths, and the sweep argv its allowlist seed pins —
// and leaves the release itself alone.
func TestUninstallHostSweepOnlyUsesTheReleaseValues(t *testing.T) {
	imageRef := "ghcr.io/confidential-dot-ai/nri-image-policy@" + testDigest
	pinnedScript := "# the release's pinned sweep\necho 'c8s host sweep'\n"
	cm := seedCMFile(t, imageRef, [][]string{
		{"/bin/sh", "-c", pinnedScript},
		{"/bin/sleep", "2147483646"},
	})
	s := newUninstallStubs(t, sweptReleaseValuesFile(t, imageRef, "/custom/nri/plugins"), seedCMStub(cm), false)

	if err := runC8s(t, "uninstall", "--host-sweep-only"); err != nil {
		t.Fatalf("uninstall --host-sweep-only: %v", err)
	}
	calls := s.f.calls(t)
	mustNotContainPrefix(t, calls, "helm uninstall")
	mustNotContainPrefix(t, calls, "kubectl delete daemonset -n")
	init := appliedDaemonSet(t, s.applied).Spec.Template.Spec.InitContainers[0]
	if want := []string{"/bin/sh", "-c", pinnedScript}; !reflect.DeepEqual(init.Command, want) {
		t.Errorf("sweep argv = %v, want the argv the release's seed pins", init.Command)
	}
	env := map[string]string{}
	for _, e := range init.Env {
		env[e.Name] = e.Value
	}
	if env["NRI_PLUGIN_DIR"] != "/custom/nri/plugins" {
		t.Errorf("sweep NRI_PLUGIN_DIR = %q, want the release's host path", env["NRI_PLUGIN_DIR"])
	}
}

// Both CLIs are named before anything runs: a missing one otherwise surfaces
// as an exec failure from whichever step reaches for it first.
func TestUninstallRequiresTheCLIsItDrives(t *testing.T) {
	for _, tc := range []struct{ name, present, wantErr string }{
		{"helm missing", "kubectl", "helm CLI not found on PATH"},
		{"kubectl missing", "helm", "kubectl CLI not found on PATH"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeBin(t)
			f.tool(t, tc.present, "")
			t.Setenv("PATH", f.dir)
			err := runC8s(t, "uninstall")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("uninstall = %v, want an error containing %q", err, tc.wantErr)
			}
			if calls := f.calls(t); len(calls) > 0 {
				t.Errorf("the refusal ran %v", calls)
			}
		})
	}
}
