//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func hostReleaseValuesFile(t *testing.T) string {
	t.Helper()
	tree := map[string]any{"nriImagePolicy": map[string]any{
		"enabled": true, "distro": "k8s",
		"containerdPrep": map[string]any{"image": map[string]any{"repository": "busybox", "digest": testDigest}},
	}}
	data, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "release-values.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type uninstallStubs struct {
	f       *fakeBin
	applied string
}

// newUninstallStubs wires stub helm/kubectl for `c8s uninstall` runs.
// valuesFile == "" makes `helm get values` answer release-not-found. Every
// kubectl query not overridden by extra answers empty (no pods, no labelled
// nodes), which is the healthy post-drain cluster.
func newUninstallStubs(t *testing.T, valuesFile, kubectlExtra string, helmUninstallFails bool) *uninstallStubs {
	t.Helper()
	f := newFakeBin(t)
	s := &uninstallStubs{f: f, applied: filepath.Join(f.dir, "applied.json")}
	getBody := `echo 'Error: release: not found' >&2; exit 1`
	if valuesFile != "" {
		getBody = `/bin/cat '` + valuesFile + `'`
	}
	fail := ""
	if helmUninstallFails {
		fail = "exit 1"
	}
	f.tool(t, "helm", `case "$1" in
get) `+getBody+` ;;
show) /bin/cat "$3/values.yaml" ;;
uninstall) `+fail+` ;;
esac`)
	f.tool(t, "kubectl", `case "$*" in
`+kubectlExtra+`"apply -f -") /bin/cat >> '`+s.applied+`' ;;
esac`)
	return s
}

// appliedDocs splits the captured `kubectl apply -f -` stream into its JSON
// documents.
func appliedDocs(t *testing.T, path string) []json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read applied manifests: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var docs []json.RawMessage
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decode applied manifests: %v\n%s", err, data)
		}
		docs = append(docs, raw)
	}
	return docs
}

func appliedDaemonSet(t *testing.T, path string) *appsv1.DaemonSet {
	t.Helper()
	for _, raw := range appliedDocs(t, path) {
		var meta struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			t.Fatalf("peek kind: %v", err)
		}
		if meta.Kind == "DaemonSet" {
			var ds appsv1.DaemonSet
			if err := json.Unmarshal(raw, &ds); err != nil {
				t.Fatalf("decode DaemonSet: %v", err)
			}
			return &ds
		}
	}
	t.Fatal("no DaemonSet was applied")
	return nil
}

func TestUninstallReleaseNotFound(t *testing.T) {
	s := newUninstallStubs(t, "", "", false)
	err := runC8s(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "--host-sweep-only") {
		t.Fatalf("want a not-found error pointing at --host-sweep-only, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm uninstall")
}

func TestUninstallHelmGetValuesFailure(t *testing.T) {
	f := newFakeBin(t)
	f.tool(t, "helm", `case "$1" in
get) echo boom >&2; exit 1 ;;
esac`)
	f.tool(t, "kubectl", "")
	err := runC8s(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("want the helm stderr surfaced, got %v", err)
	}
}

func TestUninstallRejectsMalformedReleaseValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "values.json")
	if err := os.WriteFile(path, []byte(`{"nriImagePolicy":{"enabled":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newUninstallStubs(t, path, "", false)
	err := runC8s(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "read host config") {
		t.Fatalf("want a host-config error, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm uninstall")
}

func TestUninstallSweepsNodeState(t *testing.T) {
	values := hostReleaseValuesFile(t)
	s := newUninstallStubs(t, values, "", false)
	if err := runC8s(t, "uninstall"); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	calls := s.f.calls(t)
	hi := lineIndex(calls, "helm uninstall c8s --namespace c8s-system --wait --timeout=5m")
	ai := lineIndex(calls, "kubectl apply -f -")
	ri := lineIndex(calls, "kubectl rollout status daemonset/c8s-host-sweep -n c8s-system --timeout=5m")
	di := lineIndex(calls, "kubectl delete daemonset c8s-host-sweep -n c8s-system --ignore-not-found")
	if hi < 0 || ai < hi || ri < ai || di < ri {
		t.Fatalf("sweep order wrong (helm=%d apply=%d rollout=%d delete=%d):\n%s", hi, ai, ri, di, strings.Join(calls, "\n"))
	}
	ds := appliedDaemonSet(t, s.applied)
	env := map[string]string{}
	for _, e := range ds.Spec.Template.Spec.InitContainers[0].Env {
		env[e.Name] = e.Value
	}
	if env["HOST_CONTAINERD_DIR"] != "/etc/containerd" {
		t.Fatalf("sweep containerd directory = %q, want /etc/containerd", env["HOST_CONTAINERD_DIR"])
	}
	// ...and targets every linux node, not host-selected ones.
	wantSelector := map[string]string{"kubernetes.io/os": "linux"}
	if !reflect.DeepEqual(ds.Spec.Template.Spec.NodeSelector, wantSelector) {
		t.Errorf("nodeSelector = %v, want %v", ds.Spec.Template.Spec.NodeSelector, wantSelector)
	}
}

// --host-sweep=false opts every release shape out of the host sweep.
func TestUninstallHostSweepFalseSkipsSweep(t *testing.T) {
	values := hostReleaseValuesFile(t)
	s := newUninstallStubs(t, values, "", false)
	if err := runC8s(t, "uninstall", "--host-sweep=false"); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	calls := s.f.calls(t)
	mustContainLine(t, calls, "helm uninstall c8s --namespace c8s-system --wait --timeout=5m")
	mustNotContainPrefix(t, calls, "kubectl apply")
	mustNotContainPrefix(t, calls, "kubectl rollout")
}

func TestUninstallSweepRolloutFailureKeepsDaemonSet(t *testing.T) {
	values := hostReleaseValuesFile(t)
	s := newUninstallStubs(t, values,
		`"rollout status daemonset/c8s-host-sweep -n c8s-system --timeout=5m") exit 1 ;;
`, false)
	err := runC8s(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "did not complete") {
		t.Fatalf("want the sweep-incomplete error, got %v", err)
	}
	// The DaemonSet holds the only per-node failure logs; it must survive.
	mustNotContainPrefix(t, s.f.calls(t), "kubectl delete daemonset")
}

func TestUninstallSweepNamespaceApplyFailure(t *testing.T) {
	values := hostReleaseValuesFile(t)
	s := newUninstallStubs(t, values, `"apply -f -") exit 1 ;;
`, false)
	err := runC8s(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "kubectl apply namespace") {
		t.Fatalf("want the namespace apply failure, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "kubectl rollout")
}

func TestUninstallSweepWaitFailure(t *testing.T) {
	values := hostReleaseValuesFile(t)
	s := newUninstallStubs(t, values, `"get pods -n c8s-system -l "*) exit 1 ;;
`, false)
	err := runC8s(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "waiting for armtls-mesh pods") {
		t.Fatalf("want the drain-wait failure, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "kubectl apply")
}

func TestUninstallHelmUninstallFailure(t *testing.T) {
	values := hostReleaseValuesFile(t)
	s := newUninstallStubs(t, values, "", true)
	err := runC8s(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "helm uninstall failed") {
		t.Fatalf("want the helm failure surfaced, got %v", err)
	}
	if !strings.Contains(err.Error(), "--no-hooks") {
		t.Fatalf("want the recovery hint (--no-hooks + --host-sweep-only), got %v", err)
	}
	calls := s.f.calls(t)
	mustContainLine(t, calls, "helm uninstall c8s --namespace c8s-system --wait --timeout=5m")
	// A failed helm uninstall aborts before the sweep.
	mustNotContainPrefix(t, calls, "kubectl apply")
}

func TestUninstallDeleteCRDsAndNamespace(t *testing.T) {
	values := hostReleaseValuesFile(t)

	t.Run("deletes on request", func(t *testing.T) {
		s := newUninstallStubs(t, values, "", false)
		if err := runC8s(t, "uninstall", "--delete-crds", "--delete-namespace"); err != nil {
			t.Fatalf("uninstall: %v", err)
		}
		calls := s.f.calls(t)
		ci := lineIndex(calls, "kubectl delete crd "+confidentialWorkloadCRD+" --ignore-not-found")
		ni := lineIndex(calls, "kubectl delete namespace c8s-system --ignore-not-found")
		if ci < 0 || ni < 0 {
			t.Fatalf("want crd and namespace deletes, got:\n%s", strings.Join(calls, "\n"))
		}
		// The sweep finishes before the CRD/namespace deletes.
		si := lineIndex(calls, "kubectl delete daemonset c8s-host-sweep -n c8s-system --ignore-not-found")
		if si < 0 || si > ci || si > ni {
			t.Fatalf("sweep cleanup must precede the deletes (sweep=%d crd=%d ns=%d):\n%s", si, ci, ni, strings.Join(calls, "\n"))
		}
	})

	t.Run("delete failure surfaces", func(t *testing.T) {
		newUninstallStubs(t, values, `"delete crd "*) exit 1 ;;
`, false)
		err := runC8s(t, "uninstall", "--delete-crds")
		if err == nil || !strings.Contains(err.Error(), "kubectl delete crd") {
			t.Fatalf("want the delete failure surfaced, got %v", err)
		}
	})
}

func TestUninstallHostSweepOnlyUsesChartDefaults(t *testing.T) {
	// Release already gone: config comes from the embedded chart defaults and
	// the detected distro, and the helm uninstall step is skipped entirely.
	s := newUninstallStubs(t, "", "", false)
	if err := runC8s(t, "uninstall", "--host-sweep-only"); err != nil {
		t.Fatalf("uninstall --host-sweep-only: %v", err)
	}
	calls := s.f.calls(t)
	mustNotContainPrefix(t, calls, "helm uninstall")
	// No release, no seed to replay: the embedded spec runs.
	mustNotContainPrefix(t, calls, "kubectl get configmap")
	mustContainLine(t, calls, "kubectl rollout status daemonset/c8s-host-sweep -n c8s-system --timeout=5m")
	ds := appliedDaemonSet(t, s.applied)
	// With the release gone the baked plugin still enforces the release-pinned
	// nri-image-policy digest, so the sweep runs the nri image at this CLI's
	// version tag ("main" for this dev build) rather than the busybox default.
	if want := "ghcr.io/confidential-dot-ai/nri-image-policy:main"; ds.Spec.Template.Spec.InitContainers[0].Image != want {
		t.Errorf("sweep image = %q, want %q", ds.Spec.Template.Spec.InitContainers[0].Image, want)
	}
	env := map[string]string{}
	for _, e := range ds.Spec.Template.Spec.InitContainers[0].Env {
		env[e.Name] = e.Value
	}
	if env["HOST_CONTAINERD_DIR"] != "/etc/containerd" {
		t.Fatalf("sweep containerd directory = %q, want /etc/containerd", env["HOST_CONTAINERD_DIR"])
	}
}

func TestUninstallHostSweepOnlyRejectsSweepDisabled(t *testing.T) {
	newUninstallStubs(t, "", "", false)
	if err := runC8s(t, "uninstall", "--host-sweep-only", "--host-sweep=false"); err == nil {
		t.Fatal("want the contradictory-flags error")
	}
}

func TestReleaseValuesExec(t *testing.T) {
	t.Run("found release decodes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "v.json")
		if err := os.WriteFile(path, []byte(`{"nriImagePolicy":{"enabled":true}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		f := newFakeBin(t)
		f.tool(t, "helm", "/bin/cat '"+path+"'")
		tree, found, err := releaseValues(context.Background(), "c8s", "ns")
		if err != nil || !found {
			t.Fatalf("releaseValues = (found=%t, %v), want found", found, err)
		}
		host, ok := tree["nriImagePolicy"].(map[string]any)
		if !ok || host["enabled"] != true {
			t.Fatalf("tree = %#v, want nriImagePolicy.enabled true", tree)
		}
		mustContainLine(t, f.calls(t), "helm get values c8s --namespace ns --all --output json")
	})

	t.Run("missing release is found=false", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", `echo 'Error: release: not found' >&2; exit 1`)
		tree, found, err := releaseValues(context.Background(), "c8s", "ns")
		if err != nil || found || tree != nil {
			t.Fatalf("releaseValues = (%v, %t, %v), want (nil, false, nil)", tree, found, err)
		}
	})

	t.Run("other helm failure surfaces stderr", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", `echo 'permission denied' >&2; exit 1`)
		_, _, err := releaseValues(context.Background(), "c8s", "ns")
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("want the helm stderr surfaced, got %v", err)
		}
	})

	t.Run("unparseable values surface", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", "echo not-json")
		if _, _, err := releaseValues(context.Background(), "c8s", "ns"); err == nil {
			t.Fatal("want error for unparseable values")
		}
	})
}

func TestWaitPodsGone(t *testing.T) {
	t.Run("returns once no pod matches", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := waitPodsGone(ctx, "ns", "a=b"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContainLine(t, f.calls(t), "kubectl get pods -n ns -l a=b -o name")
	})

	t.Run("polls at the 5s interval until pods are gone", func(t *testing.T) {
		f := newFakeBin(t)
		state := filepath.Join(f.dir, "first-poll-done")
		f.tool(t, "kubectl", `if [ ! -f '`+state+`' ]; then : > '`+state+`'; echo pod/armtls-mesh-x; fi`)
		start := time.Now()
		if err := waitPodsGone(context.Background(), "ns", "a=b"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n := len(f.calls(t)); n < 2 {
			t.Errorf("polled %d times, want at least 2", n)
		}
		if elapsed := time.Since(start); elapsed < 4*time.Second {
			t.Errorf("second poll after %v, want the 5s interval respected", elapsed)
		}
	})

	t.Run("kubectl failure surfaces", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "exit 1")
		if err := waitPodsGone(context.Background(), "ns", "a=b"); err == nil {
			t.Fatal("want error when kubectl fails")
		}
	})
}

// volumedReleaseValuesFile writes the computed-values JSON `helm get values
// --all` returns for a release with the volume node agent deployed.
func volumedReleaseValuesFile(t *testing.T) string {
	t.Helper()
	path := hostReleaseValuesFile(t)
	tree := map[string]any{}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &tree); err != nil {
		t.Fatal(err)
	}
	tree["volumed"] = map[string]any{"enabled": true}
	if data, err = json.Marshal(tree); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Deleting volumed under a pod that holds a volume strands the dm stack on the
// node — nothing else reaps it, and it keeps the disk open against the next
// install. Refuse, name the pods, and say what to do.
func TestUninstallRefusesWhileVolumePodsRun(t *testing.T) {
	values := volumedReleaseValuesFile(t)
	holding := `*c8s-volumes*) /usr/bin/printf 'default\tinference-0\tRunning\tweights=/tenant-a/volumes/weights\n' ;;
`

	t.Run("refuses and names the pods", func(t *testing.T) {
		s := newUninstallStubs(t, values, holding, false)
		err := runC8s(t, "uninstall")
		if err == nil || !strings.Contains(err.Error(), "default/inference-0") {
			t.Fatalf("want the volume-holding pod named, got %v", err)
		}
		if !strings.Contains(err.Error(), "scale those workloads to zero") {
			t.Errorf("refusal %q does not say what to do instead", err)
		}
		mustNotContainPrefix(t, s.f.calls(t), "helm uninstall")
	})

	t.Run("--force proceeds, having still asked which pods hold volumes", func(t *testing.T) {
		s := newUninstallStubs(t, values, holding, false)
		if err := runC8s(t, "uninstall", "--force"); err != nil {
			t.Fatalf("uninstall --force: %v", err)
		}
		mustContainLine(t, s.f.calls(t), "helm uninstall c8s --namespace c8s-system --wait --timeout=5m")
		// The pre-delete hook cannot close what these pods hold, so --force has
		// to name them here; a failed hook's logs go with the release.
		var listed bool
		for _, c := range s.f.calls(t) {
			if strings.HasPrefix(c, "kubectl get pods --all-namespaces") {
				listed = true
			}
		}
		if !listed {
			t.Errorf("--force skipped the volume-pod listing, so the mappings it strands are never named; calls: %v", s.f.calls(t))
		}
	})

	t.Run("pod listing failure surfaces", func(t *testing.T) {
		s := newUninstallStubs(t, values, "*c8s-volumes*) exit 1 ;;\n", false)
		if err := runC8s(t, "uninstall"); err == nil {
			t.Fatal("want error when the volume pod listing fails")
		}
		mustNotContainPrefix(t, s.f.calls(t), "helm uninstall")
	})
}

// A release that never deployed volumed has no mappings to strand, so the
// guard must not query for them at all.
func TestUninstallWithoutVolumedSkipsTheVolumeGuard(t *testing.T) {
	values := hostReleaseValuesFile(t)
	s := newUninstallStubs(t, values, "", false)
	if err := runC8s(t, "uninstall"); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	for _, l := range s.f.calls(t) {
		if strings.Contains(l, "c8s-volumes") {
			t.Errorf("volume guard queried for a release without volumed: %q", l)
		}
	}
}

// hostReleaseValuesNRIFile writes the computed-values JSON for a release whose
// nri-image-policy image resolves to imageRef (repository@digest).
func hostReleaseValuesNRIFile(t *testing.T, imageRef string) string {
	t.Helper()
	repo, digest, _ := strings.Cut(imageRef, "@")
	tree := map[string]any{"nriImagePolicy": map[string]any{
		"enabled": true, "distro": "k8s",
		"image": map[string]any{"repository": repo, "digest": digest},
	}}
	data, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "release-values.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// seedCMFile writes the release's allowlist seed ConfigMap as `kubectl get
// configmap -o json` answers it: one workload entry named for imageRef's
// digest, carrying shapes as command [/bin/sh -c] + exact args (or, for the
// pause, command [/bin/sleep] + exact args).
func seedCMFile(t *testing.T, imageRef string, shapes [][]string) string {
	t.Helper()
	_, digest, _ := strings.Cut(imageRef, "@")
	d, err := types.ParseDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	name := allowlist.DigestEntryName(d, imageRef)
	containers := []map[string]any{}
	for _, argv := range shapes {
		containers = append(containers, map[string]any{
			"digest":  d.String(),
			"image":   imageRef,
			"command": map[string]any{"policy": "exact", "argv": argv[:len(argv)-1]},
			"args":    map[string]any{"policy": "exact", "argv": argv[len(argv)-1:]},
		})
	}
	seed, err := json.Marshal(map[string]any{
		"schema": "c8s.allowlist/v1",
		"workloads": map[string]any{
			name: map[string]any{"label": imageRef, "initContainers": []any{}, "containers": containers},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cm, err := json.Marshal(map[string]any{"data": map[string]string{"allowlist-seed.json": string(seed)}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "seed-cm.json")
	if err := os.WriteFile(path, cm, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func seedCMStub(cmFile string) string {
	return `"get configmap c8s-cds-allowlist-seed -n c8s-system -o json") /bin/cat '` + cmFile + `' ;;
`
}

// The sweep replays the argv the release's allowlist seed pins, verbatim: an
// older install's pinned bytes win over this CLI's embedded spec, so the
// sweep stays admissible across CLI/chart version skew.
func TestUninstallSweepReplaysPinnedArgv(t *testing.T) {
	imageRef := "ghcr.io/confidential-dot-ai/nri-image-policy@" + testDigest
	values := hostReleaseValuesNRIFile(t, imageRef)
	oldScript := "# older sweep bytes\necho '==> c8s host sweep starting (old)'\n"
	cm := seedCMFile(t, imageRef, [][]string{
		{"/bin/sh", "-c", "install script"},
		{"/bin/sh", "-c", "sleep infinity"},
		{"/bin/sh", "-c", oldScript},
		{"/bin/sleep", "2147483646"},
	})
	s := newUninstallStubs(t, values, seedCMStub(cm), false)
	if err := runC8s(t, "uninstall"); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	calls := s.f.calls(t)
	// The seed is read before helm uninstall deletes it.
	gi := lineIndex(calls, "kubectl get configmap c8s-cds-allowlist-seed -n c8s-system -o json")
	hi := lineIndex(calls, "helm uninstall c8s --namespace c8s-system --wait --timeout=5m")
	if gi < 0 || hi < 0 || gi > hi {
		t.Fatalf("seed read must precede helm uninstall (get=%d helm=%d):\n%s", gi, hi, strings.Join(calls, "\n"))
	}
	ds := appliedDaemonSet(t, s.applied)
	init := ds.Spec.Template.Spec.InitContainers[0]
	if want := []string{"/bin/sh", "-c", oldScript}; !reflect.DeepEqual(init.Command, want) || len(init.Args) != 0 {
		t.Errorf("sweep argv = %v + %v, want the pinned %v", init.Command, init.Args, want)
	}
	pause := ds.Spec.Template.Spec.Containers[0]
	if want := []string{"/bin/sleep", "2147483646"}; !reflect.DeepEqual(pause.Command, want) || len(pause.Args) != 0 {
		t.Errorf("pause argv = %v + %v, want the pinned %v", pause.Command, pause.Args, want)
	}
}

// The pinned shapes are identified by content, not position: a seed whose
// entry sorts the sweep shapes first replays the same argvs.
func TestUninstallSweepReplayIsPositionIndependent(t *testing.T) {
	imageRef := "ghcr.io/confidential-dot-ai/nri-image-policy@" + testDigest
	values := hostReleaseValuesNRIFile(t, imageRef)
	oldScript := "# older sweep bytes\necho 'c8s host sweep'\n"
	cm := seedCMFile(t, imageRef, [][]string{
		{"/bin/sh", "-c", oldScript},
		{"/bin/sleep", "2147483646"},
		{"/bin/sh", "-c", "install script"},
	})
	s := newUninstallStubs(t, values, seedCMStub(cm), false)
	if err := runC8s(t, "uninstall"); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	ds := appliedDaemonSet(t, s.applied)
	if want := []string{"/bin/sh", "-c", oldScript}; !reflect.DeepEqual(ds.Spec.Template.Spec.InitContainers[0].Command, want) {
		t.Errorf("sweep argv = %v, want the pinned %v", ds.Spec.Template.Spec.InitContainers[0].Command, want)
	}
}

// A seed without usable sweep pins (missing ConfigMap, a pre-fix entry, or a
// tag-only sweep image whose digest cannot be computed) falls back to this
// CLI's embedded spec — the pre-replay behavior.
func TestUninstallSweepFallsBackToEmbeddedArgv(t *testing.T) {
	imageRef := "ghcr.io/confidential-dot-ai/nri-image-policy@" + testDigest

	t.Run("seed ConfigMap gone", func(t *testing.T) {
		values := hostReleaseValuesNRIFile(t, imageRef)
		s := newUninstallStubs(t, values, `"get configmap c8s-cds-allowlist-seed -n c8s-system -o json") exit 1 ;;
`, false)
		if err := runC8s(t, "uninstall"); err != nil {
			t.Fatalf("uninstall: %v", err)
		}
		assertEmbeddedSweepArgv(t, appliedDaemonSet(t, s.applied))
	})

	t.Run("pre-fix entry pins no sweep shapes", func(t *testing.T) {
		values := hostReleaseValuesNRIFile(t, imageRef)
		cm := seedCMFile(t, imageRef, [][]string{
			{"/bin/sh", "-c", "install script"},
			{"/bin/sh", "-c", "uninstall script"},
			{"/bin/sh", "-c", "sleep infinity"},
		})
		s := newUninstallStubs(t, values, seedCMStub(cm), false)
		if err := runC8s(t, "uninstall"); err != nil {
			t.Fatalf("uninstall: %v", err)
		}
		assertEmbeddedSweepArgv(t, appliedDaemonSet(t, s.applied))
	})

	t.Run("tag-only sweep image", func(t *testing.T) {
		values := hostReleaseValuesNRIFile(t, "ghcr.io/confidential-dot-ai/nri-image-policy@"+testDigest)
		tree := map[string]any{}
		data, err := os.ReadFile(values)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &tree); err != nil {
			t.Fatal(err)
		}
		tree["nriImagePolicy"].(map[string]any)["image"] = map[string]any{
			"repository": "ghcr.io/confidential-dot-ai/nri-image-policy", "tag": "it",
		}
		if data, err = json.Marshal(tree); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(values, data, 0o600); err != nil {
			t.Fatal(err)
		}
		s := newUninstallStubs(t, values, "", false)
		if err := runC8s(t, "uninstall"); err != nil {
			t.Fatalf("uninstall: %v", err)
		}
		assertEmbeddedSweepArgv(t, appliedDaemonSet(t, s.applied))
		mustNotContainPrefix(t, s.f.calls(t), "kubectl get configmap")
	})
}

func assertEmbeddedSweepArgv(t *testing.T, ds *appsv1.DaemonSet) {
	t.Helper()
	init := ds.Spec.Template.Spec.InitContainers[0]
	if want := []string{"/bin/sh", "-c", hostSweepScript}; !reflect.DeepEqual(init.Command, want) || len(init.Args) != 0 {
		t.Errorf("sweep argv = %v + %v, want the embedded spec", init.Command, init.Args)
	}
	pause := ds.Spec.Template.Spec.Containers[0]
	if want := []string{"/bin/sleep", "2147483647"}; !reflect.DeepEqual(pause.Command, want) || len(pause.Args) != 0 {
		t.Errorf("pause argv = %v + %v, want the embedded spec", pause.Command, pause.Args)
	}
}
