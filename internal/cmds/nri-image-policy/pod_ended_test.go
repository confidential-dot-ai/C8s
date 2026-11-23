package nriimagepolicy

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

// An ended pod identity outlives the plugin that ended it: the next plugin of
// the boot reports it from the marker beside the boot gate's, and a node
// plugin, which has no pod, records nothing.
func TestEndedPodIdentityIsRetainedAcrossAPluginRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := gatedConfig(filepath.Join(dir, "registered"))
	cfg.Pod = &podConfig{UID: "assigned"}
	p := newTestPlugin(cfg)
	p.restorePodEnded()
	if p.podEnded.Load() {
		t.Fatal("a fresh boot reports an ended identity")
	}
	p.endPodIdentity(errors.New("plugin restarted"))
	if !p.podEnded.Load() {
		t.Fatal("ending the identity did not report it")
	}
	restarted := newTestPlugin(cfg)
	restarted.restorePodEnded()
	if !restarted.podEnded.Load() {
		t.Fatal("the next plugin of the boot forgot the ended identity")
	}
	node := newTestPlugin(gatedConfig(filepath.Join(t.TempDir(), "registered")))
	node.endPodIdentity(errors.New("no pod"))
	if marker := node.podEndedMarker(); marker != "" {
		t.Fatalf("a node plugin records an ended pod identity at %s", marker)
	}
}

// A restart recomputes each pod's component sets from the containers the
// inventory records for the sandbox again, so a deadline passing afterwards
// still ends the whole pod. The pod stays ended: the set that admitted its
// containers is out of force, so admission refuses them again.
func TestARestartRecomputesComponentSetMembership(t *testing.T) {
	taTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	deadline := taTime.Add(time.Hour)
	p, killed := componentSetPlugin(t, func() time.Time { return taTime }, componentBase(), retiringDocument(t, deadline))
	pod := meshPod("tenant", "inference-0", testNetNS)
	pod.Uid = "inference-0-uid"
	mesh := componentCtr(pod, "c8s-mesh", pushDigestA, meshArgv)
	app := runningCtr(pod, "app", pushDigestB)

	if _, err := p.Synchronize(t.Context(), []*api.PodSandbox{pod}, []*api.Container{mesh, app}); err != nil {
		t.Fatal(err)
	}
	p.recheckRunning(t.Context())
	if len(*killed) != 0 {
		t.Fatalf("killed %v while the recovered pod's set was in force", *killed)
	}

	taTime = deadline
	if !p.policy.rebuildEndedSets() {
		t.Fatal("the retiring set stayed in force past its deadline")
	}
	p.recheckRunning(t.Context())
	if !slices.Contains(*killed, mesh.Id) || !slices.Contains(*killed, app.Id) {
		t.Fatalf("killed %v, want the whole recovered pod on the ended set", *killed)
	}
	if err := p.StartContainer(t.Context(), pod, mesh); err == nil {
		t.Fatal("a container of an ended pod started again")
	}
}

// An enforcer that restarts after the set ended binds the recovered containers
// no role, and still ends the pod: the served document declares its component
// container in the set that ended. A kubelet that starts the tenant container
// again, the Pod delete dropped, is refused.
func TestARestartAfterItsSetEndedEndsThePod(t *testing.T) {
	deadline := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	p, killed := componentSetPlugin(t, func() time.Time { return deadline }, componentBase(), retiringDocument(t, deadline))
	pod := meshPod("tenant", "inference-0", testNetNS)
	pod.Uid = "inference-0-uid"
	mesh := componentCtr(pod, "c8s-mesh", pushDigestA, meshArgv)
	app := runningCtr(pod, "app", pushDigestB)

	if _, err := p.Synchronize(t.Context(), []*api.PodSandbox{pod}, []*api.Container{mesh, app}); err != nil {
		t.Fatal(err)
	}
	p.recheckRunning(t.Context())
	if !slices.Contains(*killed, app.Id) {
		t.Fatalf("killed %v, want the tenant container of the pod off its sets", *killed)
	}

	restarted := runningCtr(pod, "app", pushDigestB)
	restarted.Id = app.GetId() + "-restarted"
	if err := p.StartContainer(t.Context(), pod, restarted); err == nil {
		t.Fatal("the tenant container of a pod off its sets started again after a restart")
	}
}

// retiringDocument serves one component set retiring at deadline, declaring a
// mesh container, beside the tenant workload entry.
func retiringDocument(t *testing.T, deadline time.Time) *allowlist.Allowlist {
	t.Helper()
	retiring := &allowlist.Retirement{Deadline: allowlist.Deadline{Time: deadline}}
	return componentSetsDocument(t, map[string]string{pushDigestB: "app"}, map[string]allowlist.ComponentSet{
		"0.43.0": componentSet(retiring, componentContainer(t, pushDigestA, allowlist.RoleMesh, meshArgv)),
	})
}
